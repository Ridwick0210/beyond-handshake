"""Single-owner blocking-socket HTTP/2 server loop backed by hyper-h2."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (ConnectionTerminated, DataReceived, RequestReceived,
                       StreamEnded, StreamReset, WindowUpdated)
from h2.exceptions import H2Error

from beyond_handshake.server.h2_observer import H2FrameObserver

LOGGER = logging.getLogger("beyond_handshake.server.h2")
def serve_h2(handler: Any) -> None:
    """Handle one TLS connection. This thread is the sole owner of H2Connection."""
    server = handler.app_server
    conn_id = handler.connection_id
    stream_request_ids: dict[int, str] = {}
    stream_targets: dict[int, tuple[str, str]] = {}
    stream_body: dict[int, bytearray] = defaultdict(bytearray)
    discarded_streams: set[int] = set()
    pending: dict[int, tuple[int, bytes, str]] = {}
    response_meta: dict[int, dict] = {}
    completed_responses: list[tuple[int, dict]] = []
    terminated = False

    def emit(event_type: str, payload: dict, *, stream_id: int | None = None,
             session_id: str | None = None, request_id: str | None = None) -> None:
        server.events.emit(event_type, payload, connection_id=conn_id, stream_id=stream_id,
                           session_id=session_id, request_id=request_id)

    def valid_authority(headers: list[tuple[bytes, bytes]]) -> bool:
        raw = next((v.decode("ascii", "replace") for k, v in headers if k == b":authority"), "")
        from urllib.parse import urlsplit

        try:
            hostname = urlsplit("//" + raw).hostname
        except ValueError:
            return False
        return bool(hostname and hostname.lower().strip("[]") in server.config.allowed_hosts)

    observer = H2FrameObserver(lambda kind, payload: emit(kind, payload,
        stream_id=payload.get("stream_id")), max_buffer_bytes=max(65_536,
        server.config.limits.header_bytes * 2))
    h2 = H2Connection(config=H2Configuration(client_side=False, header_encoding=None,
                                             normalize_inbound_headers=False,
                                             validate_inbound_headers=True))
    h2.local_settings.max_header_list_size = server.config.limits.header_bytes
    h2.local_settings.max_concurrent_streams = 100
    h2.initiate_connection()
    outgoing = h2.data_to_send()
    observer.feed("out", outgoing)
    handler.connection.sendall(outgoing)

    def flush() -> None:
        data = h2.data_to_send()
        if data:
            observer.feed("out", data)
            handler.connection.sendall(data)
        while completed_responses:
            stream_id, meta = completed_responses.pop(0)
            emit("http.response_end", {"bytes_emitted": meta["bytes"],
                 "server_elapsed_ns": time.monotonic_ns() - meta["start_ns"]},
                 stream_id=stream_id, session_id=meta["session_id"], request_id=meta["request_id"])

    def send_response(stream_id: int, status: int, body: bytes, content_type: str,
                      session_id: str | None = None, request_id: str | None = None,
                      content_length: int | None = None) -> None:
        headers = [(b":status", str(status).encode()), (b"content-type", content_type.encode()),
                   (b"content-length", str(len(body) if content_length is None else content_length).encode()),
                   (b"cache-control", b"no-store")]
        emit("http.response_headers", {"status": status,
             "body_bytes": len(body) if content_length is None else content_length, "protocol": "h2"},
             stream_id=stream_id, session_id=session_id, request_id=request_id)
        h2.send_headers(stream_id, headers, end_stream=(not body))
        if body:
            pending[stream_id] = (status, body, content_type)
            response_meta[stream_id] = {"bytes": 0, "start_ns": time.monotonic_ns(),
                                        "session_id": session_id, "request_id": request_id}
        else:
            completed_responses.append((stream_id, {"bytes": 0, "start_ns": time.monotonic_ns(),
                "session_id": session_id, "request_id": request_id}))

    def flush_pending() -> None:
        for sid in list(pending):
            status, body, _ctype = pending[sid]
            while body:
                try:
                    window = h2.local_flow_control_window(sid)
                except H2Error:
                    pending.pop(sid, None)
                    break
                if window <= 0:
                    pending[sid] = (status, body, _ctype)
                    break
                amount = min(window, h2.max_outbound_frame_size, len(body))
                chunk, body = body[:amount], body[amount:]
                h2.send_data(sid, chunk, end_stream=not body)
                meta = response_meta.get(sid)
                if meta is not None:
                    meta["bytes"] += len(chunk)
            else:
                pending.pop(sid, None)
                meta = response_meta.pop(sid, None)
                if meta is not None:
                    completed_responses.append((sid, meta))

    while not terminated:
        data = handler.connection.recv(65536)
        if not data:
            break
        observer.feed("in", data)
        try:
            events = h2.receive_data(data)
        except H2Error as exc:
            LOGGER.info("HTTP/2 protocol error for %s: %s", handler.client_address[0], exc)
            break
        for event in events:
            if isinstance(event, RequestReceived):
                headers = list(event.headers)
                decoded_header_bytes = sum(len(name) + len(value) + 4 for name, value in headers)
                if decoded_header_bytes > server.config.limits.header_bytes:
                    h2.reset_stream(event.stream_id, error_code=11)
                    discarded_streams.add(event.stream_id)
                    emit("measurement.health", {"component": "http2_headers", "status": "limit_exceeded",
                         "decoded_bytes": decoded_header_bytes}, stream_id=event.stream_id)
                    emit("http.stream_reset", {"error_code": 11, "direction": "out"},
                         stream_id=event.stream_id)
                    continue
                names = [(k.decode("ascii", "replace"), v.decode("utf-8", "replace")) for k, v in headers]
                method = next((v for k, v in names if k == ":method"), "GET")
                target = next((v for k, v in names if k == ":path"), "/")
                request_id = uuid4().hex
                stream_request_ids[event.stream_id] = request_id
                stream_targets[event.stream_id] = (method, target)
                try:
                    target_parts = urlsplit(target)
                    sid = _session_id(target_parts.path)
                    if len(target) > 8192 or not target.startswith("/") or not valid_authority(headers):
                        h2.reset_stream(event.stream_id, error_code=1)
                        discarded_streams.add(event.stream_id)
                        stream_targets.pop(event.stream_id, None)
                        stream_request_ids.pop(event.stream_id, None)
                        emit("http.stream_reset", {"error_code": 1, "direction": "out"},
                             stream_id=event.stream_id)
                        continue
                    safe_names = []
                    retain_safe = server.config.logging.retain_safe_header_values
                    safe_header_values = {"accept", "accept-language", "content-type", "sec-fetch-dest",
                                          "sec-fetch-mode", "sec-fetch-site", "user-agent"}
                    for name, value in names:
                        if name.startswith(":"):
                            if name == ":method":
                                value = method
                            elif name == ":path":
                                value = _normalized_route(target)
                            else:
                                value = "<redacted>"
                        elif retain_safe and name.lower() in safe_header_values:
                            pass
                        else:
                            value = "<redacted>"
                        safe_names.append([name, value])
                    emit("http.request_headers", {"method": method, "query_present": bool(target_parts.query),
                         "normalized_route": _normalized_route(target), "headers_ordered": safe_names,
                         "protocol": "h2", "request_mono_ns": time.monotonic_ns()},
                         stream_id=event.stream_id, session_id=sid, request_id=request_id)
                except Exception:
                    send_response(event.stream_id, 400, b'{"error":"Bad request"}\n', "application/json")
                    discarded_streams.add(event.stream_id)
            elif isinstance(event, DataReceived):
                if event.stream_id in discarded_streams:
                    h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    continue
                body = stream_body[event.stream_id]
                h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                if len(body) + len(event.data) > server.config.limits.request_body_bytes:
                    h2.reset_stream(event.stream_id, error_code=1)
                    discarded_streams.add(event.stream_id)
                    stream_body.pop(event.stream_id, None)
                    stream_targets.pop(event.stream_id, None)
                    stream_request_ids.pop(event.stream_id, None)
                    emit("measurement.health", {"component": "http2_body", "status": "limit_exceeded"},
                         stream_id=event.stream_id)
                    emit("http.stream_reset", {"error_code": 1, "direction": "out"},
                         stream_id=event.stream_id)
                else:
                    body.extend(event.data)
            elif isinstance(event, StreamEnded):
                if event.stream_id in discarded_streams:
                    discarded_streams.discard(event.stream_id)
                    stream_body.pop(event.stream_id, None)
                    stream_targets.pop(event.stream_id, None)
                    stream_request_ids.pop(event.stream_id, None)
                    continue
                method, target = stream_targets.pop(event.stream_id, ("GET", "/"))
                request_body = bytes(stream_body.pop(event.stream_id, b""))
                status, body, ctype, sid, route, transitions = server.tasks.handle(method, target, request_body)
                request_id = stream_request_ids.pop(event.stream_id, None)
                for transition in transitions:
                    emit("task.transition", transition, stream_id=event.stream_id,
                         session_id=sid, request_id=request_id)
                emit("http.request_end", {"body_bytes": len(request_body), "route": route},
                     stream_id=event.stream_id, session_id=sid,
                     request_id=request_id)
                representation_bytes = len(body)
                if method == "HEAD":
                    body = b""
                send_response(event.stream_id, status, body, ctype, sid, request_id,
                              content_length=representation_bytes)
            elif isinstance(event, StreamReset):
                pending.pop(event.stream_id, None)
                response_meta.pop(event.stream_id, None)
                stream_body.pop(event.stream_id, None)
                stream_targets.pop(event.stream_id, None)
                stream_request_ids.pop(event.stream_id, None)
                discarded_streams.discard(event.stream_id)
                emit("http.stream_reset", {"error_code": int(event.error_code), "direction": "in"},
                     stream_id=event.stream_id)
            elif isinstance(event, WindowUpdated):
                flush_pending()
            elif isinstance(event, ConnectionTerminated):
                terminated = True
        flush_pending()
        flush()
    observer.finish()
    try:
        h2.close_connection()
        flush()
    except (H2Error, OSError):
        pass


def _session_id(path: str) -> str | None:
    parts = path.split("/")
    return parts[2] if len(parts) >= 4 and parts[1] == "s" else None


def _normalized_route(target: str) -> str:
    path = urlsplit(target).path
    parts = path.split("/")
    if len(parts) >= 4 and parts[1] == "s":
        suffix = "/".join(parts[3:])
        if suffix.startswith("item/"):
            return "detail"
        if suffix.startswith("assets/img/"):
            return "asset_image"
        return {"start": "start", "api/search": "search_api", "api/save": "save_api",
                "complete": "confirmation", "assets/style.css": "asset_css",
                "assets/app.js": "asset_js", "assets/large.bin": "asset_large",
                "favicon.ico": "favicon"}.get(suffix, "other")
    return "healthz" if path == "/healthz" else "root" if path == "/" else "other"
