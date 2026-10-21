"""TLS-wrapped HTTP/1.1 endpoint using Python's standard library parser."""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from beyond_handshake.config import ServerConfig
from beyond_handshake.event_writer import EventWriter

LOGGER = logging.getLogger("beyond_handshake.server")
_SESSION_ROUTE = re.compile(r"^/s/([A-Za-z0-9_-]{1,80})(?:/|$)")
_SAFE_VALUE_HEADERS = {
    "accept",
    "accept-language",
    "content-type",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "user-agent",
}


class LocalHTTPServer(ThreadingHTTPServer):
    """One local TLS endpoint; application logs are emitted after TLS termination."""

    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, address: tuple[str, int], config: ServerConfig, context: ssl.SSLContext,
                 events: EventWriter) -> None:
        self.config = config
        self.events = events
        self.ssl_context = context
        super().__init__(address, RequestHandler, bind_and_activate=True)

    def get_request(self) -> tuple[ssl.SSLSocket, Any]:
        sock, address = super().get_request()
        sock.settimeout(self.config.limits.handshake_seconds)
        wrapped = self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return wrapped, address

    def handle_error(self, request: Any, client_address: tuple[str, int]) -> None:
        LOGGER.info("connection handler ended with an error for %s", client_address[0], exc_info=True)


class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BeyondHandshake"
    sys_version = ""
    timeout = 30

    @property
    def app_server(self) -> LocalHTTPServer:
        return self.server  # type: ignore[return-value]

    def setup(self) -> None:
        self.connection = self.request
        self._setup_failed = False
        self.connection_id: str | None = None
        self._open_logged = False
        try:
            self.connection.do_handshake()
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            self._setup_failed = True
            LOGGER.info("TLS handshake failed for %s: %s", self.client_address[0], exc)
            self.connection.close()
            return
        self.connection.settimeout(self.app_server.config.limits.idle_seconds)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)
        self.connection_id = uuid4().hex
        cipher = self.connection.cipher()
        self.app_server.events.emit(
            "connection.open",
            {
                "peer_ip": self.client_address[0],
                "peer_port": self.client_address[1],
                "local_ip": self.connection.getsockname()[0],
                "local_port": self.connection.getsockname()[1],
                "transport": "tcp",
                "tls_version": self.connection.version(),
                "tls_cipher": cipher[0] if cipher else None,
                "tls_alpn": self.connection.selected_alpn_protocol(),
                "server_name": self.connection.server_hostname,
            },
            connection_id=self.connection_id,
        )
        self._open_logged = True

    def handle(self) -> None:
        if not self._setup_failed:
            super().handle()

    def finish(self) -> None:
        if self._open_logged and self.connection_id:
            try:
                self.app_server.events.emit(
                    "connection.close",
                    {"reason": "handler_finished"},
                    connection_id=self.connection_id,
                )
            except RuntimeError:
                LOGGER.exception("could not record connection close")
        if hasattr(self, "wfile"):
            try:
                self.wfile.flush()
            except (OSError, ValueError):
                pass
            self.wfile.close()
        if hasattr(self, "rfile"):
            self.rfile.close()
        if hasattr(self, "connection"):
            self.connection.close()

    def log_message(self, format_string: str, *args: Any) -> None:
        LOGGER.info("%s - %s", self.client_address[0], format_string % args)

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        if not self.connection_id:
            return
        self.app_server.events.emit(
            "http.response",
            {
                "status": int(code) if str(code).isdigit() else None,
                "body_bytes": int(size) if str(size).isdigit() else None,
            },
            connection_id=self.connection_id,
            request_id=getattr(self, "_request_id", None),
            session_id=getattr(self, "_session_id", None),
        )

    def send_response(self, code: int, message: str | None = None) -> None:
        """Write the normal server/date headers and defer event logging until body size is known."""
        self.send_response_only(code, message)
        self.send_header("Server", self.version_string())
        self.send_header("Date", self.date_time_string())

    def _send_json(self, status: int, payload: dict[str, Any], *, close: bool = False) -> None:
        body = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if getattr(self, "command", "") != "HEAD":
            self.wfile.write(body)
        self.log_request(status, len(body))

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        del message, explain
        descriptions = {
            400: "Bad request",
            404: "Route not found",
            405: "Method not allowed",
            408: "Request timed out",
            413: "Request body too large",
            414: "Request target too long",
            431: "Request headers too large",
            500: "Internal server error",
            501: "Transfer encoding is not supported by this prototype",
        }
        reason = descriptions.get(code, "Request rejected")
        try:
            self._send_json(code, {"error": reason}, close=True)
        except (OSError, ssl.SSLError, RuntimeError):
            self.close_connection = True

    def handle_expect_100(self) -> bool:
        self.send_response_only(100)
        self.end_headers()
        return True

    def _validate_host(self) -> bool:
        raw_host = self.headers.get("Host", "")
        try:
            hostname = urlsplit("//" + raw_host).hostname
        except ValueError:
            return False
        if not hostname:
            return False
        return hostname.lower().strip("[]") in self.app_server.config.allowed_hosts

    def _read_body(self) -> bytes | None:
        transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
        if transfer_encodings:
            self.send_error(501)
            return None
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) > 1:
            self.send_error(400)
            return None
        if not lengths:
            return b""
        raw_length = lengths[0].strip()
        if not raw_length.isascii() or not raw_length.isdigit():
            self.send_error(400)
            return None
        length = int(raw_length)
        if length > self.app_server.config.limits.request_body_bytes:
            self.send_error(413)
            return None
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error(400)
            return None
        return body

    def _header_log(self) -> list[list[str]]:
        retain_safe = self.app_server.config.logging.retain_safe_header_values
        result = []
        for name, value in self.headers.raw_items():
            normalized = name.lower()
            visible = value if retain_safe and normalized in _SAFE_VALUE_HEADERS else "<redacted>"
            result.append([name, visible])
        return result

    def _route(self) -> tuple[int, bytes, str]:
        if self.command == "HEAD" or self.command == "GET":
            if self.path == "/healthz":
                return 200, b'{"status":"ok","phase":3,"protocol":"http/1.1"}\n', "application/json"
            if self.path == "/":
                return 200, _INDEX_HTML, "text/html; charset=utf-8"
        if self.command in {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}:
            return 404, b'{"error":"Route not found"}\n', "application/json"
        return 405, b'{"error":"Method not allowed"}\n', "application/json"

    def _dispatch(self) -> None:
        started_mono = time.monotonic_ns()
        path = self.path
        try:
            parsed_target = urlsplit(path)
        except ValueError:
            self.send_error(400)
            return
        if parsed_target.scheme or parsed_target.netloc or not parsed_target.path.startswith("/"):
            self.send_error(400)
            return
        if len(path) > 8192:
            self.send_error(414)
            return
        header_bytes = sum(len(name) + len(value) + 4 for name, value in self.headers.raw_items())
        if header_bytes > self.app_server.config.limits.header_bytes:
            self.send_error(431)
            return
        if self.request_version >= "HTTP/1.1" and not self._validate_host():
            self.send_error(400)
            return
        body = self._read_body()
        if body is None:
            return

        self._request_id = uuid4().hex
        match = _SESSION_ROUTE.match(parsed_target.path)
        self._session_id = match.group(1) if match else None
        try:
            self.app_server.events.emit(
                "http.request",
                {
                    "method": self.command,
                    "route": parsed_target.path,
                    "http_version": self.request_version,
                    "headers_ordered": self._header_log(),
                    "body_bytes": len(body),
                    "request_mono_ns": started_mono,
                    "query_present": bool(parsed_target.query),
                },
                connection_id=self.connection_id,
                request_id=self._request_id,
                session_id=self._session_id,
            )
        except RuntimeError:
            LOGGER.exception("measurement event writer failed; stopping this request")
            self.send_error(500)
            return

        status, response_body, content_type = self._route()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response_body)
        elapsed_ns = time.monotonic_ns() - started_mono
        try:
            self.app_server.events.emit(
                "http.request_end",
                {"status": status, "server_elapsed_ns": elapsed_ns},
                connection_id=self.connection_id,
                request_id=self._request_id,
                session_id=self._session_id,
            )
            self.log_request(status, len(response_body))
        except RuntimeError:
            LOGGER.exception("measurement event writer failed after response")
            self.close_connection = True

    do_GET = _dispatch
    do_HEAD = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_DELETE = _dispatch
    do_PATCH = _dispatch
    do_OPTIONS = _dispatch


_INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Beyond Handshake</title><style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141b2e;--ink:#edf2ff;--muted:#aab5ce;--line:#293450;--accent:#71e2c2}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 85% 0%,#1a3150 0,transparent 38%),var(--bg);color:var(--ink);font:16px/1.6 system-ui,sans-serif}
main{width:min(900px,calc(100% - 36px));margin:8vh auto}.eyebrow{color:var(--accent);font-size:.78rem;letter-spacing:.16em;text-transform:uppercase}
h1{font-size:clamp(2.4rem,7vw,5rem);line-height:1.02;letter-spacing:-.045em;margin:.65rem 0 1rem;max-width:760px}
.lead{max-width:650px;color:var(--muted);font-size:1.12rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:36px 0}
article{background:linear-gradient(145deg,#171f34,#11182a);border:1px solid var(--line);border-radius:16px;padding:20px}
article b{display:block;color:var(--accent);font-size:.78rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px}
article p{margin:0;color:var(--muted)}.status{border-top:1px solid var(--line);padding-top:18px;color:var(--muted);font-size:.92rem}
a{color:var(--accent)}code{color:#fff;background:#202b42;padding:.12em .4em;border-radius:5px}
</style></head><body><main><div class="eyebrow">Network measurement prototype · Phase 3</div>
<h1>Beyond the TLS handshake.</h1><p class="lead">A controlled local project exploring what network behavior can reveal when a browserless client tries to resemble a real browser.</p>
<section class="grid"><article><b>Current endpoint</b><p>HTTPS with TLS terminated here. Requests are recorded as structured, redacted JSONL events.</p></article>
<article><b>Available protocol</b><p>HTTP/1.1. The TLS session records its negotiated version, cipher, and ALPN selection.</p></article>
<article><b>Research status</b><p>Prototype only. No detector, HTTP/2 measurement, packet capture, or research result is available yet.</p></article></section>
<p class="status">Health check: <a href="/healthz">/healthz</a> · Local endpoint intended for controlled development traffic.</p>
</main></body></html>""".encode("utf-8")


def make_ssl_context(config: ServerConfig) -> ssl.SSLContext:
    if not config.tls.cert.is_file():
        raise FileNotFoundError(f"TLS certificate not found: {config.tls.cert}; run 'bh cert create'")
    if not config.tls.key.is_file():
        raise FileNotFoundError(f"TLS private key not found: {config.tls.key}; run 'bh cert create'")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = (
        ssl.TLSVersion.TLSv1_2
        if config.tls.minimum_version == "TLSv1_2"
        else ssl.TLSVersion.TLSv1_3
    )
    context.set_alpn_protocols(list(config.tls.alpn))
    context.load_cert_chain(str(config.tls.cert), str(config.tls.key))
    if config.tls.keylog_path:
        config.tls.keylog_path.parent.mkdir(parents=True, exist_ok=True)
        context.keylog_filename = str(config.tls.keylog_path)
    return context


def serve(config: ServerConfig, config_sha256: str) -> None:
    context = make_ssl_context(config)
    metadata = {
        "listen_host": config.listen_host,
        "listen_port": config.listen_port,
        "alpn": list(config.tls.alpn),
        "minimum_tls_version": config.tls.minimum_version,
        "server_tls_terminates_connection": True,
        "phase": 3,
    }
    events = EventWriter(
        config.logging.output_dir,
        config.limits.event_queue_items,
        config_sha256,
        metadata,
    )
    server = LocalHTTPServer((config.listen_host, config.listen_port), config, context, events)
    LOGGER.info(
        "local prototype listening at https://%s:%d (run_id=%s; HTTP/1.1 only)",
        config.listen_host,
        config.listen_port,
        events.run_id,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        LOGGER.info("shutdown requested")
    finally:
        server.server_close()
        events.close()
        LOGGER.info("run finalized at %s", events.run_dir)
