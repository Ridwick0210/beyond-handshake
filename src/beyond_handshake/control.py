"""Loopback-only control plane, isolated from measured task traffic."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from beyond_handshake.tasks import TaskOracle


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], oracle: TaskOracle, run_id: str):
        self.oracle = oracle
        self.run_id = run_id
        super().__init__(address, ControlHandler)


class ControlHandler(BaseHTTPRequestHandler):
    server: ControlServer

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def _reply(self, status: int, value: dict) -> None:
        body = (json.dumps(value, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _local_only(self) -> bool:
        return self.client_address[0] in {"127.0.0.1", "::1"}

    def do_POST(self) -> None:
        if not self._local_only():
            self._reply(403, {"error": "control plane is loopback-only"})
            return
        if self.path != "/sessions":
            self._reply(404, {"error": "not found"})
            return
        length_raw = self.headers.get("Content-Length", "")
        if not length_raw.isdigit() or int(length_raw) > 4096:
            self._reply(413, {"error": "invalid control request size"})
            return
        try:
            data = json.loads(self.rfile.read(int(length_raw)))
            result = self.server.oracle.register(data["session_id"], data["seed"],
                                                 data.get("task_id", "catalog-search-detail-save-v1"))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self._reply(400, {"error": str(exc)})
            return
        self._reply(201, result)

    def do_GET(self) -> None:
        if not self._local_only():
            self._reply(403, {"error": "control plane is loopback-only"})
            return
        if self.path == "/run":
            self._reply(200, {"run_id": self.server.run_id})
            return
        parts = self.path.strip("/").split("/")
        if len(parts) != 3 or parts[0] != "sessions" or parts[2] != "outcome":
            self._reply(404, {"error": "not found"})
            return
        try:
            result = self.server.oracle.outcome(parts[1])
        except KeyError as exc:
            self._reply(404, {"error": str(exc)})
            return
        self._reply(200, result)
