"""Bounded, append-only JSONL event writer and run manifest lifecycle."""

from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from beyond_handshake.schemas.events import EventEnvelope, RunManifest


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write(data)
        stream.flush()
    temporary.replace(path)


class EventWriter:
    """Serialize events from server threads to one append-only JSONL file."""

    _STOP = object()

    def __init__(
        self,
        output_dir: Path,
        queue_items: int,
        config_sha256: str,
        server_metadata: dict[str, Any],
    ) -> None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.run_id = f"{stamp}-{uuid4().hex[:8]}"
        self.run_dir = output_dir / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.events_path = self.run_dir / "events.jsonl"
        self.manifest_path = self.run_dir / "manifest.json"
        self.producer_id = uuid4().hex
        self._seq = 0
        self._seq_lock = threading.Lock()
        self._queue: queue.Queue[dict[str, Any] | object] = queue.Queue(maxsize=queue_items)
        self._state_lock = threading.Lock()
        self._count = 0
        self._dropped = 0
        self._error: str | None = None
        self._closed = False
        self._started_ns = time.time_ns()
        self._config_sha256 = config_sha256
        self._server_metadata = server_metadata
        self._write_manifest("partial")
        self._worker = threading.Thread(target=self._write_loop, name="bh-event-writer", daemon=True)
        self._worker.start()

    def _manifest(self, status: str, **kwargs: Any) -> RunManifest:
        with self._state_lock:
            return RunManifest(
                schema_version="1.0",
                run_id=self.run_id,
                status=status,
                started_wall_ns=self._started_ns,
                source_commit=None,
                config_sha256=self._config_sha256,
                server=self._server_metadata,
                event_count=self._count,
                dropped_events=self._dropped,
                failure=self._error,
                **kwargs,
            )

    def _write_manifest(self, status: str, **kwargs: Any) -> None:
        _atomic_json(self.manifest_path, self._manifest(status, **kwargs).to_dict())

    def emit(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        connection_id: str | None = None,
        request_id: str | None = None,
    ) -> None:
        with self._state_lock:
            if self._closed:
                raise RuntimeError("event writer is closed")
            if self._error:
                raise RuntimeError(f"event writer failed: {self._error}")
        with self._seq_lock:
            self._seq += 1
            event = EventEnvelope(
                schema_version="1.0",
                event_type=event_type,
                event_id=uuid4().hex,
                producer_id=self.producer_id,
                seq=self._seq,
                ts_wall_ns=time.time_ns(),
                ts_mono_ns=time.monotonic_ns(),
                run_id=self.run_id,
                session_id=session_id,
                connection_id=connection_id,
                request_id=request_id,
                payload=payload,
            )
            try:
                self._queue.put_nowait(event.to_dict())
            except queue.Full as exc:
                with self._state_lock:
                    self._dropped += 1
                    self._error = "event queue overflow"
                self._write_manifest("partial")
                raise RuntimeError("event queue overflow; this run is invalid") from exc

    def _write_loop(self) -> None:
        try:
            with self.events_path.open("a", encoding="utf-8") as stream:
                while True:
                    item = self._queue.get()
                    try:
                        if item is self._STOP:
                            stream.flush()
                            return
                        stream.write(json.dumps(item, separators=(",", ":"), ensure_ascii=False))
                        stream.write("\n")
                        stream.flush()
                        with self._state_lock:
                            self._count += 1
                    finally:
                        self._queue.task_done()
        except Exception as exc:  # Keep a failed writer visible to the server and manifest.
            with self._state_lock:
                self._error = f"{type(exc).__name__}: {exc}"

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
        if self._worker.is_alive():
            try:
                self._queue.put(self._STOP, timeout=2)
            except queue.Full:
                with self._state_lock:
                    self._error = self._error or "event queue did not drain during shutdown"
        self._worker.join(timeout=10)
        if self._worker.is_alive():
            with self._state_lock:
                self._error = self._error or "event writer did not stop within 10 seconds"
        digest = None
        if self.events_path.exists():
            hasher = hashlib.sha256()
            with self.events_path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
        end = time.time_ns()
        self._write_manifest(
            "failed" if self._error else "complete",
            event_file_sha256=digest,
            ended_wall_ns=end,
        )
