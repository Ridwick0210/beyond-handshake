"""Bounded structural observer for decrypted HTTP/2 bytes.

The observer records frame boundaries and SETTINGS entries without interpreting
HPACK or changing bytes passed to hyper-h2. Times are receive observation times.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_TYPES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
    4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
    8: "WINDOW_UPDATE", 9: "CONTINUATION",
}


@dataclass(slots=True)
class _DirectionState:
    buffer: bytearray = field(default_factory=bytearray)
    preface_checked: bool = False
    preface_buffer: bytearray = field(default_factory=bytearray)


class H2FrameObserver:
    """Incrementally identify frame headers; memory is capped per direction."""

    def __init__(self, emit: Callable[[str, dict], None], max_buffer_bytes: int = 1_048_576):
        if max_buffer_bytes < 9:
            raise ValueError("max_buffer_bytes must be at least one frame header")
        self.emit = emit
        self.max_buffer_bytes = max_buffer_bytes
        self._states = {"in": _DirectionState(), "out": _DirectionState(preface_checked=True)}
        self._disabled = False

    def feed(self, direction: str, data: bytes) -> None:
        if self._disabled:
            return
        if direction not in self._states:
            raise ValueError("direction must be 'in' or 'out'")
        state = self._states[direction]
        if not state.preface_checked:
            combined = bytes(state.preface_buffer) + data
            prefix_len = min(len(combined), len(CLIENT_PREFACE))
            if combined[:prefix_len] != CLIENT_PREFACE[:prefix_len]:
                self.emit("http2.preface", {"direction": direction, "valid": False,
                                             "observed_mono_ns": time.monotonic_ns()})
                state.preface_checked = True
                state.preface_buffer.clear()
                data = combined
            elif len(combined) >= len(CLIENT_PREFACE):
                self.emit("http2.preface", {"direction": direction, "valid": True,
                                             "observed_mono_ns": time.monotonic_ns()})
                state.preface_buffer.clear()
                state.preface_checked = True
                data = combined[len(CLIENT_PREFACE):]
            else:
                state.preface_buffer.extend(data)
                return
        chunk_size = max(1, self.max_buffer_bytes // 2)
        for offset in range(0, len(data), chunk_size):
            state.buffer.extend(data[offset:offset + chunk_size])
            self._drain(direction, state)
            if self._disabled:
                return

    def _disable(self, reason: str) -> None:
        self._disabled = True
        for state in self._states.values():
            state.buffer.clear()
            state.preface_buffer.clear()
        self.emit("measurement.health", {"component": "http2_frame_observer",
                                          "status": "disabled", "reason": reason})

    def _drain(self, direction: str, state: _DirectionState) -> None:
        if len(state.buffer) > self.max_buffer_bytes:
            self._disable("observer buffer limit exceeded")
            return
        while len(state.buffer) >= 9:
            length = int.from_bytes(state.buffer[:3], "big")
            if length + 9 > self.max_buffer_bytes:
                self._disable("frame exceeds observer buffer limit")
                return
            if len(state.buffer) < length + 9:
                return
            frame_type = state.buffer[3]
            flags = state.buffer[4]
            stream_id = int.from_bytes(state.buffer[5:9], "big") & 0x7FFFFFFF
            payload = bytes(state.buffer[9:9 + length])
            del state.buffer[:9 + length]
            at_ns = time.monotonic_ns()
            info = {"direction": direction, "frame_type": frame_type,
                    "frame_name": FRAME_TYPES.get(frame_type, "UNKNOWN"), "flags": flags,
                    "stream_id": stream_id, "payload_length": length,
                    "observed_mono_ns": at_ns}
            if frame_type == 8 and length == 4:
                info["window_increment"] = int.from_bytes(payload, "big") & 0x7FFFFFFF
            elif frame_type == 3 and length == 4:
                info["error_code"] = int.from_bytes(payload, "big")
            elif frame_type == 7 and length >= 8:
                info["last_stream_id"] = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                info["error_code"] = int.from_bytes(payload[4:8], "big")
            self.emit("http2.frame", info)
            if frame_type == 4:
                ack = bool(flags & 0x1)
                entries = []
                if not ack and length % 6 == 0:
                    for offset in range(0, length, 6):
                        entries.append({"setting_id": int.from_bytes(payload[offset:offset + 2], "big"),
                                        "value": int.from_bytes(payload[offset + 2:offset + 6], "big")})
                self.emit("http2.settings", {"direction": direction, "ack": ack,
                                              "entries": entries, "observed_mono_ns": at_ns})

    def finish(self) -> None:
        if self._disabled:
            return
        state = self._states["in"]
        if state.preface_buffer or state.buffer:
            self.emit("measurement.health", {"component": "http2_frame_observer",
                                              "status": "truncated_input",
                                              "buffered_bytes": len(state.preface_buffer) + len(state.buffer)})
