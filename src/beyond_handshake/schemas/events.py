"""Small standard-library schemas with explicit validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    schema_version: str
    event_type: str
    event_id: str
    producer_id: str
    seq: int
    ts_wall_ns: int
    ts_mono_ns: int
    run_id: str
    session_id: str | None = None
    connection_id: str | None = None
    stream_id: int | None = None
    request_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("unsupported event schema_version")
        if not self.event_type or not self.event_id or not self.producer_id or not self.run_id:
            raise ValueError("event type and identifiers must be non-empty")
        if self.seq < 0 or self.ts_wall_ns < 0 or self.ts_mono_ns < 0:
            raise ValueError("sequence and timestamps must be non-negative")
        if self.stream_id is not None and self.stream_id < 0:
            raise ValueError("stream_id must be non-negative")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be a JSON object")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RunManifest:
    schema_version: str
    run_id: str
    status: str
    started_wall_ns: int
    source_commit: str | None
    config_sha256: str
    server: dict[str, Any]
    event_count: int = 0
    dropped_events: int = 0
    event_file_sha256: str | None = None
    ended_wall_ns: int | None = None
    failure: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("unsupported run manifest schema_version")
        if self.status not in {"partial", "complete", "failed"}:
            raise ValueError("run status must be partial, complete, or failed")
        if not self.run_id or self.started_wall_ns < 0:
            raise ValueError("run id must be non-empty and start timestamp non-negative")
        if self.event_count < 0 or self.dropped_events < 0:
            raise ValueError("event counters must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
