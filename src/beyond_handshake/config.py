"""Validated TOML configuration for the local server."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class TLSConfig:
    cert: Path
    key: Path
    minimum_version: str
    alpn: tuple[str, ...]
    keylog_path: Path | None


@dataclass(frozen=True, slots=True)
class LimitsConfig:
    request_body_bytes: int
    header_bytes: int
    idle_seconds: float
    handshake_seconds: float
    event_queue_items: int


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    output_dir: Path
    retain_safe_header_values: bool


@dataclass(frozen=True, slots=True)
class ServerConfig:
    schema_version: str
    listen_host: str
    listen_port: int
    control_port: int
    allowed_hosts: frozenset[str]
    tls: TLSConfig
    limits: LimitsConfig
    logging: LoggingConfig
    config_path: Path


def _keys(value: dict[str, Any], required: set[str], label: str) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required
    if missing or unknown:
        parts = []
        if missing:
            parts.append(f"missing {sorted(missing)}")
        if unknown:
            parts.append(f"unknown {sorted(unknown)}")
        raise ValueError(f"invalid {label} keys: " + "; ".join(parts))


def load_server_config(path: Path) -> ServerConfig:
    config_path = path.expanduser().resolve()
    with config_path.open("rb") as stream:
        raw = tomllib.load(stream)
    if not isinstance(raw, dict):
        raise ValueError("server config must be a TOML table")
    _keys(
        raw,
        {"schema_version", "listen_host", "listen_port", "control_port", "allowed_hosts", "tls", "limits", "logging"},
        "server",
    )
    if raw["schema_version"] != "1.0":
        raise ValueError("unsupported server schema_version; expected '1.0'")
    host = raw["listen_host"]
    port = raw["listen_port"]
    if not isinstance(host, str) or not host:
        raise ValueError("listen_host must be a non-empty string")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("listen_port must be an integer between 1 and 65535")
    control_port = raw["control_port"]
    if not isinstance(control_port, int) or isinstance(control_port, bool) or not 1 <= control_port <= 65535:
        raise ValueError("control_port must be an integer between 1 and 65535")
    if control_port == port:
        raise ValueError("control_port must differ from listen_port")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("listen_host must be loopback; explicit non-local binding is not supported")

    allowed = raw["allowed_hosts"]
    if not isinstance(allowed, list) or not allowed or any(not isinstance(x, str) for x in allowed):
        raise ValueError("allowed_hosts must be a non-empty array of hostnames")
    allowed_hosts = frozenset(x.lower().strip("[]") for x in allowed)

    tls = raw["tls"]
    if not isinstance(tls, dict):
        raise ValueError("tls must be a TOML table")
    _keys(tls, {"cert", "key", "minimum_version", "alpn", "keylog_path"}, "tls")
    for key in ("cert", "key", "minimum_version"):
        if not isinstance(tls[key], str) or not tls[key]:
            raise ValueError(f"tls.{key} must be a non-empty string")
    if tls["minimum_version"] not in {"TLSv1_2", "TLSv1_3"}:
        raise ValueError("minimum_version must be TLSv1_2 or TLSv1_3")
    alpn = tls["alpn"]
    if not isinstance(alpn, list) or not alpn or any(x not in {"http/1.1", "h2"} for x in alpn):
        raise ValueError("tls.alpn must contain only http/1.1 and/or h2")
    if len(set(alpn)) != len(alpn):
        raise ValueError("tls.alpn must not contain duplicates")
    keylog_raw = tls["keylog_path"]
    if not isinstance(keylog_raw, str):
        raise ValueError("tls.keylog_path must be an empty string or a relative/absolute path")
    config_dir = next(
        (parent for parent in config_path.parents if (parent / "pyproject.toml").is_file()),
        config_path.parent,
    )

    limits = raw["limits"]
    if not isinstance(limits, dict):
        raise ValueError("limits must be a TOML table")
    _keys(
        limits,
        {"request_body_bytes", "header_bytes", "idle_seconds", "handshake_seconds", "event_queue_items"},
        "limits",
    )
    for key in ("request_body_bytes", "header_bytes", "event_queue_items"):
        if not isinstance(limits[key], int) or isinstance(limits[key], bool) or limits[key] < 1:
            raise ValueError(f"limits.{key} must be a positive integer")
    for key in ("idle_seconds", "handshake_seconds"):
        if not isinstance(limits[key], (int, float)) or limits[key] <= 0:
            raise ValueError(f"limits.{key} must be a positive number")

    logging = raw["logging"]
    if not isinstance(logging, dict):
        raise ValueError("logging must be a TOML table")
    _keys(logging, {"output_dir", "retain_safe_header_values"}, "logging")
    if not isinstance(logging["output_dir"], str) or not logging["output_dir"]:
        raise ValueError("logging.output_dir must be a non-empty string")
    retain = logging["retain_safe_header_values"]
    if not isinstance(retain, bool):
        raise ValueError("logging.retain_safe_header_values must be boolean")

    return ServerConfig(
        schema_version="1.0",
        listen_host=host,
        listen_port=port,
        control_port=control_port,
        allowed_hosts=allowed_hosts,
        tls=TLSConfig(
            cert=(config_dir / tls["cert"]).resolve(),
            key=(config_dir / tls["key"]).resolve(),
            minimum_version=tls["minimum_version"],
            alpn=tuple(alpn),
            keylog_path=(config_dir / keylog_raw).resolve() if keylog_raw else None,
        ),
        limits=LimitsConfig(
            request_body_bytes=limits["request_body_bytes"],
            header_bytes=limits["header_bytes"],
            idle_seconds=float(limits["idle_seconds"]),
            handshake_seconds=float(limits["handshake_seconds"]),
            event_queue_items=limits["event_queue_items"],
        ),
        logging=LoggingConfig(
            output_dir=(config_dir / logging["output_dir"]).resolve(),
            retain_safe_header_values=retain,
        ),
        config_path=config_path,
    )
