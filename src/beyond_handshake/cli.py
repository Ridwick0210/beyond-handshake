"""Command-line entry point for the local prototype."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import ssl
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from beyond_handshake import __version__
from beyond_handshake.certificates import create_lab_certificate
from beyond_handshake.config import load_server_config


def _project_root() -> Path:
    return next(
        (parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file()),
        Path.cwd(),
    )


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)


def _doctor(output: Path | None) -> int:
    root = _project_root()
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "collected_at_utc": datetime.now(UTC).isoformat(),
        "prototype_version": __version__,
        "python_version": sys.version,
        "openssl_version": ssl.OPENSSL_VERSION,
        "tls_alpn_supported": bool(ssl.HAS_ALPN),
        "openssl_cli": shutil.which("openssl"),
        "curl_cli": shutil.which("curl"),
        "project_root": str(root),
        "packet_capture": "deferred to Phase 6",
        "http2": "deferred to Phase 4",
        "git_commit": None,
    }
    config_path = root / "configs" / "server.toml"
    result["server_config"] = str(config_path)
    try:
        config = load_server_config(config_path)
        result["server_config_valid"] = True
        result["server_certificate_present"] = config.tls.cert.is_file()
        result["server_private_key_present"] = config.tls.key.is_file()
        result["event_output_directory"] = str(config.logging.output_dir)
    except (OSError, ValueError) as exc:
        result["server_config_valid"] = False
        result["server_config_error"] = str(exc)

    required_ok = (
        sys.version_info >= (3, 12)
        and ssl.HAS_ALPN
        and bool(result.get("server_config_valid"))
        and bool(result.get("server_certificate_present"))
        and bool(result.get("server_private_key_present"))
    )
    result["status"] = "ready_to_serve" if required_ok else "setup_required"
    if output:
        _write_json(output.expanduser().resolve(), result)
    print(json.dumps(result, indent=2))
    return 0 if required_ok else 2


def _cert(args: argparse.Namespace) -> int:
    cert, server_cert, server_key = create_lab_certificate(args.out, args.hostname)
    print(f"Local CA: {cert}")
    print(f"Server certificate: {server_cert}")
    print(f"Server private key: {server_key}")
    print("Trust this CA only in an isolated test client/profile. Do not install it system-wide.")
    return 0


def _server(args: argparse.Namespace) -> int:
    from beyond_handshake.server.http1 import serve

    config_path = args.config.expanduser().resolve()
    try:
        config = load_server_config(config_path)
    except (OSError, ValueError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    digest = hashlib.sha256(config_path.read_bytes()).hexdigest()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logging.Formatter.converter = time.gmtime
    try:
        serve(config, digest)
    except (OSError, ssl.SSLError, RuntimeError) as exc:
        logging.getLogger("beyond_handshake").error("server could not start: %s", exc)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bh",
        description="Local prototype for controlled browser-stack measurement (Phases 0–3).",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="inspect local runtime prerequisites")
    doctor.add_argument("--output", type=Path, help="write the environment report as JSON")

    cert = commands.add_parser("cert", help="manage local development certificates")
    cert_commands = cert.add_subparsers(dest="cert_command", required=True)
    create = cert_commands.add_parser("create", help="create a local CA and HTTPS server certificate")
    create.add_argument("--hostname", action="append", required=True, help="DNS name or IP SAN; repeatable")
    create.add_argument("--out", type=Path, default=Path("local/tls"))

    server = commands.add_parser("server", help="run the localhost HTTPS/HTTP/1.1 prototype")
    server.add_argument("--config", type=Path, default=Path("configs/server.toml"))
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "doctor":
            return _doctor(args.output)
        if args.command == "cert":
            return _cert(args)
        if args.command == "server":
            return _server(args)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
