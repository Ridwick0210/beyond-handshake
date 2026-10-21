"""Command-line entry point for the local prototype."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import asdict
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


def _module_available(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


def _git_commit() -> str | None:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=_project_root(),
                                capture_output=True, text=True, timeout=2, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def _git_dirty() -> bool | None:
    try:
        result = subprocess.run(["git", "status", "--porcelain"], cwd=_project_root(),
                                capture_output=True, text=True, timeout=2, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return bool(result.stdout.strip())


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
        "packet_capture": {"tshark": shutil.which("tshark"), "dumpcap": shutil.which("dumpcap")},
        "http2": _module_available("h2"),
        "browser": {"chrome": shutil.which("google-chrome"),
                    "chromium": shutil.which("chromium"),
                    "playwright": _module_available("playwright")},
        "curl_cffi": _module_available("curl_cffi"),
        "git_commit": _git_commit(),
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
        and bool(result.get("http2"))
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
        serve(config, digest, _git_commit(), _git_dirty())
    except (OSError, ssl.SSLError, RuntimeError) as exc:
        logging.getLogger("beyond_handshake").error("server could not start: %s", exc)
        return 2
    return 0


def _task(args: argparse.Namespace) -> int:
    expected_port = load_server_config(_project_root() / "configs" / "server.toml").control_port
    if args.control_port != expected_port:
        print(f"control port must match the configured loopback control port {expected_port}", file=sys.stderr)
        return 2
    session_id = args.session_id or uuid.uuid4().hex
    if args.task_command == "register":
        seed = args.seed if args.seed is not None else secrets.randbelow(2**31)
        payload = json.dumps({"session_id": session_id, "seed": seed}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{args.control_port}/sessions", data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
    else:
        request = urllib.request.Request(
            f"http://127.0.0.1:{args.control_port}/sessions/{session_id}/outcome"
        )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            print(json.dumps(json.load(response), indent=2))
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        print(f"task control request failed: {exc}", file=sys.stderr)
        return 2
    return 0


def _capture(args: argparse.Namespace) -> int:
    from beyond_handshake.capture import (capture_loopback, discover_capture_tools,
        join_and_aggregate, tshark_extract)

    if args.capture_command == "doctor":
        result = discover_capture_tools()
        print(json.dumps(result, indent=2))
        return 0 if (result.get("loopback_capture_supported")
                     and result.get("field_inventory_ok")) else 2
    if args.capture_command == "extract":
        result = tshark_extract(args.pcap, args.output)
        print(json.dumps(result, indent=2))
        return 0
    if args.capture_command == "join":
        result = join_and_aggregate(args.packets, args.events, args.output)
        print(json.dumps(result, indent=2))
        return 0
    expected_port = load_server_config(_project_root() / "configs" / "server.toml").listen_port
    if args.port != expected_port:
        print(f"capture is restricted to the configured local task port {expected_port}", file=sys.stderr)
        return 2
    try:
        result = capture_loopback(args.port, args.seconds, args.output_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"capture failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "captured" else 2


def _dataset(args: argparse.Namespace) -> int:
    from beyond_handshake.dataset import build_dataset, evaluate_naive_bayes

    if args.dataset_command == "build":
        result = build_dataset(args.features, args.labels, args.output_dir)
    else:
        result = evaluate_naive_bayes(args.dataset_dir, args.output)
    print(json.dumps(result, indent=2))
    return 0


def _client(args: argparse.Namespace) -> int:
    from beyond_handshake.client import (available_impersonation_profiles, run_curl_cffi,
                                         run_stdlib, write_attempt)

    if args.client_command == "profiles":
        try:
            profiles = available_impersonation_profiles()
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(json.dumps({"adapter": "curl_cffi", "profiles": profiles}, indent=2))
        return 0
    if args.client_command == "manual":
        print(json.dumps({"session_id": args.session_id,
                          "task_url": f"https://localhost:{args.port}/s/{args.session_id}/start",
                          "certificate_authority": str(args.ca_file),
                          "next_command": f"./scripts/bh task outcome {args.session_id}"}, indent=2))
        return 0
    config = load_server_config(_project_root() / "configs" / "server.toml")
    origin = urllib.parse.urlsplit(args.origin)
    if origin.port != config.listen_port or args.control_port != config.control_port:
        print("client ports must match the configured local task and control ports", file=sys.stderr)
        return 2
    try:
        if args.adapter == "stdlib":
            result = run_stdlib(args.session_id, args.origin, args.ca_file,
                                args.timeout, args.control_port)
        else:
            if not args.profile:
                print("--profile is required for the curl-cffi adapter", file=sys.stderr)
                return 2
            result = run_curl_cffi(args.session_id, args.origin, args.ca_file,
                                   args.timeout, args.profile, args.control_port)
        path = write_attempt(result, args.output_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"client setup failed: {exc}", file=sys.stderr)
        return 2
    output = {**asdict(result), "attempt_record": str(path)}
    print(json.dumps(output, indent=2))
    return 0 if result.task_success else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bh",
        description="Local controlled browser-stack measurement prototype (Phases 0–7 pilot components).",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="inspect local runtime prerequisites")
    doctor.add_argument("--output", type=Path, help="write the environment report as JSON")

    cert = commands.add_parser("cert", help="manage local development certificates")
    cert_commands = cert.add_subparsers(dest="cert_command", required=True)
    create = cert_commands.add_parser("create", help="create a local CA and HTTPS server certificate")
    create.add_argument("--hostname", action="append", required=True, help="DNS name or IP SAN; repeatable")
    create.add_argument("--out", type=Path, default=Path("local/tls"))

    server = commands.add_parser("server", help="run the localhost HTTPS/HTTP/1.1 and h2 prototype")
    server.add_argument("--config", type=Path, default=Path("configs/server.toml"))
    task = commands.add_parser("task", help="register a local synthetic task or inspect its oracle outcome")
    task_commands = task.add_subparsers(dest="task_command", required=True)
    register = task_commands.add_parser("register", help="register a local catalog task")
    register.add_argument("--session-id")
    register.add_argument("--seed", type=int)
    register.add_argument("--control-port", type=int, default=8444)
    outcome = task_commands.add_parser("outcome", help="read a registered task outcome")
    outcome.add_argument("session_id")
    outcome.add_argument("--control-port", type=int, default=8444)
    capture = commands.add_parser("capture", help="inspect tools or capture loopback task traffic")
    capture_commands = capture.add_subparsers(dest="capture_command", required=True)
    capture_commands.add_parser("doctor", help="inspect dumpcap and TShark availability")
    extract = capture_commands.add_parser("extract", help="extract versioned packet fields with TShark")
    extract.add_argument("--pcap", type=Path, required=True)
    extract.add_argument("--output", type=Path, required=True)
    join = capture_commands.add_parser("join", help="join extracted flows to server events")
    join.add_argument("--packets", type=Path, required=True)
    join.add_argument("--events", type=Path, required=True)
    join.add_argument("--output", type=Path, required=True)
    capture_run = capture_commands.add_parser("loopback", help="capture only TCP traffic to the local task port")
    capture_run.add_argument("--port", type=int, default=8443)
    capture_run.add_argument("--seconds", type=float, required=True)
    capture_run.add_argument("--output-dir", type=Path, default=Path("local/captures"))
    client = commands.add_parser("client", help="run a local task with a declared client adapter")
    client_commands = client.add_subparsers(dest="client_command", required=True)
    client_commands.add_parser("profiles", help="list profiles exposed by the installed curl_cffi API")
    manual = client_commands.add_parser("manual", help="print the human task URL and oracle command")
    manual.add_argument("session_id")
    manual.add_argument("--port", type=int, default=8443)
    manual.add_argument("--ca-file", type=Path, default=Path("local/tls/ca.pem"))
    run_client = client_commands.add_parser("run", help="run a task through a declared trusted adapter")
    run_client.add_argument("session_id")
    run_client.add_argument("--adapter", choices=["stdlib", "curl-cffi"], default="curl-cffi")
    run_client.add_argument("--profile")
    run_client.add_argument("--origin", default="https://localhost:8443")
    run_client.add_argument("--ca-file", type=Path, default=Path("local/tls/ca.pem"))
    run_client.add_argument("--control-port", type=int, default=8444)
    run_client.add_argument("--timeout", type=float, default=120)
    run_client.add_argument("--output-dir", type=Path, default=Path("data/raw/client-attempts"))
    dataset = commands.add_parser("dataset", help="build separated feature/label tables and evaluate baseline")
    dataset_commands = dataset.add_subparsers(dest="dataset_command", required=True)
    dataset_build = dataset_commands.add_parser("build", help="aggregate joined observations using a label registry")
    dataset_build.add_argument("--features", type=Path, required=True)
    dataset_build.add_argument("--labels", type=Path, required=True)
    dataset_build.add_argument("--output-dir", type=Path, required=True)
    evaluate = dataset_commands.add_parser("evaluate", help="fit train-only baseline and score held-out families")
    evaluate.add_argument("--dataset-dir", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
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
        if args.command == "task":
            return _task(args)
        if args.command == "capture":
            return _capture(args)
        if args.command == "client":
            return _client(args)
        if args.command == "dataset":
            return _dataset(args)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
