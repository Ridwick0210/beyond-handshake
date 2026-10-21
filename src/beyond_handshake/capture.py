"""Explicit loopback-only dumpcap supervision and TShark capability inventory."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import signal
import subprocess
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


def parse_tshark_field_inventory(text: str) -> list[dict[str, str]]:
    """Parse the stable tab-delimited columns from `tshark -G fields`."""
    fields = []
    for line in text.splitlines():
        columns = line.split("\t")
        if len(columns) >= 4 and columns[0] == "F":
            fields.append({"display_name": columns[1], "field_name": columns[2],
                           "field_type": columns[3]})
    return fields


def discover_capture_tools() -> dict:
    tshark = shutil.which("tshark")
    dumpcap = shutil.which("dumpcap")
    tcpdump = shutil.which("tcpdump")
    result = {"tshark": tshark, "dumpcap": dumpcap, "tcpdump": tcpdump,
              "loopback_capture_supported": False,
              "field_inventory_count": 0, "missing": []}
    if dumpcap:
        try:
            interfaces = subprocess.run([dumpcap, "-D"], capture_output=True, text=True, timeout=10)
        except OSError as exc:
            result["dumpcap_error"] = f"{type(exc).__name__}: {exc}"
        else:
            result["interfaces_exit_code"] = interfaces.returncode
            result["interfaces"] = interfaces.stdout.splitlines()
            result["loopback_capture_supported"] = interfaces.returncode == 0 and any(
                "loopback" in line.lower() or re.search(r"(^|[ .(])lo([ .)]|$)", line) is not None
                for line in interfaces.stdout.splitlines()
            )
            if interfaces.returncode:
                result["dumpcap_error"] = interfaces.stderr.strip()[-500:]
    if not result["loopback_capture_supported"] and tcpdump:
        try:
            interfaces = subprocess.run([tcpdump, "-D"], capture_output=True, text=True, timeout=10)
        except OSError as exc:
            result["tcpdump_error"] = f"{type(exc).__name__}: {exc}"
        else:
            result["tcpdump_interfaces_exit_code"] = interfaces.returncode
            result["tcpdump_interfaces"] = interfaces.stdout.splitlines()
            result["loopback_capture_supported"] = interfaces.returncode == 0 and any(
                re.search(r"(^|[ .(])lo([ .)]|$)", line) is not None for line in interfaces.stdout.splitlines())
            if result["loopback_capture_supported"]:
                result["capture_backend"] = "tcpdump"
            elif interfaces.returncode:
                result["tcpdump_error"] = interfaces.stderr.strip()[-500:]
    if not dumpcap and not tcpdump:
        result["missing"].append("dumpcap and tcpdump are not installed")
    elif not result["loopback_capture_supported"]:
        result["missing"].append("no capture tool can enumerate loopback with current permissions")
    if not tshark:
        result["missing"].append("tshark is not installed; no packet extraction is available")
    else:
        version = subprocess.run([tshark, "--version"], capture_output=True, text=True, timeout=10)
        fields = subprocess.run([tshark, "-G", "fields"], capture_output=True, text=True, timeout=30)
        result["tshark_version"] = version.stdout.splitlines()[0] if version.stdout else "unknown"
        inventory = parse_tshark_field_inventory(fields.stdout) if fields.returncode == 0 else []
        result["field_inventory_count"] = len(inventory)
        result["field_inventory_ok"] = fields.returncode == 0 and bool(inventory)
        if fields.returncode:
            result["missing"].append("tshark -G fields failed; field names have not been verified")
    return result


def capture_loopback(port: int, seconds: float, output_dir: Path) -> dict:
    """Capture only loopback TCP traffic for the configured local task port."""
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not 0 < seconds <= 3600:
        raise ValueError("seconds must be in (0, 3600]")
    tools = discover_capture_tools()
    backend = tools.get("capture_backend")
    binary = shutil.which(backend or "dumpcap")
    if not binary or not tools.get("loopback_capture_supported"):
        raise RuntimeError("no loopback capture backend is available with current permissions")
    # Disallow collecting arbitrary interfaces through this initial local pilot command.
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    capture_path = output_dir / f"loopback-{stamp}-{uuid4().hex[:6]}.pcapng"
    stderr_path = output_dir / f"loopback-{stamp}-{uuid4().hex[:6]}.capture.stderr.log"
    stderr_file = stderr_path.open("wb")
    if backend == "tcpdump":
        args = [binary, "-i", "lo", "-n", "-s", "0", "-U", "-w", str(capture_path),
                f"tcp port {port}"]
    else:
        args = [binary, "-i", "lo", "-f", f"tcp port {port}", "-w", str(capture_path), "-q"]
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=stderr_file, close_fds=True)
    try:
        time.sleep(0.4)
        if process.poll() is not None:
            raise RuntimeError(f"dumpcap exited early ({process.returncode}); inspect {stderr_path}")
        time.sleep(seconds)
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=3)
    except BaseException:
        if process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=3)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        stderr_file.close()
    digest = None
    if capture_path.is_file():
        hasher = hashlib.sha256()
        with capture_path.open("rb") as capture_file:
            for chunk in iter(lambda: capture_file.read(1024 * 1024), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
    return {"capture_path": str(capture_path), "stderr_path": str(stderr_path),
            "sha256": digest, "exit_code": process.returncode,
            "interface": "lo", "capture_filter": f"tcp port {port}", "capture_backend": backend or "dumpcap",
            "duration_seconds": seconds, "status": "captured" if digest else "failed"}


PACKET_FIELDS = (
    "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack", "tcp.hdr_len",
    "tcp.window_size_value", "tcp.options.mss_val", "tcp.options.wscale.shift",
    "tcp.options.sack_perm", "tcp.options.timestamp.tsval", "tls.handshake.type",
    "tcp.options.kind",
    "tls.handshake.version", "tls.record.version", "tls.handshake.ciphersuite",
    "tls.handshake.extension.type", "tls.handshake.extensions_alpn_str",
)


def tshark_extract(pcap: Path, output: Path) -> dict:
    """Extract a versioned packet table using only fields supported by this TShark build."""
    tshark = shutil.which("tshark")
    if not tshark:
        raise RuntimeError("tshark is unavailable; install Wireshark CLI before extraction")
    pcap = pcap.expanduser().resolve()
    if not pcap.is_file():
        raise FileNotFoundError(pcap)
    version = subprocess.run([tshark, "--version"], capture_output=True, text=True, timeout=15)
    inventory_result = subprocess.run([tshark, "-G", "fields"], capture_output=True,
                                      text=True, timeout=60)
    if version.returncode or inventory_result.returncode:
        raise RuntimeError("TShark version or field inventory query failed")
    available = {item["field_name"] for item in parse_tshark_field_inventory(inventory_result.stdout)}
    fields = [field for field in PACKET_FIELDS if field in available]
    if "tcp.stream" not in fields or "frame.time_epoch" not in fields:
        raise RuntimeError("TShark lacks required frame.time_epoch or tcp.stream fields")
    command = [tshark, "-n", "-r", str(pcap), "-Y", "tcp", "-T", "fields", "-E", "header=y",
               "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=,"]
    for field in fields:
        command.extend(["-e", field])
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.PIPE, text=True, timeout=300)
    if result.returncode:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"TShark packet extraction failed: {result.stderr[-2000:]}")
    with temporary.open("r", newline="", encoding="utf-8") as source, output.open(
            "w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=["schema_version", *fields], delimiter="\t")
        writer.writeheader()
        for row in csv.DictReader(source, delimiter="\t"):
            writer.writerow({"schema_version": "packet-observations/1", **row})
    temporary.unlink()
    with output.open(encoding="utf-8") as stream:
        packet_count = max(0, sum(1 for _ in stream) - 1)
    manifest = {"schema_version": "packet-extraction/1", "pcap": str(pcap),
                "pcap_sha256": _sha256(pcap), "output": str(output), "output_sha256": _sha256(output),
                "tshark_version": version.stdout.splitlines()[0], "fields": fields,
                "packets_exported": packet_count, "command": command,
                "limitations": ["HTTP/2 after TLS is encrypted; use endpoint frame events for H2 features"]}
    output.with_suffix(output.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def join_and_aggregate(packets_path: Path, events_path: Path, output_path: Path) -> dict:
    """Join packet TCP streams to server connections by socket tuple and time; ambiguous joins fail closed."""
    flows: dict[str, dict] = {}
    with packets_path.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            sid = row.get("tcp.stream", "")
            if not sid:
                continue
            flow = flows.setdefault(sid, {"times": [], "rows": [], "client": None, "server": None})
            try:
                flow["times"].append(float(row["frame.time_epoch"]))
            except (TypeError, ValueError):
                pass
            src = row.get("ip.src") or row.get("ipv6.src")
            dst = row.get("ip.dst") or row.get("ipv6.dst")
            sport, dport = row.get("tcp.srcport"), row.get("tcp.dstport")
            if src and dst and sport and dport:
                flow["rows"].append(row)
                # The server endpoint is the configured task port; direction is discovered later.
                flow.setdefault("endpoints", set()).update({(src, sport), (dst, dport)})
    events = []
    with events_path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                events.append(json.loads(line))
    opens = [e for e in events if e.get("event_type") == "connection.open"]
    by_server = defaultdict(list)
    for stream_id, flow in flows.items():
        for endpoint in flow.get("endpoints", set()):
            by_server[endpoint].append((stream_id, flow))
    joins, unmatched, ambiguous = [], [], []
    for event in opens:
        p = event.get("payload", {})
        tuple_key = (str(p.get("peer_ip")), str(p.get("peer_port")))
        candidates = by_server.get(tuple_key, [])
        start = min(candidates[0][1]["times"], default=0) if len(candidates) == 1 else 0
        # Since connection.open follows TLS completion, require it to land inside a candidate flow interval.
        stamp = event.get("ts_wall_ns", 0) / 1e9
        candidates = [(sid, flow) for sid, flow in candidates if flow["times"] and
                      min(flow["times"]) - 2 <= stamp <= max(flow["times"]) + 2]
        if len(candidates) != 1:
            (ambiguous if len(candidates) > 1 else unmatched).append(event.get("connection_id"))
            continue
        sid, flow = candidates[0]
        # Protocol-feature vector uses observations only. Identifiers and labels remain sidecar metadata.
        connection_sessions = {e.get("session_id") for e in events
                               if e.get("connection_id") == event.get("connection_id") and e.get("session_id")}
        if len(connection_sessions) > 1:
            ambiguous.append(event.get("connection_id"))
            continue
        rows = flow["rows"]
        peer_port = str(p.get("peer_port"))
        tcp = [r for r in rows if r.get("tcp.flags.syn") == "1"
               and r.get("tcp.srcport") == peer_port and r.get("tcp.flags.ack") != "1"]
        client_hello = [r for r in rows if "1" in r.get("tls.handshake.type", "").split(",")]
        feature = {
            "feature_schema": "cross-layer/1",
            "tcp_packet_count": len(rows),
            "tcp_client_to_server_packets": sum(1 for r in rows if r.get("tcp.srcport") == peer_port),
            "tcp_flow_duration_seconds": max(flow["times"]) - min(flow["times"]) if flow["times"] else None,
            "tcp_initial_window": _first_numeric(tcp, "tcp.window_size_value"),
            "tcp_mss": _first_numeric(tcp, "tcp.options.mss_val"),
            "tcp_window_scale": _first_numeric(tcp, "tcp.options.wscale.shift"),
            "tcp_syn_options_order": _first_sequence(tcp, "tcp.options.kind"),
            "tls_handshake_types": _distinct_values(rows, "tls.handshake.type"),
            "tls_offered_versions": _distinct_values(client_hello, "tls.handshake.version"),
            "tls_cipher_suites_order": _first_sequence(client_hello, "tls.handshake.ciphersuite"),
            "tls_extension_types_order": _first_sequence(client_hello, "tls.handshake.extension.type"),
            "tls_alpn_offers": _distinct_values(client_hello, "tls.handshake.extensions_alpn_str"),
            "endpoint_tls_version": p.get("tls_version"),
            "endpoint_alpn": p.get("tls_alpn"),
            "h2_inbound_settings_order": _settings_values(events, event.get("connection_id")),
            "h2_inbound_frame_types": _inbound_frame_types(events, event.get("connection_id")),
            "h2_header_names_order": _header_values(events, event.get("connection_id")),
            "h2_request_count": _h2_request_count(events, event.get("connection_id")),
        }
        joins.append({"connection_id": event.get("connection_id"), "tcp_stream": sid,
                      "session_ids": sorted({e.get("session_id") for e in events
                          if e.get("connection_id") == event.get("connection_id") and e.get("session_id")}),
                      "features": feature})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in joins), encoding="utf-8")
    report = {"schema_version": "join-quality/1", "packet_flow_count": len(flows),
              "server_connection_count": len(opens), "joined_count": len(joins),
              "unmatched_connection_ids": unmatched, "ambiguous_connection_ids": ambiguous,
              "unjoined_flow_count": max(0, len(flows) - len(joins)), "features_path": str(output_path),
              "packets_sha256": _sha256(packets_path), "events_sha256": _sha256(events_path),
              "features_sha256": _sha256(output_path),
              "policy": "only unique tuple/time matches are retained; inspect and exclude all unmatched joins"}
    output_path.with_suffix(".join-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def _first_numeric(rows: list[dict], field: str):
    for row in rows:
        for value in row.get(field, "").split(","):
            try:
                return int(value)
            except ValueError:
                continue
    return None


def _first_value(rows: list[dict], field: str):
    return next((r[field] for r in rows if r.get(field)), None)


def _distinct_values(rows: list[dict], field: str) -> list[str]:
    return list(dict.fromkeys(v for r in rows for v in r.get(field, "").split(",") if v))


def _first_sequence(rows: list[dict], field: str) -> list[str]:
    return next((r[field].split(",") for r in rows if r.get(field)), [])


def _event_values(events: list[dict], conn_id: str, event_type: str, key: str) -> list:
    return [e.get("payload", {}).get(key) for e in events
            if e.get("connection_id") == conn_id and e.get("event_type") == event_type
            and e.get("payload", {}).get(key) is not None]


def _settings_values(events: list[dict], conn_id: str) -> list:
    return [e.get("payload", {}).get("entries", []) for e in events
            if e.get("connection_id") == conn_id and e.get("event_type") == "http2.settings"
            and e.get("payload", {}).get("direction") == "in"
            and not e.get("payload", {}).get("ack")]


def _header_values(events: list[dict], conn_id: str) -> list:
    return [[item[0] for item in e.get("payload", {}).get("headers_ordered", [])]
            for e in events if e.get("connection_id") == conn_id
            and e.get("event_type") == "http.request_headers"
            and e.get("payload", {}).get("protocol") == "h2"]


def _h2_request_count(events: list[dict], conn_id: str) -> int:
    return sum(e.get("connection_id") == conn_id and e.get("event_type") == "http.request_headers"
               and e.get("payload", {}).get("protocol") == "h2" for e in events)


def _inbound_frame_types(events: list[dict], conn_id: str) -> list:
    return [e.get("payload", {}).get("frame_type") for e in events
            if e.get("connection_id") == conn_id and e.get("event_type") == "http2.frame"
            and e.get("payload", {}).get("direction") == "in"]


def features_from_server_events(events_path: Path, output_path: Path) -> dict:
    """Build explicitly event-only features when packet capture is unavailable."""
    events = []
    with events_path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                events.append(json.loads(line))
    opens = [event for event in events if event.get("event_type") == "connection.open"]
    rows = []
    for opened in opens:
        connection_id = opened.get("connection_id")
        payload = opened.get("payload", {})
        session_ids = sorted({event.get("session_id") for event in events
                              if event.get("connection_id") == connection_id and event.get("session_id")})
        if len(session_ids) > 1:
            continue
        rows.append({"connection_id": connection_id, "session_ids": session_ids,
                     "feature_source": "server-events-only", "features": {
                         "feature_schema": "cross-layer/1",
                         "endpoint_tls_version": payload.get("tls_version"),
                         "endpoint_alpn": payload.get("tls_alpn"),
                         "h2_inbound_settings_order": _settings_values(events, connection_id),
                         "h2_inbound_frame_types": _inbound_frame_types(events, connection_id),
                         "h2_header_names_order": _header_values(events, connection_id),
                         "h2_request_count": _h2_request_count(events, connection_id)}})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    return {"schema_version": "event-features/1", "feature_source": "server-events-only",
            "connection_count": len(rows), "matched_session_connection_count": sum(bool(r["session_ids"]) for r in rows),
            "events_sha256": _sha256(events_path), "features_sha256": _sha256(output_path),
            "features_path": str(output_path),
            "limitations": ["no TCP or packet-derived ClientHello features", "HTTP/2 features only when endpoint observer remained healthy"]}
