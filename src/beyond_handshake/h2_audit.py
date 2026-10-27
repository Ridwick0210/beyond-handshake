"""Compare endpoint HTTP/2 observations with independent decrypted TShark PDML.

Only local lab captures with an explicit TLS key log are accepted. The report
contains counts and mismatches, never key material or header values.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path


def _field(node: ET.Element, name: str) -> ET.Element | None:
    return next((item for item in node.iter("field") if item.get("name") == name), None)


def _parse_pdml(document: bytes) -> tuple[dict[int, list[list[tuple[int, int]]]],
                                         dict[tuple[int, int], list[list[str]]]]:
    settings: dict[int, list[list[tuple[int, int]]]] = defaultdict(list)
    headers: dict[tuple[int, int], list[list[str]]] = defaultdict(list)
    root = ET.fromstring(document)
    for packet in root.findall("packet"):
        tcp = packet.find("./proto[@name='tcp']")
        if tcp is None:
            continue
        source = _field(tcp, "tcp.srcport")
        destination = _field(tcp, "tcp.dstport")
        if source is None or destination is None or destination.get("show") != "8443":
            continue
        port = int(source.get("show", "0"))
        for proto in packet.findall("./proto[@name='http2']"):
            for frame in proto.findall("./field[@name='http2.stream']"):
                frame_type = _field(frame, "http2.type")
                stream = _field(frame, "http2.streamid")
                if frame_type is None or stream is None:
                    continue
                if frame_type.get("show") == "4":
                    entries = []
                    for entry in frame.findall("./field[@name='http2.settings']"):
                        identifier = _field(entry, "http2.settings.id")
                        value = next((item for item in entry.iter("field")
                                      if item is not entry and item is not identifier
                                      and item.get("value") and len(item.get("value", "")) == 8), None)
                        if identifier is not None and value is not None:
                            entries.append((int(identifier.get("show", "0")),
                                            int(value.get("value", "0"), 16)))
                    if entries:
                        settings[port].append(entries)
                elif frame_type.get("show") == "1":
                    names = [item.get("show", "") for item in frame.iter("field")
                             if item.get("name") == "http2.header.name"]
                    if names:
                        headers[(port, int(stream.get("show", "0")))].append(names)
    return settings, headers


def audit_h2(collection_manifest: Path, keylog: Path, output: Path) -> dict:
    if not keylog.is_file():
        raise FileNotFoundError("local TLS key log is missing")
    manifest = json.loads(collection_manifest.read_text(encoding="utf-8"))
    events = [json.loads(line) for line in Path(manifest["event_file"]).read_text(
        encoding="utf-8").splitlines() if line.strip()]
    peer_port = {event["connection_id"]: int(event["payload"]["peer_port"])
                 for event in events if event["event_type"] == "connection.open"}
    if len(set(peer_port.values())) != len(peer_port):
        raise ValueError("client source port was reused within the audit run; port-only join is ambiguous")
    wire_settings: dict[int, list[list[tuple[int, int]]]] = defaultdict(list)
    wire_headers: dict[tuple[int, int], list[list[str]]] = defaultdict(list)
    for extraction in manifest["packet_extractions"]:
        command = ["tshark", "-r", extraction["pcap"], "-o", f"tls.keylog_file:{keylog}",
                   "-Y", "http2 && tcp.dstport==8443", "-T", "pdml"]
        result = subprocess.run(command, capture_output=True, check=True, timeout=60)
        settings, headers = _parse_pdml(result.stdout)
        for port, entries in settings.items():
            wire_settings[port].extend(entries)
        for key, entries in headers.items():
            wire_headers[key].extend(entries)
    expected_settings: dict[int, list[list[tuple[int, int]]]] = defaultdict(list)
    expected_headers: dict[tuple[int, int], list[list[str]]] = defaultdict(list)
    for event in events:
        port = peer_port.get(event.get("connection_id"))
        if port is None:
            continue
        if event["event_type"] == "http2.settings" and event["payload"]["direction"] == "in":
            if not event["payload"]["ack"]:
                expected_settings[port].append([(int(entry["setting_id"]), int(entry["value"]))
                                                for entry in event["payload"]["entries"]])
        elif event["event_type"] == "http.request_headers" and event["payload"]["protocol"] == "h2":
            expected_headers[(port, int(event["stream_id"]))].append(
                [name for name, _ in event["payload"]["headers_ordered"]])
    mismatches = []
    for port in sorted(set(expected_settings) | set(wire_settings)):
        if expected_settings[port] != wire_settings[port]:
            mismatches.append(f"inbound SETTINGS mismatch on client port {port}")
    for key in sorted(set(expected_headers) | set(wire_headers)):
        if expected_headers[key] != wire_headers[key]:
            mismatches.append(f"request header order mismatch on client port/stream {key}")
    report = {"schema_version": "independent-h2-audit/1",
              "captures": len(manifest["packet_extractions"]),
              "compared_settings_frames": sum(map(len, expected_settings.values())),
              "compared_request_header_lists": sum(map(len, expected_headers.values())),
              "wire_settings_frames": sum(map(len, wire_settings.values())),
              "wire_request_header_lists": sum(map(len, wire_headers.values())),
              "mismatches": mismatches,
              "scope": "lab TLS decryption and Wireshark PDML; ordered inbound SETTINGS and request header names"}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collection-manifest", type=Path, required=True)
    parser.add_argument("--keylog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit_h2(args.collection_manifest, args.keylog, args.output)
    print(json.dumps(report, indent=2))
    return 1 if report["mismatches"] or not report["compared_settings_frames"] or not report[
        "compared_request_header_lists"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
