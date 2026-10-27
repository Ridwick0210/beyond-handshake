"""Small independent wire decoder for auditing selected TShark extraction fields.

This intentionally supports only the local pilot's Ethernet/IPv4/IPv6, TCP, and
single-segment TLS ClientHello packets. Unsupported packets are reported, not
silently treated as verified evidence.
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
from pathlib import Path


def _frames(path: Path):
    data = path.read_bytes()
    offset = 0
    endian = "<"
    interfaces: list[int] = []
    while offset + 12 <= len(data):
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            marker = data[offset + 8:offset + 12]
            if marker == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif marker == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("invalid PCAPNG byte-order marker")
            interfaces = []
        block_type, length = struct.unpack_from(endian + "II", data, offset)
        if length < 12 or offset + length > len(data):
            raise ValueError("truncated PCAPNG block")
        if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            raise ValueError("PCAPNG block length mismatch")
        body = data[offset + 8:offset + length - 4]
        if block_type == 1:
            if len(body) < 8:
                raise ValueError("truncated PCAPNG interface block")
            interfaces.append(struct.unpack_from(endian + "H", body)[0])
        elif block_type == 6:
            if len(body) < 20:
                raise ValueError("truncated PCAPNG packet block")
            interface_id, _, _, size, _ = struct.unpack_from(endian + "IIIII", body)
            if interface_id >= len(interfaces) or len(body) < 20 + size:
                raise ValueError("invalid PCAPNG packet interface or length")
            yield interfaces[interface_id], body[20:20 + size]
        offset += length
    if offset != len(data):
        raise ValueError("trailing incomplete PCAPNG block")


def _tcp(frame: bytes, linktype: int):
    if linktype != 1 or len(frame) < 14:
        return None
    position = 12
    ethertype = int.from_bytes(frame[position:position + 2], "big")
    position = 14
    while ethertype in (0x8100, 0x88a8):
        if len(frame) < position + 4:
            return None
        ethertype = int.from_bytes(frame[position + 2:position + 4], "big")
        position += 4
    if ethertype == 0x0800:
        if len(frame) < position + 20:
            return None
        header_length = (frame[position] & 0x0f) * 4
        if header_length < 20 or frame[position + 9] != 6:
            return None
        if int.from_bytes(frame[position + 6:position + 8], "big") & 0x1fff:
            return None
        family = 4
        position += header_length
    elif ethertype == 0x86dd:
        if len(frame) < position + 40 or frame[position + 6] != 6:
            return None
        family = 6
        position += 40
    else:
        return None
    if len(frame) < position + 20:
        return None
    source, destination = struct.unpack_from("!HH", frame, position)
    header_length = (frame[position + 12] >> 4) * 4
    if header_length < 20 or len(frame) < position + header_length:
        return None
    flags = frame[position + 13]
    options = frame[position + 20:position + header_length]
    payload = frame[position + header_length:]
    return family, source, destination, flags, options, payload


def _client_hello(payload: bytes):
    if len(payload) < 9 or payload[0] != 22 or payload[5] != 1:
        return None
    record_length = int.from_bytes(payload[3:5], "big")
    handshake_length = int.from_bytes(payload[6:9], "big")
    if len(payload) < 5 + record_length or 4 + handshake_length > record_length:
        return "incomplete"
    body = payload[9:9 + handshake_length]
    if len(body) < 35:
        return "incomplete"
    position = 34  # legacy_version + random
    session_length = body[position]
    position += 1 + session_length
    if position + 2 > len(body):
        return "incomplete"
    cipher_length = int.from_bytes(body[position:position + 2], "big")
    position += 2
    if cipher_length % 2 or position + cipher_length + 1 > len(body):
        return "incomplete"
    ciphers = [f"0x{int.from_bytes(body[index:index + 2], 'big'):04x}"
               for index in range(position, position + cipher_length, 2)]
    position += cipher_length
    compression_length = body[position]
    position += 1 + compression_length
    if position + 2 > len(body):
        return "incomplete"
    extension_length = int.from_bytes(body[position:position + 2], "big")
    position += 2
    end = position + extension_length
    if end > len(body):
        return "incomplete"
    extensions = []
    while position < end:
        if position + 4 > end:
            return "incomplete"
        kind, size = struct.unpack_from("!HH", body, position)
        position += 4 + size
        if position > end:
            return "incomplete"
        extensions.append(str(kind))
    return ciphers, extensions


def audit_capture(pcap: Path, observations: Path) -> dict:
    syns = {}
    hellos = {}
    incomplete = 0
    for linktype, frame in _frames(pcap):
        packet = _tcp(frame, linktype)
        if packet is None:
            continue
        family, source, destination, flags, options, payload = packet
        if destination != 8443:
            continue
        key = (family, source)
        if flags & 0x02 and not flags & 0x10:
            syns.setdefault(key, options.hex())
        parsed = _client_hello(payload)
        if parsed == "incomplete":
            incomplete += 1
        elif parsed is not None:
            hellos.setdefault(key, parsed)
    compared_syns = 0
    compared_hellos = 0
    mismatches = []
    with observations.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            if row["tcp.dstport"] != "8443":
                continue
            key = (6 if row["ipv6.src"] else 4, int(row["tcp.srcport"]))
            if row["tcp.flags.syn"] == "True" and row["tcp.flags.ack"] == "False":
                compared_syns += 1
                if syns.get(key) != row["tcp.options"].lower():
                    mismatches.append(f"SYN options {key}")
            if "1" in row["tls.handshake.type"].split(","):
                compared_hellos += 1
                expected = (row["tls.handshake.ciphersuite"].lower().split(","),
                            row["tls.handshake.extension.type"].split(","))
                if hellos.get(key) != expected:
                    mismatches.append(f"ClientHello cipher/extension order {key}")
    return {"pcap": str(pcap), "tshark_observations": str(observations),
            "compared_syns": compared_syns, "compared_client_hellos": compared_hellos,
            "single_segment_incomplete_hellos": incomplete, "mismatches": mismatches,
            "scope": "Ethernet IPv4/IPv6 without IP extension headers; single-segment TLS ClientHello"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collection-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    manifest = json.loads(arguments.collection_manifest.read_text(encoding="utf-8"))
    results = [audit_capture(Path(item["pcap"]), Path(item["output"]))
               for item in manifest["packet_extractions"]]
    report = {"schema_version": "independent-packet-audit/1", "captures": len(results),
              "compared_syns": sum(item["compared_syns"] for item in results),
              "compared_client_hellos": sum(item["compared_client_hellos"] for item in results),
              "unaudited_captures": [item["pcap"] for item in results if not item["compared_syns"]
                                     or not item["compared_client_hellos"]],
              "single_segment_incomplete_hellos": sum(
                  item["single_segment_incomplete_hellos"] for item in results),
              "mismatches": [error for item in results for error in item["mismatches"]],
              "results": results}
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))
    return 1 if report["mismatches"] or report["unaudited_captures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
