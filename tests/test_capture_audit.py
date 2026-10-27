from __future__ import annotations

import csv
import struct
import tempfile
import unittest
from pathlib import Path

from beyond_handshake.capture_audit import _client_hello, _frames, audit_capture


def _block(kind: int, body: bytes) -> bytes:
    padded = body + bytes((-len(body)) % 4)
    length = len(padded) + 12
    return struct.pack("<II", kind, length) + padded + struct.pack("<I", length)


def _frame(flags: int, options: bytes = b"", payload: bytes = b"") -> bytes:
    ethernet = bytes(12) + b"\x08\x00"
    tcp_header = bytearray(20 + len(options))
    struct.pack_into("!HH", tcp_header, 0, 55555, 8443)
    tcp_header[12] = (len(tcp_header) // 4) << 4
    tcp_header[13] = flags
    tcp_header[20:] = options
    ipv4 = bytearray(20)
    ipv4[0] = 0x45
    struct.pack_into("!H", ipv4, 2, 20 + len(tcp_header) + len(payload))
    ipv4[9] = 6
    ipv4[12:20] = b"\x7f\x00\x00\x01" * 2
    return ethernet + ipv4 + tcp_header + payload


def _hello() -> bytes:
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x04\x13\x01\x13\x02"
            + b"\x01\x00" + b"\x00\x04\x00\x00\x00\x00")
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class CaptureAuditTests(unittest.TestCase):
    def test_client_hello_extracts_order_and_rejects_incomplete_record(self):
        hello = _hello()
        self.assertEqual(_client_hello(hello), (["0x1301", "0x1302"], ["0"]))
        self.assertEqual(_client_hello(hello[:-1]), "incomplete")

    def test_independent_decoder_compares_and_catches_changed_tshark_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pcap = root / "sample.pcapng"
            section = _block(0x0a0d0d0a, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
            interface = _block(1, struct.pack("<HHI", 1, 0, 65535))
            packets = []
            for frame in (_frame(2, b"\x02\x04\x05\xb4"), _frame(24, payload=_hello())):
                packets.append(_block(6, struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame))
                                      + frame))
            pcap.write_bytes(section + interface + b"".join(packets))
            self.assertEqual(len(list(_frames(pcap))), 2)
            observations = root / "observations.tsv"
            fields = ["tcp.dstport", "tcp.srcport", "ipv6.src", "tcp.flags.syn",
                      "tcp.flags.ack", "tcp.options", "tls.handshake.type",
                      "tls.handshake.ciphersuite", "tls.handshake.extension.type"]
            with observations.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t")
                writer.writeheader()
                writer.writerow({"tcp.dstport": "8443", "tcp.srcport": "55555",
                                 "tcp.flags.syn": "True", "tcp.flags.ack": "False",
                                 "tcp.options": "020405b4"})
                writer.writerow({"tcp.dstport": "8443", "tcp.srcport": "55555",
                                 "tls.handshake.type": "1", "tls.handshake.ciphersuite": "0x1301,0x1302",
                                 "tls.handshake.extension.type": "0"})
            result = audit_capture(pcap, observations)
            self.assertEqual((result["compared_syns"], result["compared_client_hellos"]), (1, 1))
            self.assertEqual(result["mismatches"], [])
            observations.write_text(observations.read_text().replace("0x1302", "0x1303"))
            self.assertIn("ClientHello", audit_capture(pcap, observations)["mismatches"][0])


if __name__ == "__main__":
    unittest.main()
