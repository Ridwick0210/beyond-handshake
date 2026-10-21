from __future__ import annotations

import unittest
import csv
import json
import tempfile
import os
import threading
from pathlib import Path
from unittest.mock import patch

from beyond_handshake.capture import (capture_loopback, join_and_aggregate,
                                      parse_capture_health, parse_tshark_field_inventory, tshark_extract,
                                      _tcp_option_order, _tshark_bool)


class CaptureInventoryTests(unittest.TestCase):
    def test_capture_drop_diagnostics_from_dumpcap_and_tcpdump(self) -> None:
        dumpcap = "Packets received/dropped on interface 'Loopback: lo': 67/2 (pcap:2/dumpcap:0)"
        self.assertEqual(parse_capture_health(dumpcap), {"packets_received": 67,
                                                         "packets_dropped": 2})
        tcpdump = "67 packets received by filter\n0 packets dropped by kernel"
        self.assertEqual(parse_capture_health(tcpdump), {"packets_received": 67,
                                                         "packets_dropped": 0})

    def test_tshark_boolean_fields_accept_real_text_and_numeric_encodings(self) -> None:
        self.assertIs(_tshark_bool("True"), True)
        self.assertIs(_tshark_bool("False"), False)
        self.assertIs(_tshark_bool("1"), True)
        self.assertIs(_tshark_bool("0"), False)
        self.assertIsNone(_tshark_bool(""))

    def test_tcp_option_order_uses_raw_syn_bytes(self) -> None:
        order = _tcp_option_order([{"tcp.options": "0204ffd70402080ae14030ec000000000103030a"}])
        self.assertEqual(order, ["2", "4", "8", "1", "3"])
        with self.assertRaisesRegex(ValueError, "length is invalid"):
            _tcp_option_order([{"tcp.options": "0201"}])

    def test_parses_only_field_rows_and_preserves_real_names(self) -> None:
        text = "\n".join([
            "P\tProtocol\tShortName\tFilterName",
            "F\tTCP Source Port\ttcp.srcport\tFT_UINT16",
            "F\tTLS Handshake Type\ttls.handshake.type\tFT_UINT8",
        ])
        self.assertEqual(parse_tshark_field_inventory(text), [
            {"display_name": "TCP Source Port", "field_name": "tcp.srcport", "field_type": "FT_UINT16"},
            {"display_name": "TLS Handshake Type", "field_name": "tls.handshake.type", "field_type": "FT_UINT8"},
        ])

    def test_unique_time_join_writes_observation_features_and_quality_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packets = root / "packets.csv"
            fields = ["schema_version", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst",
                      "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack", "tcp.window_size_value",
                      "tcp.options.mss_val", "tcp.options.kind", "tls.handshake.type",
                      "tls.handshake.version", "tls.handshake.ciphersuite",
                      "tls.handshake.extension.type", "tls.handshake.extensions_alpn_str"]
            with packets.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fields, delimiter="\t")
                writer.writeheader()
                writer.writerow(dict(zip(fields, ["packet-observations/1", "1000.0", "7", "127.0.0.1",
                    "127.0.0.1", "50000", "8443", "1", "0", "64240", "1460", "2,4,8", "", "",
                    "", "", ""])))
                writer.writerow(dict(zip(fields, ["packet-observations/1", "1000.1", "7", "127.0.0.1",
                    "127.0.0.1", "50000", "8443", "0", "1", "64240", "", "", "1", "771",
                    "4865,4866", "0,10,43", "h2,http/1.1"])))
            events = root / "events.jsonl"
            data = [
                {"event_type": "connection.open", "connection_id": "c1", "ts_wall_ns": 1_000_000_000_000,
                 "payload": {"peer_ip": "127.0.0.1", "peer_port": 50000,
                             "local_ip": "127.0.0.1", "local_port": 8443,
                             "tls_version": "TLSv1.3", "tls_alpn": "h2"}},
                {"event_type": "http2.settings", "connection_id": "c1", "payload": {
                    "direction": "in", "entries": [{"setting_id": 1, "value": 4096}]}},
                {"event_type": "http.request_headers", "connection_id": "c1", "session_id": "s1",
                 "payload": {"headers_ordered": [[":method", "GET"], [":path", "/s/s1/start"]]}},
            ]
            events.write_text("".join(json.dumps(item) + "\n" for item in data))
            output = root / "joined.jsonl"
            report = join_and_aggregate(packets, events, output, session_id="s1")
            self.assertEqual(report["joined_count"], 1)
            self.assertEqual(report["server_connection_count"], 1)
            joined = json.loads(output.read_text().splitlines()[0])
            self.assertEqual(joined["tcp_stream"], "7")
            self.assertEqual(joined["features"]["h2_inbound_settings_order"][0][0]["setting_id"], 1)
            self.assertEqual(joined["session_ids"], ["s1"])
            self.assertEqual(joined["features"]["tls_cipher_suites_order"], ["4865", "4866"])

    def test_join_excludes_flow_without_client_hello(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packets = root / "packets.tsv"
            packets.write_text("frame.time_epoch\ttcp.stream\tip.src\tip.dst\ttcp.srcport\ttcp.dstport\ttcp.flags.syn\ttcp.flags.ack\n"
                               "1000.0\t7\t127.0.0.1\t127.0.0.1\t50000\t8443\t1\t0\n")
            events = root / "events.jsonl"
            events.write_text(json.dumps({"event_type": "connection.open", "connection_id": "c1",
                "ts_wall_ns": 1_000_000_000_000, "payload": {"peer_ip": "127.0.0.1",
                "peer_port": 50000, "local_ip": "127.0.0.1", "local_port": 8443}}) + "\n")
            report = join_and_aggregate(packets, events, root / "joined.jsonl")
            self.assertEqual(report["joined_count"], 0)
            self.assertTrue(report["incomplete_packet_evidence"][0]["missing_client_hello"])

    def test_capture_stop_signal_keeps_capture_open_until_task_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "fake-dumpcap"
            fake.write_text("""#!/usr/bin/env python3
import pathlib, signal, sys, time
out = pathlib.Path(sys.argv[sys.argv.index('-w') + 1])
out.write_bytes(b'pcap fixture')
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
while True:
    time.sleep(0.05)
""")
            fake.chmod(0o755)
            ready, stop = threading.Event(), threading.Event()
            result = {}
            with patch("beyond_handshake.capture.discover_capture_tools",
                       return_value={"loopback_capture_supported": True}), \
                 patch("beyond_handshake.capture.shutil.which", return_value=str(fake)):
                worker = threading.Thread(target=lambda: result.update(
                    capture_loopback(8443, 5, root, ready_event=ready, stop_event=stop)))
                worker.start()
                self.assertTrue(ready.wait(3))
                self.assertTrue(worker.is_alive())
                stop.set()
                worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result["status"], "captured")
            self.assertLess(result["duration_seconds"], 5)

    def test_extractor_uses_installed_field_inventory_and_writes_versioned_tsv(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake = root / "tshark"
            fake.write_text("""#!/usr/bin/env python3
import sys
args = sys.argv[1:]
if args == ['--version']:
 print('TShark (Wireshark) 9.9 fixture')
elif args == ['-G', 'fields']:
 print('F\\tFrame time epoch\\tframe.time_epoch\\tFT_ABSOLUTE_TIME')
 print('F\\tTCP stream index\\ttcp.stream\\tFT_UINT32')
else:
 print('frame.time_epoch\\ttcp.stream')
 print('1000.0\\t7')
""")
            fake.chmod(0o755)
            pcap = root / "fixture.pcapng"
            pcap.write_bytes(b"fixture")
            output = root / "packets.tsv"
            old_path = os.environ.get("PATH", "")
            try:
                os.environ["PATH"] = str(root) + os.pathsep + old_path
                result = tshark_extract(pcap, output)
            finally:
                os.environ["PATH"] = old_path
            self.assertEqual(result["packets_exported"], 1)
            self.assertIn("tcp.stream", result["fields"])
            self.assertEqual(result["tls_decode_port"], None)
            self.assertIn("packet-observations/1", output.read_text())


if __name__ == "__main__":
    unittest.main()
