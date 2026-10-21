from __future__ import annotations

import unittest
import csv
import json
import tempfile
import os
from pathlib import Path

from beyond_handshake.capture import join_and_aggregate, parse_tshark_field_inventory, tshark_extract


class CaptureInventoryTests(unittest.TestCase):
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
                      "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.window_size_value",
                      "tcp.options.mss_val", "tcp.options.kind", "tls.handshake.type",
                      "tls.handshake.version", "tls.handshake.ciphersuite",
                      "tls.handshake.extension.type", "tls.handshake.extensions_alpn_str"]
            with packets.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fields, delimiter="\t")
                writer.writeheader()
                writer.writerow(dict(zip(fields, ["packet-observations/1", "1000.0", "7", "127.0.0.1",
                    "127.0.0.1", "50000", "8443", "1", "64240", "1460", "2,4,8", "1", "771",
                    "4865,4866", "0,10,43", "h2,http/1.1"])))
            events = root / "events.jsonl"
            data = [
                {"event_type": "connection.open", "connection_id": "c1", "ts_wall_ns": 1_000_000_000_000,
                 "payload": {"peer_ip": "127.0.0.1", "peer_port": 50000,
                             "tls_version": "TLSv1.3", "tls_alpn": "h2"}},
                {"event_type": "http2.settings", "connection_id": "c1", "payload": {
                    "direction": "in", "entries": [{"setting_id": 1, "value": 4096}]}},
                {"event_type": "http.request_headers", "connection_id": "c1", "session_id": "s1",
                 "payload": {"headers_ordered": [[":method", "GET"], [":path", "/s/s1/start"]]}},
            ]
            events.write_text("".join(json.dumps(item) + "\n" for item in data))
            output = root / "joined.jsonl"
            report = join_and_aggregate(packets, events, output)
            self.assertEqual(report["joined_count"], 1)
            joined = json.loads(output.read_text().splitlines()[0])
            self.assertEqual(joined["tcp_stream"], "7")
            self.assertEqual(joined["features"]["h2_inbound_settings_order"][0][0]["setting_id"], 1)
            self.assertEqual(joined["session_ids"], ["s1"])

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
            self.assertIn("packet-observations/1", output.read_text())


if __name__ == "__main__":
    unittest.main()
