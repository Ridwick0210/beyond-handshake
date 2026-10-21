from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from beyond_handshake.fidelity import fidelity_report


class FidelityTests(unittest.TestCase):
    def test_packet_evidence_is_reported_without_claiming_target_browser_parity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            features = root / "features.csv"
            with features.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["session_id", "tls_cipher_suites_order",
                    "endpoint_alpn"])
                writer.writeheader()
                writer.writerow({"session_id": "browser", "tls_cipher_suites_order": '["4865"]',
                                 "endpoint_alpn": '"h2"'})
                writer.writerow({"session_id": "imitator", "tls_cipher_suites_order": '["4866"]',
                                 "endpoint_alpn": '"h2"'})
            labels = root / "labels.json"
            labels.write_text(json.dumps([{"session_id": "browser", "client_family": "mozilla-firefox"},
                                          {"session_id": "imitator", "client_family": "curl-impersonate"}]))
            report = fidelity_report(features, labels, root / "report.json")
            self.assertEqual(report["feature_source"], "packet-and-server-events")
            self.assertIn("tls_cipher_suites_order", report["observed_packet_dimensions"])
            self.assertEqual(report["comparisons"][0]["overall_status"], "approximate_not_verified")


if __name__ == "__main__":
    unittest.main()
