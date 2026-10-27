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

    def test_chrome_version_mismatch_is_not_reported_as_profile_parity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            features = root / "features.csv"
            with features.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["session_id", "tls_cipher_suites_order"])
                writer.writeheader()
                writer.writerow({"session_id": "chrome", "tls_cipher_suites_order": '["4865"]'})
                writer.writerow({"session_id": "curl", "tls_cipher_suites_order": '["4865"]'})
            labels = root / "labels.json"
            labels.write_text(json.dumps([
                {"session_id": "chrome", "client_family": "google-chrome"},
                {"session_id": "curl", "client_family": "curl-impersonate"},
            ]))
            attempts = root / "episodes.jsonl"
            attempts.write_text(json.dumps({"attempt": {
                "client_family": "google-chrome", "adapter_version": "Google Chrome 156.0.8078.47",
                "steps": [{"chrome_binary_sha256": "abc123"}],
            }}) + "\n")
            report = fidelity_report(features, labels, root / "report.json", attempts)
            comparison = next(row for row in report["comparisons"]
                              if row["actual_client_family"] == "google-chrome"
                              and row["impersonator_family"] == "curl-impersonate")
            self.assertEqual(comparison["overall_status"], "version_mismatch")
            self.assertFalse(comparison["target_browser_available"])
            self.assertEqual(comparison["actual_browser_binary_hashes"], {"abc123": 1})

    def test_connection_count_alone_is_not_a_protocol_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            features = root / "features.csv"
            with features.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["session_id", "endpoint_alpn"])
                writer.writeheader()
                writer.writerow({"session_id": "chrome", "endpoint_alpn": '["h2","h2"]'})
                writer.writerow({"session_id": "curl", "endpoint_alpn": '["h2"]'})
            labels = root / "labels.json"
            labels.write_text(json.dumps([
                {"session_id": "chrome", "client_family": "google-chrome"},
                {"session_id": "curl", "client_family": "curl-impersonate"},
            ]))
            attempts = root / "episodes.jsonl"
            attempts.write_text(json.dumps({"attempt": {
                "client_family": "google-chrome", "adapter_version": "Google Chrome 156.0.8078.47",
            }}) + "\n")
            report = fidelity_report(features, labels, root / "report.json", attempts)
            comparison = next(row for row in report["comparisons"]
                              if row["actual_client_family"] == "google-chrome"
                              and row["impersonator_family"] == "curl-impersonate")
            alpn = next(row for row in comparison["components"] if row["component"] == "endpoint_alpn")
            self.assertEqual(alpn["status"], "matched")
            self.assertEqual(comparison["overall_status"], "version_mismatch")

    def test_chrome_for_testing_milestone_and_grease_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            features = root / "features.csv"
            with features.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["session_id", "tls_cipher_suites_order"])
                writer.writeheader()
                writer.writerow({"session_id": "chrome", "tls_cipher_suites_order":
                                 '[["0x0a0a","0x1301","0x1302"]]'})
                writer.writerow({"session_id": "curl", "tls_cipher_suites_order":
                                 '[["0x4a4a","0x1301","0x1302"]]'})
            labels = root / "labels.json"
            labels.write_text(json.dumps([
                {"session_id": "chrome", "client_family": "google-chrome"},
                {"session_id": "curl", "client_family": "curl-impersonate"},
            ]))
            attempts = root / "episodes.jsonl"
            attempts.write_text(json.dumps({"attempt": {
                "client_family": "google-chrome",
                "adapter_version": "Google Chrome for Testing 150.0.7871.124",
            }}) + "\n")
            report = fidelity_report(features, labels, root / "report.json", attempts)
            comparison = next(row for row in report["comparisons"]
                              if row["actual_client_family"] == "google-chrome"
                              and row["impersonator_family"] == "curl-impersonate")
            ciphers = next(row for row in comparison["components"]
                           if row["component"] == "tls_cipher_suites_order")
            self.assertEqual(ciphers["status"], "matched")
            self.assertTrue(comparison["target_browser_available"])
            self.assertEqual(comparison["target_version_alignment"], "milestone_match_only")
            self.assertEqual(comparison["overall_status"], "approximate_not_verified")


if __name__ == "__main__":
    unittest.main()
