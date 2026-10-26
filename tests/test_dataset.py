from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from beyond_handshake.dataset import build_dataset, evaluate_naive_bayes


class DatasetTests(unittest.TestCase):
    def test_build_keeps_labels_separate_and_rejects_family_split_leakage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            joined = root / "joined.jsonl"
            joined.write_text(json.dumps({"session_ids": ["tr", "tr2", "te", "te2"], "features": {
                "tcp_packet_count": 4, "endpoint_alpn": "h2"}}) + "\n")
            labels = root / "labels.json"
            labels.write_text(json.dumps([
                {"session_id": "tr", "execution_stack": "browser", "client_family": "fam1", "partition": "train"},
                {"session_id": "tr2", "execution_stack": "browserless", "client_family": "fam2",
                 "partition": "train", "imitation_stage": 1},
                {"session_id": "te", "execution_stack": "browserless", "client_family": "fam3", "partition": "test"},
                {"session_id": "te2", "execution_stack": "browser", "client_family": "fam4", "partition": "test"},
            ]))
            out = root / "dataset"
            manifest = build_dataset(joined, labels, out)
            self.assertTrue(manifest["label_feature_separation"])
            self.assertNotIn("execution_stack", (out / "features.csv").read_text())
            self.assertNotIn("imitation_stage", (out / "features.csv").read_text())
            self.assertIn("execution_stack", (out / "labels.csv").read_text())
            self.assertIn("imitation_stage", (out / "labels.csv").read_text())
            result = evaluate_naive_bayes(out, root / "eval.json")
            self.assertEqual(result["test_count"], 2)
            self.assertEqual(set(result["comparisons"]), {"tls_only", "tls_plus_h2", "full"})
            self.assertTrue(result["common_test_cohort_for_all_groups"])

    def test_family_cannot_appear_in_multiple_partitions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            joined = root / "joined.jsonl"
            joined.write_text(json.dumps({"session_ids": ["a"], "features": {"x": 1}}) + "\n")
            labels = root / "labels.json"
            labels.write_text(json.dumps([
                {"session_id": "a", "execution_stack": "browserless", "client_family": "same", "partition": "train"},
                {"session_id": "b", "execution_stack": "browserless", "client_family": "same", "partition": "test"},
            ]))
            with self.assertRaisesRegex(ValueError, "cross partitions"):
                build_dataset(joined, labels, root / "out")


if __name__ == "__main__":
    unittest.main()
