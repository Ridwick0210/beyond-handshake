from __future__ import annotations

import unittest
import csv
import tempfile
import importlib.util
from pathlib import Path

from beyond_handshake.modeling import (_select_threshold, _validate_packet_coverage,
                                       score_bundle, train_baselines)


class ModelingTests(unittest.TestCase):
    def test_threshold_obeys_fpr_cap_and_prefers_recall_then_higher_cutoff(self):
        threshold, metrics = _select_threshold([0, 0, 1, 1], [0.1, 0.8, 0.7, 0.9], 0.0)
        self.assertEqual(threshold, 0.9)
        self.assertEqual(metrics["false_positive_rate"], 0.0)
        self.assertEqual(metrics["recall"], 0.5)

    def test_requires_both_classes(self):
        with self.assertRaisesRegex(ValueError, "both classes"):
            _select_threshold([0, 0], [0.1, 0.2], 0.05)

    def test_partial_packet_coverage_is_not_accepted_for_model_fitting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (root / "coverage.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["session_id", "packet_connection_count",
                    "event_only_connection_count", "unknown_source_connection_count", "packet_complete"])
                writer.writeheader()
                writer.writerow({"session_id": "browser", "packet_connection_count": 1,
                                 "event_only_connection_count": 0, "unknown_source_connection_count": 0,
                                 "packet_complete": True})
                writer.writerow({"session_id": "browserless", "packet_connection_count": 0,
                                 "event_only_connection_count": 1, "unknown_source_connection_count": 0,
                                 "packet_complete": False})
            labels = [{"session_id": "browser", "partition": "train", "execution_stack": "browser"},
                      {"session_id": "browserless", "partition": "train", "execution_stack": "browserless"}]
            with self.assertRaisesRegex(ValueError, "partial packet coverage"):
                _validate_packet_coverage(root, labels)

    @unittest.skipUnless(importlib.util.find_spec("sklearn") and importlib.util.find_spec("pandas"),
                         "requires optional ml extra")
    def test_model_bundle_roundtrip_and_feature_order_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset = root / "dataset"
            dataset.mkdir()
            feature_rows, label_rows = [], []
            for i in range(16):
                sid = f"s{i}"
                is_train = i < 8
                browserless = i % 2 == 1
                feature_rows.append({"session_id": sid, "connection_count": "1",
                    "endpoint_alpn": '"http/1.1"' if browserless else '"h2"'})
                label_rows.append({"session_id": sid, "client_family": ("browser" if not browserless else
                    ("train-family" if is_train else "validation-family")),
                    "execution_stack": "browserless" if browserless else "browser",
                    "partition": "train" if is_train else "validation"})
            with (dataset / "features.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(feature_rows[0]))
                writer.writeheader(); writer.writerows(feature_rows)
            with (dataset / "labels.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(label_rows[0]))
                writer.writeheader(); writer.writerows(label_rows)
            out = root / "models"
            train_baselines(dataset, out, 0.5)
            import joblib
            bundle = joblib.load(out / "logistic-regression.joblib")
            rows = [{"connection_count": 1.0, "endpoint_alpn": '"h2"'}]
            frame_ordered = __import__("pandas").DataFrame(rows, columns=bundle["feature_columns"])
            scores = score_bundle(out / "logistic-regression.joblib", frame_ordered)
            self.assertEqual(len(scores), 1)
            with self.assertRaisesRegex(ValueError, "feature order/schema"):
                score_bundle(out / "logistic-regression.joblib", frame_ordered[list(reversed(frame_ordered.columns))])
            tls_out = root / "tls_models"
            tls_report = train_baselines(dataset, tls_out, 0.5, feature_group="tls_only")
            self.assertEqual(tls_report["feature_group"], "tls_only")
            self.assertEqual(tls_report["feature_columns"], ["endpoint_alpn"])


if __name__ == "__main__":
    unittest.main()
