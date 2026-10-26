from __future__ import annotations

import unittest

from beyond_handshake.development import _measurement_gate


class DevelopmentGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = {"episodes": [
            {"partition": "train", "execution_stack": "browser", "client_family": "firefox"},
            {"partition": "validation", "execution_stack": "browserless", "client_family": "curl"},
        ]}
        self.collection = {
            "attempt_count": 2, "successful_task_count": 2, "capture_count": 2,
            "event_only_connection_count": 0,
            "packet_extractions": [{"capture_health": {"packets_dropped": 0}} for _ in range(2)],
            "dataset": {"row_count": 2, "packet_complete_session_count": 2,
                        "unmatched_sessions": [], "coverage_by_cohort": [
                            {"partition": "train", "execution_stack": "browser",
                             "client_family": "firefox", "sessions": 1},
                            {"partition": "validation", "execution_stack": "browserless",
                             "client_family": "curl", "sessions": 1},
                        ]},
        }

    def test_complete_packet_cohort_passes(self) -> None:
        self.assertTrue(_measurement_gate(self.plan, self.collection)["passed"])

    def test_capture_drop_or_fallback_blocks_training(self) -> None:
        self.collection["packet_extractions"][0]["capture_health"]["packets_dropped"] = 1
        self.collection["event_only_connection_count"] = 1
        gate = _measurement_gate(self.plan, self.collection)
        self.assertFalse(gate["passed"])
        self.assertEqual(len(gate["problems"]), 2)


if __name__ == "__main__":
    unittest.main()
