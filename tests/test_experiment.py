from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from beyond_handshake.experiment import plan_experiment


class ExperimentPlanningTests(unittest.TestCase):
    def test_development_schedule_is_reproducible_and_family_held_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "experiment.json"
            config.write_text(json.dumps({"schema_version": "1.0", "experiment_id": "test-plan",
                "seed": 7, "repeats_per_client_partition": 2, "clients": [
                    {"name": "browser", "adapter": "firefox", "client_family": "browser-x",
                     "execution_stack": "browser", "partitions": ["train", "validation"]},
                    {"name": "negative-a", "adapter": "stdlib", "client_family": "family-a",
                     "execution_stack": "browserless", "partitions": ["train"]},
                    {"name": "negative-b", "adapter": "curl-cffi", "client_family": "family-b",
                     "execution_stack": "browserless", "profile": "chrome150", "partitions": ["validation"]}]}))
            first, second = root / "first.json", root / "second.json"
            a, b = plan_experiment(config, first), plan_experiment(config, second)
            self.assertEqual([x["session_id"] for x in a["episodes"]], [x["session_id"] for x in b["episodes"]])
            self.assertEqual(len(a["episodes"]), 8)
            self.assertEqual({x["partition"] for x in a["episodes"]}, {"train", "validation"})
            self.assertTrue(all(x["partition"] != "test" for x in a["episodes"]))


if __name__ == "__main__":
    unittest.main()
