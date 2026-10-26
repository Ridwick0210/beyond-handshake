from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from beyond_handshake.experiment import (_combine_feature_sources,
                                         plan_experiment, rebuild_capture_dataset)


class ExperimentPlanningTests(unittest.TestCase):
    def test_rebuild_refuses_unfinished_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "active"
            run.mkdir()
            with self.assertRaisesRegex(ValueError, "not finalized"):
                rebuild_capture_dataset(run, root / "rebuilt", 8443)
            self.assertFalse((root / "rebuilt").exists())

    def test_packet_join_replaces_event_only_row_for_same_connection(self):
        packet_rows = [{"connection_id": "joined", "session_ids": ["s1"],
                        "features": {"tcp_packet_count": 5}}]
        event_rows = [{"connection_id": "joined", "session_ids": ["s1"],
                       "feature_source": "server-events-only", "features": {"endpoint_alpn": "h2"}},
                      {"connection_id": "fallback", "session_ids": ["s2"],
                       "feature_source": "server-events-only", "features": {"endpoint_alpn": "http/1.1"}},
                      {"connection_id": "prior-run", "session_ids": ["old"],
                       "feature_source": "server-events-only", "features": {"endpoint_alpn": "h2"}}]
        rows = _combine_feature_sources(packet_rows, event_rows, {"s1", "s2"})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["feature_source"], "packet-and-server-events")
        self.assertEqual(rows[1]["connection_id"], "fallback")

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

    def test_go_stdlib_adapter_is_accepted_in_a_development_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "experiment.json"
            config.write_text(json.dumps({"schema_version": "1.0", "experiment_id": "go-smoke",
                "seed": 11, "repeats_per_client_partition": 1, "clients": [
                    {"name": "browser", "adapter": "firefox", "client_family": "browser-x",
                     "execution_stack": "browser", "partitions": ["train", "validation"]},
                    {"name": "negative-a", "adapter": "stdlib", "client_family": "family-a",
                     "execution_stack": "browserless", "partitions": ["train"]},
                    {"name": "negative-go", "adapter": "go-stdlib",
                     "client_family": "go-net-http", "execution_stack": "browserless",
                     "partitions": ["validation"]}]}))

            plan = plan_experiment(config, root / "plan.json")

            go_episodes = [row for row in plan["episodes"] if row["adapter"] == "go-stdlib"]
            self.assertEqual(len(go_episodes), 1)
            self.assertEqual(go_episodes[0]["partition"], "validation")
            self.assertTrue(all(row["partition"] != "test" for row in plan["episodes"]))

    def test_stage_0_and_1_plan_pairs_task_seeds_and_keeps_families_partitioned(self):
        config = Path(__file__).resolve().parents[1] / "configs/stages_0_1_development.json"
        with tempfile.TemporaryDirectory() as tmp:
            plan = plan_experiment(config, Path(tmp) / "plan.json")

        episodes = plan["episodes"]
        self.assertEqual(len(episodes), 60)
        for family in ("curl-impersonate", "go-client-family"):
            rows = [row for row in episodes if row["client_family"] == family]
            self.assertEqual({row["imitation_stage"] for row in rows}, {0, 1})
            self.assertEqual({row["partition"] for row in rows}, {rows[0]["partition"]})
            for repeat in range(10):
                pair = [row for row in rows if row["repeat"] == repeat]
                self.assertEqual(len(pair), 2)
                self.assertEqual({row["task_seed"] for row in pair}, {pair[0]["task_seed"]})
                self.assertEqual({row["pair_id"] for row in pair}, {pair[0]["pair_id"]})

    def test_stage_0_cannot_carry_an_impersonation_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "experiment.json"
            config.write_text(json.dumps({"schema_version": "1.0", "experiment_id": "bad-stage",
                "repeats_per_client_partition": 1, "clients": [
                    {"name": "browser", "adapter": "firefox", "client_family": "browser",
                     "execution_stack": "browser", "partitions": ["train", "validation"]},
                    {"name": "bad", "adapter": "curl-cffi", "client_family": "bad-family",
                     "execution_stack": "browserless", "imitation_stage": 0,
                     "profile": "chrome150", "partitions": ["train"]},
                    {"name": "other", "adapter": "stdlib", "client_family": "other-family",
                     "execution_stack": "browserless", "partitions": ["validation"]}]}))
            with self.assertRaisesRegex(ValueError, "stage 0"):
                plan_experiment(config, root / "plan.json")

    def test_stage_2_3_plan_keeps_curl_family_in_one_partition_and_pairs_seeds(self):
        config = Path(__file__).resolve().parents[1] / "configs/stages_2_3_development.json"
        with tempfile.TemporaryDirectory() as tmp:
            plan = plan_experiment(config, Path(tmp) / "plan.json")

        episodes = plan["episodes"]
        self.assertEqual(len(episodes), 50)
        curl_rows = [row for row in episodes if row["client_family"] == "curl-impersonate"]
        self.assertEqual({row["imitation_stage"] for row in curl_rows}, {2, 3})
        self.assertEqual({row["partition"] for row in curl_rows}, {"train"})
        for repeat in range(10):
            pair = [row for row in curl_rows if row["repeat"] == repeat]
            self.assertEqual(len(pair), 2)
            self.assertEqual({row["task_seed"] for row in pair}, {pair[0]["task_seed"]})
            self.assertEqual({row["pair_id"] for row in pair}, {pair[0]["pair_id"]})


if __name__ == "__main__":
    unittest.main()
