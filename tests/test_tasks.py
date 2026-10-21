from __future__ import annotations

import json
import re
import unittest
from urllib.parse import urlencode

from beyond_handshake.tasks import LARGE_ASSET, TaskOracle


class TaskOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracle = TaskOracle()
        self.session_id = "a" * 32
        self.oracle.register(self.session_id, 1234)
        self.prefix = f"/s/{self.session_id}"

    def test_full_success_flow_and_duplicate_save(self) -> None:
        status, page, _, sid, route, transitions = self.oracle.handle("GET", self.prefix + "/start")
        self.assertEqual((status, sid, route), (200, self.session_id, "start"))
        self.assertEqual(transitions[0]["new_state"], "started")
        term = re.search(r"<b>([^<]+)</b>", page.decode()).group(1)
        status, result, _, _, route, _ = self.oracle.handle(
            "GET", self.prefix + "/api/search?" + urlencode({"q": term})
        )
        item = json.loads(result)["items"][0]
        self.assertEqual((status, route), (200, "search_api"))
        status, detail, *_ = self.oracle.handle("GET", item["url"])
        self.assertEqual(status, 200)
        item_id = re.search(r'name=item_id value="([^"]+)', detail.decode()).group(1)
        nonce = re.search(r'name=nonce value="([^"]+)', detail.decode()).group(1)
        status, saved, *_ = self.oracle.handle(
            "POST", self.prefix + "/api/save", urlencode({"item_id": item_id, "nonce": nonce}).encode()
        )
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(saved)["duplicate"])
        status, duplicate, *_ = self.oracle.handle(
            "POST", self.prefix + "/api/save", urlencode({"item_id": item_id, "nonce": nonce}).encode()
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(duplicate)["duplicate"])
        status, result, *_ = self.oracle.handle("GET", self.prefix + "/complete")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(result)["task_success"])
        self.assertTrue(self.oracle.outcome(self.session_id)["task_success"])

    def test_invalid_item_transition_is_rejected(self) -> None:
        self.oracle.handle("GET", self.prefix + "/start")
        status, _, _, _, _, transitions = self.oracle.handle("GET", self.prefix + "/item/amber-mug")
        self.assertEqual(status, 409)
        self.assertEqual(transitions, [])
        self.assertEqual(self.oracle.outcome(self.session_id)["state"], "started")

    def test_task_spec_is_reproducible_for_seed(self) -> None:
        first = self.oracle.task_spec(self.session_id)
        other = "b" * 32
        self.oracle.register(other, 1234)
        second = self.oracle.task_spec(other)
        self.assertEqual(first["instructions"], second["instructions"])
        self.assertEqual(first["workload_id"], second["workload_id"])

    def test_large_asset_is_stable_and_local(self) -> None:
        status, payload, mime, sid, route, _ = self.oracle.handle(
            "GET", self.prefix + "/assets/large.bin"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(payload), 192 * 1024)
        self.assertEqual(payload, LARGE_ASSET)
        self.assertEqual(mime, "application/octet-stream")
        self.assertEqual((sid, route), (self.session_id, "asset_large"))

    def test_image_asset_is_deterministic_and_allowlisted(self) -> None:
        first = self.oracle.handle("GET", self.prefix + "/assets/img/amber-mug.svg")
        second = self.oracle.handle("GET", self.prefix + "/assets/img/amber-mug.svg")
        rejected = self.oracle.handle("GET", self.prefix + "/assets/img/../../secret.svg")
        self.assertEqual(first[0], 200)
        self.assertEqual(first[1], second[1])
        self.assertEqual(first[2], "image/svg+xml")
        self.assertEqual(rejected[0], 404)


if __name__ == "__main__":
    unittest.main()
