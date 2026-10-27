from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from beyond_handshake.client import (_ResourceParser, _cache_max_age, _discover_and_fetch_resources,
                                     chrome_prerequisites, run_go_stdlib)


class ChromePrerequisiteTests(unittest.TestCase):
    def test_explicit_pinned_binary_takes_priority_over_system_chrome(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            browser, certutil, bwrap = (root / name for name in ("chrome", "certutil", "bwrap"))
            for path in (browser, certutil, bwrap):
                path.write_text("fixture")
                path.chmod(0o700)
            with mock.patch.dict("os.environ", {"BH_CHROME_BIN": str(browser),
                                             "BH_CERTUTIL": str(certutil)}), mock.patch(
                    "beyond_handshake.client.shutil.which", return_value=str(bwrap)):
                self.assertEqual(chrome_prerequisites(), (browser, certutil, bwrap))


class GoClientBridgeTests(unittest.TestCase):
    def _files(self, root: Path) -> tuple[Path, Path]:
        ca_file = root / "ca.pem"
        ca_file.write_text("test certificate placeholder", encoding="utf-8")
        binary = root / "bh-go-client"
        binary.write_bytes(b"test executable placeholder")
        return ca_file, binary

    @mock.patch("beyond_handshake.client.read_task_outcome")
    @mock.patch("beyond_handshake.client.subprocess.run")
    def test_successful_result_preserves_adapter_identity_and_protocol(
            self, run: mock.Mock, outcome: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ca_file, binary = self._files(Path(tmp))
            run.side_effect = [
                subprocess.CompletedProcess([str(binary), "--version"], 0, "go1.26.9\n", ""),
                subprocess.CompletedProcess([str(binary)], 0, json.dumps({
                    "protocol": "h2", "steps": [{"route": "start", "status": 200}]
                }) + "\n", ""),
            ]
            outcome.return_value = {"task_success": True}

            result = run_go_stdlib("a" * 32, "https://localhost:8443", ca_file, 10,
                                   control_port=8444, binary_path=binary)

        self.assertTrue(result.task_success)
        self.assertEqual(result.adapter_name, "go-stdlib")
        self.assertEqual(result.client_family, "go-net-http")
        self.assertEqual(result.observed_protocol, "h2")
        self.assertEqual(result.adapter_version, "go1.26.9")
        command = run.call_args_list[1].args[0]
        self.assertEqual(command[0], str(binary))
        self.assertIn(str(ca_file.resolve()), command)
        outcome.assert_called_once_with("a" * 32, 8444)

    @mock.patch("beyond_handshake.client.read_task_outcome")
    @mock.patch("beyond_handshake.client.subprocess.run")
    def test_child_error_is_recorded_as_failed_attempt(self, run: mock.Mock,
                                                       outcome: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ca_file, binary = self._files(Path(tmp))
            run.side_effect = [
                subprocess.CompletedProcess([str(binary), "--version"], 0, "go1.26.9\n", ""),
                subprocess.CompletedProcess([str(binary)], 1,
                                            '{"steps":[],"error":"start: refused"}\n', ""),
            ]

            result = run_go_stdlib("b" * 32, "https://localhost:8443", ca_file, 10,
                                   binary_path=binary)

        self.assertFalse(result.task_success)
        self.assertEqual(result.failure_category, "task_flow_failure")
        self.assertIn("start: refused", result.error or "")
        outcome.assert_not_called()


class ResourceDiscoveryTests(unittest.TestCase):
    def test_cache_policy_requires_public_freshness_and_respects_no_store(self):
        self.assertEqual(_cache_max_age("public, max-age=3600"), 3600)
        self.assertEqual(_cache_max_age("private, max-age=3600"), 0)
        self.assertEqual(_cache_max_age("no-store, max-age=3600"), 0)

    def test_html_parser_collects_only_expected_resource_attributes(self):
        parser = _ResourceParser()
        parser.feed('<link rel="stylesheet" href="assets/a.css">'
                    '<script src="assets/app.js"></script>'
                    '<img src="assets/img/item.svg"><a href="/outside">skip</a>')
        self.assertEqual(parser.resources, ["assets/a.css", "assets/app.js",
                                            "assets/img/item.svg"])

    def test_stage3_discovery_is_session_scoped_and_caches_fresh_assets(self):
        class Response:
            status_code = 200
            headers = {"Cache-Control": "public, max-age=3600"}

            def __init__(self, url, body):
                self.url = url
                self.content = body

        class Client:
            def __init__(self):
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(url)
                body = (b"body{background:url('img/amber-mug.svg')}"
                        if url.endswith("style.css") else b"asset")
                return Response(url, body)

        class Page:
            url = "https://localhost:8443/s/" + "a" * 32 + "/start"
            text = ('<link rel="stylesheet" href="assets/style.css">'
                    '<script src="assets/app.js"></script>'
                    '<img src="https://example.invalid/x">')

        client = Client()
        cache = {}
        metrics = {"discovered": 0, "network_fetches": 0, "cache_hits": 0}
        _discover_and_fetch_resources(client, Page(), "https://localhost:8443",
                                      "a" * 32, 10**20, cache, metrics)
        _discover_and_fetch_resources(client, Page(), "https://localhost:8443",
                                      "a" * 32, 10**20, cache, metrics)

        self.assertEqual(len(client.calls), 3)
        self.assertEqual(metrics["network_fetches"], 3)
        self.assertEqual(metrics["cache_hits"], 3)
        self.assertTrue(all("example.invalid" not in value for value in client.calls))


if __name__ == "__main__":
    unittest.main()
