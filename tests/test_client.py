from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from beyond_handshake.client import run_go_stdlib


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


if __name__ == "__main__":
    unittest.main()
