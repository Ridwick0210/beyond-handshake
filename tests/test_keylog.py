from __future__ import annotations

import os
import ssl
import tempfile
import unittest
from pathlib import Path

from beyond_handshake.server.http1 import _secure_keylog_file


class KeylogTests(unittest.TestCase):
    def test_keylog_is_private_on_create_and_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secrets.log"
            _secure_keylog_file(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.keylog_filename = str(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            os.chmod(path, 0o644)
            _secure_keylog_file(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_keylog_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.write_text("unchanged")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                _secure_keylog_file(link)
            self.assertEqual(target.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
