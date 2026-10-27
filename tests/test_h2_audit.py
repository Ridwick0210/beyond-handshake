from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from beyond_handshake.h2_audit import _parse_pdml, audit_h2


PDML = b"""<pdml><packet>
  <proto name="tcp"><field name="tcp.srcport" show="55555"/>
    <field name="tcp.dstport" show="8443"/></proto>
  <proto name="http2"><field name="http2.stream">
    <field name="http2.type" show="4"/><field name="http2.streamid" show="0"/>
    <field name="http2.settings"><field name="http2.settings.id" show="4"/>
      <field name="http2.settings.initial_window_size" show="65535" value="0000ffff"/>
    </field>
  </field></proto>
  <proto name="http2"><field name="http2.stream">
    <field name="http2.type" show="1"/><field name="http2.streamid" show="1"/>
    <field name="http2.header.name" show=":method"/>
    <field name="http2.header.name" show=":path"/>
  </field></proto>
</packet></pdml>"""


class H2AuditTests(unittest.TestCase):
    def test_parse_pdml_preserves_settings_and_header_order(self):
        settings, headers = _parse_pdml(PDML)
        self.assertEqual(settings[55555], [[(4, 65535)]])
        self.assertEqual(headers[(55555, 1)], [[":method", ":path"]])

    def test_audit_detects_changed_endpoint_setting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            events = root / "events.jsonl"
            manifest = root / "manifest.json"
            keylog = root / "keylog"
            keylog.write_text("fixture")
            rows = [
                {"event_type": "connection.open", "connection_id": "c1",
                 "payload": {"peer_port": 55555}},
                {"event_type": "http2.settings", "connection_id": "c1",
                 "payload": {"direction": "in", "ack": False,
                             "entries": [{"setting_id": 4, "value": 65535}]}},
                {"event_type": "http.request_headers", "connection_id": "c1", "stream_id": 1,
                 "payload": {"protocol": "h2", "headers_ordered": [[":method", "GET"],
                                                              [":path", "start"]]}},
            ]
            events.write_text("".join(json.dumps(row) + "\n" for row in rows))
            manifest.write_text(json.dumps({"event_file": str(events),
                                            "packet_extractions": [{"pcap": str(root / "fixture.pcapng")}]}))
            with patch("beyond_handshake.h2_audit.subprocess.run",
                       return_value=SimpleNamespace(stdout=PDML)):
                good = audit_h2(manifest, keylog, root / "good.json")
                self.assertEqual(good["mismatches"], [])
                rows[1]["payload"]["entries"][0]["value"] = 65536
                events.write_text("".join(json.dumps(row) + "\n" for row in rows))
                bad = audit_h2(manifest, keylog, root / "bad.json")
            self.assertIn("SETTINGS", bad["mismatches"][0])


if __name__ == "__main__":
    unittest.main()
