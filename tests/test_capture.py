from __future__ import annotations

import unittest

from beyond_handshake.capture import parse_tshark_field_inventory


class CaptureInventoryTests(unittest.TestCase):
    def test_parses_only_field_rows_and_preserves_real_names(self) -> None:
        text = "\n".join([
            "P\tProtocol\tShortName\tFilterName",
            "F\tTCP Source Port\ttcp.srcport\tFT_UINT16",
            "F\tTLS Handshake Type\ttls.handshake.type\tFT_UINT8",
        ])
        self.assertEqual(parse_tshark_field_inventory(text), [
            {"display_name": "TCP Source Port", "field_name": "tcp.srcport", "field_type": "FT_UINT16"},
            {"display_name": "TLS Handshake Type", "field_name": "tls.handshake.type", "field_type": "FT_UINT8"},
        ])


if __name__ == "__main__":
    unittest.main()
