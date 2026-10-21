"""Convenience entry point for generating local development certificates."""

from __future__ import annotations

import argparse
from pathlib import Path

from beyond_handshake.certificates import create_lab_certificate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", action="append", required=True)
    parser.add_argument("--out", type=Path, default=Path("local/tls"))
    args = parser.parse_args()
    ca, certificate, key = create_lab_certificate(args.out, args.hostname)
    print(f"CA: {ca}\nCertificate: {certificate}\nPrivate key: {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
