"""Create an isolated local development CA and a SAN-bearing HTTPS certificate."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from pathlib import Path

_DNS_NAME = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$")


def _san_name(hostname: str) -> str:
    try:
        address = ipaddress.ip_address(hostname)
        return f"IP:{address.compressed}"
    except ValueError:
        if not _DNS_NAME.fullmatch(hostname):
            raise ValueError(f"invalid certificate hostname: {hostname!r}")
        return f"DNS:{hostname.rstrip('.').lower()}"


def create_lab_certificate(output_dir: Path, hostnames: list[str]) -> tuple[Path, Path, Path]:
    if not hostnames:
        raise ValueError("provide at least one --hostname")
    if not shutil.which("openssl"):
        raise RuntimeError("openssl is required to create the local development certificate")
    sans = [_san_name(hostname) for hostname in hostnames]
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    ca_cert = output_dir / "ca.pem"
    ca_key = output_dir / "ca-key.pem"
    server_cert = output_dir / "server-cert.pem"
    server_key = output_dir / "server-key.pem"
    outputs = [ca_cert, ca_key, server_cert, server_key]
    existing = [str(path) for path in outputs if path.exists()]
    if existing:
        raise FileExistsError("refusing to overwrite existing certificate files: " + ", ".join(existing))

    csr = output_dir / "server.csr"
    extensions = output_dir / "server.ext"
    serial = output_dir / "ca.srl"
    san_text = ",".join(sans)
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName={san_text}\n",
        encoding="ascii",
    )
    commands = [
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "3650",
            "-subj", "/CN=BeyondHandshake Local Development CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ],
        [
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-keyout", str(server_key), "-out", str(csr),
            "-subj", "/CN=BeyondHandshake Local Server",
        ],
        [
            "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(server_cert),
            "-days", "365", "-sha256", "-extfile", str(extensions),
        ],
    ]
    try:
        for command in commands:
            subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        for path in outputs:
            path.unlink(missing_ok=True)
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()
            raise RuntimeError(f"openssl certificate generation failed: {detail}") from exc
        raise RuntimeError(f"could not run openssl: {exc}") from exc
    finally:
        csr.unlink(missing_ok=True)
        extensions.unlink(missing_ok=True)
        serial.unlink(missing_ok=True)

    ca_key.chmod(0o600)
    server_key.chmod(0o600)
    return ca_cert, server_cert, server_key
