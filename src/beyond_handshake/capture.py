"""Explicit loopback-only dumpcap supervision and TShark capability inventory."""

from __future__ import annotations

import hashlib
import re
import shutil
import signal
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path


def parse_tshark_field_inventory(text: str) -> list[dict[str, str]]:
    """Parse the stable tab-delimited columns from `tshark -G fields`."""
    fields = []
    for line in text.splitlines():
        columns = line.split("\t")
        if len(columns) >= 4 and columns[0] == "F":
            fields.append({"display_name": columns[1], "field_name": columns[2],
                           "field_type": columns[3]})
    return fields


def discover_capture_tools() -> dict:
    tshark = shutil.which("tshark")
    dumpcap = shutil.which("dumpcap")
    result = {"tshark": tshark, "dumpcap": dumpcap, "loopback_capture_supported": False,
              "field_inventory_count": 0, "missing": []}
    if not dumpcap:
        result["missing"].append("dumpcap is not installed")
    else:
        interfaces = subprocess.run([dumpcap, "-D"], capture_output=True, text=True, timeout=10)
        result["interfaces_exit_code"] = interfaces.returncode
        result["interfaces"] = interfaces.stdout.splitlines()
        result["loopback_capture_supported"] = interfaces.returncode == 0 and any(
            "loopback" in line.lower() or re.search(r"(^|[ .(])lo([ .)]|$)", line) is not None
            for line in interfaces.stdout.splitlines()
        )
        if interfaces.returncode:
            result["missing"].append("dumpcap cannot enumerate capture interfaces with current permissions")
    if not tshark:
        result["missing"].append("tshark is not installed; no packet extraction is available")
    else:
        version = subprocess.run([tshark, "--version"], capture_output=True, text=True, timeout=10)
        fields = subprocess.run([tshark, "-G", "fields"], capture_output=True, text=True, timeout=30)
        result["tshark_version"] = version.stdout.splitlines()[0] if version.stdout else "unknown"
        inventory = parse_tshark_field_inventory(fields.stdout) if fields.returncode == 0 else []
        result["field_inventory_count"] = len(inventory)
        result["field_inventory_ok"] = fields.returncode == 0 and bool(inventory)
        if fields.returncode:
            result["missing"].append("tshark -G fields failed; field names have not been verified")
    return result


def capture_loopback(port: int, seconds: float, output_dir: Path) -> dict:
    """Capture only loopback TCP traffic for the configured local task port."""
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not 0 < seconds <= 3600:
        raise ValueError("seconds must be in (0, 3600]")
    dumpcap = shutil.which("dumpcap")
    if not dumpcap:
        raise RuntimeError("dumpcap is unavailable; install Wireshark's capture tool first")
    # Disallow collecting arbitrary interfaces through this initial local pilot command.
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    capture_path = output_dir / f"loopback-{stamp}.pcapng"
    stderr_path = output_dir / f"loopback-{stamp}.dumpcap.stderr.log"
    stderr_file = stderr_path.open("wb")
    args = [dumpcap, "-i", "lo", "-f", f"tcp port {port}", "-w", str(capture_path), "-q"]
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=stderr_file, close_fds=True)
    try:
        time.sleep(0.4)
        if process.poll() is not None:
            raise RuntimeError(f"dumpcap exited early ({process.returncode}); inspect {stderr_path}")
        time.sleep(seconds)
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=3)
    except BaseException:
        if process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=3)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        stderr_file.close()
    digest = None
    if capture_path.is_file():
        hasher = hashlib.sha256()
        with capture_path.open("rb") as capture_file:
            for chunk in iter(lambda: capture_file.read(1024 * 1024), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
    return {"capture_path": str(capture_path), "stderr_path": str(stderr_path),
            "sha256": digest, "exit_code": process.returncode,
            "interface": "lo", "capture_filter": f"tcp port {port}",
            "duration_seconds": seconds, "status": "captured" if digest else "failed"}
