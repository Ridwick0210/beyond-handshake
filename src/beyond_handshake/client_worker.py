"""Isolated per-episode client process used by the resource-cost collector."""

from __future__ import annotations

import json
import os
import threading
import sys
import time
from pathlib import Path

from beyond_handshake.client import (run_chrome, run_curl_cffi, run_firefox,
                                     run_go_stdlib, run_go_tls_client, run_stdlib)


class _ProcessTreeMeter:
    """Sample the isolated episode's Linux process tree; no collector/server included."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)
        self._seen_cpu: dict[tuple[int, int], int] = {}
        self._peak_rss = 0
        self._ticks = os.sysconf("SC_CLK_TCK")
        self._page_size = os.sysconf("SC_PAGE_SIZE")

    def start(self) -> None:
        self._thread.start()

    def finish(self) -> dict:
        self._stop.set()
        self._thread.join()
        cpu_ticks = sum(self._seen_cpu.values())
        return {"cpu_ns": int(cpu_ticks * 1_000_000_000 / self._ticks),
                "peak_process_tree_rss_bytes": self._peak_rss,
                "method": "Linux /proc process-tree sampling at 20 ms; episode isolated in worker"}

    def _sample(self) -> None:
        while True:
            rss = 0
            pending = [os.getpid()]
            visited: set[int] = set()
            while pending:
                pid = pending.pop()
                if pid in visited:
                    continue
                visited.add(pid)
                try:
                    raw = Path(f"/proc/{pid}/stat").read_text()
                    fields = raw[raw.rfind(")") + 2:].split()
                    # fields begin at stat field 3: state, ppid, ..., utime, stime, ..., starttime
                    ppid, utime, stime, starttime = int(fields[1]), int(fields[11]), int(fields[12]), int(fields[19])
                    del ppid
                    key = (pid, starttime)
                    self._seen_cpu[key] = max(self._seen_cpu.get(key, 0), utime + stime)
                    rss_pages = int(Path(f"/proc/{pid}/statm").read_text().split()[1])
                    rss += rss_pages * self._page_size
                    children = Path(f"/proc/{pid}/task/{pid}/children")
                    pending.extend(int(value) for value in children.read_text().split())
                except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
                    continue
            self._peak_rss = max(self._peak_rss, rss)
            if self._stop.wait(0.02):
                return


def main() -> int:
    request = json.load(sys.stdin)
    adapter = request["adapter"]
    args = (request["session_id"], request["origin"], Path(request["ca_file"]),
            request["timeout"], request["control_port"])
    meter = _ProcessTreeMeter()
    meter.start()
    try:
        if adapter == "chrome":
            result = run_chrome(*args)
        elif adapter == "firefox":
            result = run_firefox(*args)
        elif adapter == "stdlib":
            result = run_stdlib(*args)
        elif adapter == "go-stdlib":
            result = run_go_stdlib(*args)
        elif adapter == "go-tls-client":
            result = run_go_tls_client(*args[:4], request.get("profile"), args[4],
                                       imitation_stage=request.get("imitation_stage", 1))
        elif adapter == "curl-cffi":
            result = run_curl_cffi(*args[:4], request.get("profile"), args[4],
                                   request.get("imitation_stage", 1))
        else:
            raise ValueError(f"unsupported adapter {adapter!r}")
    finally:
        resource_metrics = meter.finish()
    result.resource_metrics = {**result.resource_metrics, **resource_metrics}
    print(json.dumps({"result": {field: getattr(result, field)
                                 for field in result.__dataclass_fields__}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
