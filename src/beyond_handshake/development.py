"""One-command local development collection with a strict measurement gate."""

from __future__ import annotations

import importlib.util
import json
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

from beyond_handshake.capture import discover_capture_tools
from beyond_handshake.client import available_impersonation_profiles, chrome_prerequisites
from beyond_handshake.config import load_server_config
from beyond_handshake.experiment import collect_plan, plan_experiment
from beyond_handshake.modeling import train_baselines


def _project_root() -> Path:
    return next(parent for parent in Path(__file__).resolve().parents
                if (parent / "pyproject.toml").is_file())


def _preflight(config_path: Path, output_root: Path, model_root: Path,
               server_config_path: Path) -> tuple[dict, object]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    experiment_id = config.get("experiment_id")
    if not isinstance(experiment_id, str) or not experiment_id or "/" in experiment_id or ".." in experiment_id:
        raise ValueError("experiment_id must be a simple nonempty name")
    if (output_root / experiment_id).exists() or (output_root / f"{experiment_id}-plan.json").exists():
        raise FileExistsError("development output already exists; use a new experiment_id")
    if model_root.exists():
        raise FileExistsError(f"model output already exists: {model_root}")
    server_config = load_server_config(server_config_path)
    if not server_config.tls.cert.is_file() or not server_config.tls.key.is_file():
        raise FileNotFoundError("local TLS server certificate or key is missing")
    ca_file = Path(config.get("ca_file", "local/tls/ca.pem"))
    if not ca_file.is_file():
        raise FileNotFoundError(f"local CA is missing: {ca_file}")
    if config.get("origin") != f"https://localhost:{server_config.listen_port}":
        raise ValueError("development origin must match the local HTTPS server")
    if config.get("task_id") != "catalog-search-detail-save-v1":
        raise ValueError("unsupported development task_id")
    adapters = {client.get("adapter") for client in config.get("clients", [])}
    if "firefox" in adapters and not shutil.which("firefox"):
        raise RuntimeError("Firefox is unavailable")
    if "chrome" in adapters:
        chrome_prerequisites()
    if "go-stdlib" in adapters and not (_project_root() / "local/bin/bh-go-client").is_file():
        raise RuntimeError("Go adapter is not built; run `make go-client`")
    if "go-tls-client" in adapters and not (_project_root() / "local/bin/bh-go-tls-client").is_file():
        raise RuntimeError("Go tls-client adapter is not built; run `make go-tls-client`")
    if "curl-cffi" in adapters:
        available = set(available_impersonation_profiles())
        for client in config["clients"]:
            if (client.get("adapter") == "curl-cffi" and client.get("imitation_stage", 1) in (1, 2, 3)
                    and client.get("profile") not in available):
                raise RuntimeError(f"unsupported curl-cffi profile: {client.get('profile')}")
    if importlib.util.find_spec("sklearn") is None:
        raise RuntimeError("ML dependencies are missing; run `uv sync --locked --extra ml --extra impersonation`")
    capture = discover_capture_tools()
    if not capture.get("loopback_capture_supported") or not capture.get("field_inventory_ok"):
        raise RuntimeError("loopback packet capture is unavailable; run this command in the authorized wireshark group")
    if shutil.disk_usage(output_root.parent).free < 1024**3:
        raise RuntimeError("less than 1 GiB free; collection was not started")
    return config, server_config


def _wait_for_server(process: subprocess.Popen, origin: str, ca_file: Path) -> None:
    context = ssl.create_default_context(cafile=str(ca_file))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"local server exited during startup with code {process.returncode}")
        try:
            with urllib.request.urlopen(origin + "/healthz", context=context, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise TimeoutError("local server did not become ready within 15 seconds")


def _measurement_gate(plan: dict, collection: dict) -> dict:
    expected = len(plan["episodes"])
    dataset = collection["dataset"]
    counts = Counter((row["partition"], row["execution_stack"], row["client_family"])
                     for row in plan["episodes"])
    problems = []
    if collection["attempt_count"] != expected or collection["successful_task_count"] != expected:
        problems.append("some planned tasks did not succeed")
    if collection["capture_count"] != expected:
        problems.append("some packet captures failed")
    if dataset["row_count"] != expected or dataset["packet_complete_session_count"] != expected:
        problems.append("some sessions lack complete packet and server evidence")
    if collection["event_only_connection_count"] != 0 or dataset["unmatched_sessions"]:
        problems.append("some sessions used event-only fallback or did not join")
    extractions = collection["packet_extractions"]
    if len(extractions) != expected or any(
            item.get("capture_health", {}).get("packets_dropped") != 0 for item in extractions):
        problems.append("capture drop counts are missing or nonzero")
    observed = {(row["partition"], row["execution_stack"], row["client_family"]): row["sessions"]
                for row in dataset["coverage_by_cohort"]}
    if observed != dict(counts):
        problems.append("dataset cohort counts differ from the frozen plan")
    return {"passed": not problems, "expected_sessions": expected,
            "cohort_counts": [{"partition": key[0], "execution_stack": key[1],
                               "client_family": key[2], "sessions": count}
                              for key, count in sorted(counts.items())],
            "problems": problems}


def run_development(config_path: Path, output_root: Path, model_root: Path,
                    server_config_path: Path) -> dict:
    """Collect, audit, and train on a new development cohort; never open a test partition."""
    config_path = config_path.resolve()
    output_root = output_root.resolve()
    model_root = model_root.resolve()
    server_config_path = server_config_path.resolve()
    config, server_config = _preflight(config_path, output_root, model_root, server_config_path)
    output_root.mkdir(parents=True, exist_ok=True)
    plan_path = output_root / f"{config['experiment_id']}-plan.json"
    plan = plan_experiment(config_path, plan_path)
    if any(row["partition"] == "test" for row in plan["episodes"]):
        raise ValueError("development run cannot collect a test partition")
    log_path = output_root / f"{config['experiment_id']}-server.log"
    started = time.monotonic()
    with log_path.open("wb") as server_log:
        server = subprocess.Popen([sys.executable, "-m", "beyond_handshake.cli", "server",
                                   "--config", str(server_config_path)],
                                  cwd=_project_root(), stdin=subprocess.DEVNULL,
                                  stdout=server_log, stderr=subprocess.STDOUT)
        try:
            _wait_for_server(server, config["origin"], Path(config["ca_file"]).resolve())
            collection = collect_plan(plan_path, output_root, server_config_path)
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
    run_dir = output_root / config["experiment_id"]
    gate = _measurement_gate(plan, collection)
    report = {"schema_version": "development-run/1", "experiment_id": config["experiment_id"],
              "plan": str(plan_path), "collection": str(run_dir / "collection-manifest.json"),
              "server_log": str(log_path), "measurement_gate": gate,
              "models": {}, "elapsed_seconds": time.monotonic() - started,
              "status": "ready_to_train" if gate["passed"] else "measurement_failed",
              "limitations": ["local development cohort only", "final test was not collected or scored"]}
    report_path = run_dir / "development-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not gate["passed"]:
        raise RuntimeError(f"measurement gate failed; inspect {report_path}: {gate['problems']}")
    for group in ("tls_only", "tls_plus_h2", "full"):
        result = train_baselines(run_dir / "dataset", model_root / group, feature_group=group)
        report["models"][group] = {"report": str(model_root / group / "model-selection.json"),
                                   "train_rows": result["train_rows"],
                                   "validation_rows": result["validation_rows"],
                                   "test_rows_read": result["test_rows_read"]}
    report["elapsed_seconds"] = time.monotonic() - started
    report["status"] = "development_models_trained"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
