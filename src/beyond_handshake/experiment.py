"""Deterministic local planning and audited single-session collection workflow."""

from __future__ import annotations

import json
import random
import resource
import threading
import time
import urllib.request
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from beyond_handshake.capture import (capture_loopback, features_from_server_events,
                                      join_and_aggregate, tshark_extract)
from beyond_handshake.client import run_curl_cffi, run_firefox, run_stdlib, write_attempt
from beyond_handshake.config import load_server_config
from beyond_handshake.dataset import build_dataset


def plan_experiment(config_path: Path, output_path: Path) -> dict:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("schema_version") != "1.0" or not config.get("experiment_id"):
        raise ValueError("experiment config needs schema_version 1.0 and experiment_id")
    seed = int(config.get("seed", 0))
    repeats = int(config.get("repeats_per_client_partition", 1))
    if not 1 <= repeats <= 1000:
        raise ValueError("repeats_per_client_partition must be in [1, 1000]")
    clients = config.get("clients", [])
    if not clients:
        raise ValueError("at least one client must be configured")
    episodes = []
    for client in clients:
        if client.get("adapter") not in {"firefox", "stdlib", "curl-cffi"}:
            raise ValueError(f"unsupported adapter in plan: {client.get('adapter')}")
        if client.get("execution_stack") not in {"browser", "browserless"}:
            raise ValueError("client execution_stack must be browser or browserless")
        if not client.get("client_family") or not client.get("partitions"):
            raise ValueError("each client needs client_family and partitions")
        for partition in client["partitions"]:
            if partition not in {"train", "validation"}:
                raise ValueError("collection plan only permits train/validation; final test stays sealed")
            for repeat in range(repeats):
                identity = f"{config['experiment_id']}:{client['name']}:{partition}:{repeat}"
                session_id = uuid.uuid5(uuid.NAMESPACE_URL, identity).hex
                episode = {"episode_id": uuid.uuid5(uuid.NAMESPACE_DNS, identity).hex,
                           "session_id": session_id, "client_name": client["name"],
                           "adapter": client["adapter"], "client_family": client["client_family"],
                           "execution_stack": client["execution_stack"],
                           "controller": client.get("controller", "script"),
                           "profile": client.get("profile"), "partition": partition,
                           "repeat": repeat, "task_seed": random.Random(identity).randrange(2**31),
                           "task_id": config.get("task_id", "catalog-search-detail-save-v1"),
                           "profile_group_id": uuid.uuid5(uuid.NAMESPACE_OID, identity).hex,
                           "capture_block_id": f"{config['experiment_id']}:{partition}:{repeat}"}
                episodes.append(episode)
    random.Random(seed).shuffle(episodes)
    _validate_plan_partitions(episodes)
    # Each repeat number is the intended capture block; block sequence is randomized by the frozen seed.
    document = {"schema_version": "experiment-plan/1", "experiment_id": config["experiment_id"],
                "seed": seed, "config_sha256": _sha256(config_path), "config": config,
                "planned_at_utc": datetime.now(UTC).isoformat(), "episodes": episodes,
                "reserved_test": config.get("reserved_test", {"status": "not_collected"})}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return document


def _validate_plan_partitions(episodes: list[dict]) -> None:
    parts: dict[str, set[str]] = {}
    families: dict[str, set[str]] = {}
    for episode in episodes:
        parts.setdefault(episode["partition"], set()).add(episode["execution_stack"])
        if episode["execution_stack"] == "browserless":
            families.setdefault(episode["client_family"], set()).add(episode["partition"])
    for partition in ("train", "validation"):
        if parts.get(partition) != {"browser", "browserless"}:
            raise ValueError(f"planned {partition} partition must include browser and browserless sessions")
    leaked = [family for family, memberships in families.items() if len(memberships) > 1]
    if leaked:
        raise ValueError(f"browserless client families cross partitions: {leaked}")


def collect_plan(plan_path: Path, output_dir: Path, server_config_path: Path) -> dict:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("schema_version") != "experiment-plan/1":
        raise ValueError("unsupported experiment plan")
    config = plan["config"]
    server_config = load_server_config(server_config_path)
    event_file = _active_event_file(server_config.logging.output_dir)
    origin = config.get("origin", f"https://localhost:{server_config.listen_port}")
    ca_file = Path(config.get("ca_file", server_config.tls.cert.parent / "ca.pem"))
    timeout = float(config.get("task_deadline_seconds", 45))
    capture_seconds = float(config.get("capture_seconds", 5))
    run_dir = output_dir / plan["experiment_id"]
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "captures").mkdir()
    states_path = run_dir / "lifecycle.jsonl"
    results_path = run_dir / "episodes.jsonl"
    labels = []
    outcomes = []
    for episode in plan["episodes"]:
        transition = []

        def record(state: str, **details: object) -> None:
            row = {"episode_id": episode["episode_id"], "session_id": episode["session_id"],
                   "state": state, "ts_wall_ns": time.time_ns(), **details}
            transition.append(row)
            with states_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")

        record("planned")
        task = _register_task(server_config.control_port, episode["session_id"], episode["task_seed"])
        record("prepared", workload_id=task.get("task", {}).get("workload_id"))
        capture_result: dict = {}
        capture_error: list[str] = []
        capture_done = threading.Event()

        def capture_worker() -> None:
            try:
                capture_result.update(capture_loopback(server_config.listen_port, capture_seconds,
                                                       run_dir / "captures"))
            except Exception as exc:
                capture_error.append(f"{type(exc).__name__}: {exc}")
            finally:
                capture_done.set()

        capture_thread = threading.Thread(target=capture_worker, name="bh-loopback-capture", daemon=True)
        capture_thread.start()
        time.sleep(0.5)
        record("capture_ready", status="capturing" if not capture_done.is_set() else "capture_unavailable")
        record("running")
        cpu_start = time.process_time_ns()
        rss_before = _rss_bytes()
        started = time.time_ns()
        try:
            adapter = episode["adapter"]
            if adapter == "firefox":
                attempt = run_firefox(episode["session_id"], origin, ca_file, timeout,
                                      server_config.control_port)
            elif adapter == "stdlib":
                attempt = run_stdlib(episode["session_id"], origin, ca_file, timeout,
                                     server_config.control_port)
            else:
                if not episode.get("profile"):
                    raise ValueError("curl-cffi plan entry must declare profile")
                attempt = run_curl_cffi(episode["session_id"], origin, ca_file, timeout,
                                        episode["profile"], server_config.control_port)
        except Exception as exc:
            # A setup error remains a visible attempt and never vanishes from the schedule.
            from beyond_handshake.client import ExecutionResult

            now = time.time_ns()
            attempt = ExecutionResult(episode["episode_id"], episode["session_id"], episode["adapter"],
                "unknown", episode["client_family"], "unresolved", episode.get("profile"), None,
                episode["controller"], started, now, False, failure_category="setup_failure",
                error=f"{type(exc).__name__}: {exc}")
        cpu_ns = time.process_time_ns() - cpu_start
        rss_after = _rss_bytes()
        record("draining")
        capture_thread.join(timeout=capture_seconds + 12)
        if capture_thread.is_alive():
            capture_error.append("TimeoutError: capture worker did not stop")
        record("finalized", capture_status=capture_result.get("status", "failed"),
               task_success=attempt.task_success)
        attempt_path = write_attempt(attempt, run_dir / "attempts")
        outcome = {"episode": episode, "attempt": asdict(attempt),
                   "attempt_record": str(attempt_path), "event_file": str(event_file),
                   "capture": capture_result or {"status": "unavailable", "error": "; ".join(capture_error)},
                   "cost": {"wall_ns": attempt.end_wall_ns - attempt.start_wall_ns,
                            "orchestrator_cpu_ns": cpu_ns, "rss_before_bytes": rss_before,
                            "rss_after_bytes": rss_after,
                            "memory_peak_bytes": None,
                            "memory_method": "unavailable; no per-session child process accounting"}}
        outcomes.append(outcome)
        labels.append({"session_id": episode["session_id"], "execution_stack": episode["execution_stack"],
                       "client_family": episode["client_family"], "controller": episode["controller"],
                       "partition": episode["partition"], "task_id": episode["task_id"],
                       "profile_group_id": episode["profile_group_id"],
                       "capture_block_id": episode["capture_block_id"],
                       "task_success": attempt.task_success,
                       "attempt_status": "complete" if attempt.error is None else "failed"})
        with results_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(outcome, sort_keys=True) + "\n")
        record("validated", outcome="task_success" if attempt.task_success else "attempt_failed",
               capture="captured" if capture_result.get("status") == "captured" else "not_captured")
    labels_path = run_dir / "labels.json"
    labels_path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
    event_features_path = run_dir / "event-features.jsonl"
    feature_manifest = features_from_server_events(event_file, event_features_path)
    packet_manifest, join_manifests, joined_rows = _extract_and_join_captures(outcomes, event_file, run_dir)
    event_rows = [json.loads(line) for line in event_features_path.read_text(encoding="utf-8").splitlines()
                  if line.strip()]
    combined_rows = _combine_feature_sources(joined_rows, event_rows)
    combined_features_path = run_dir / "features.jsonl"
    combined_features_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n"
                                                 for row in combined_rows), encoding="utf-8")
    dataset_manifest = build_dataset(combined_features_path, labels_path, run_dir / "dataset")
    split_manifest = {"schema_version": "grouped-split/1", "seed": plan["seed"],
        "config_sha256": plan["config_sha256"], "plan_sha256": _sha256(plan_path),
        "train_session_ids": sorted(r["session_id"] for r in labels if r["partition"] == "train"),
        "validation_session_ids": sorted(r["session_id"] for r in labels if r["partition"] == "validation"),
        "test_session_ids": [], "reserved_test": plan.get("reserved_test"),
        "browserless_family_assignment": {family: sorted({r["partition"] for r in labels
            if r["client_family"] == family and r["execution_stack"] == "browserless"})
            for family in sorted({r["client_family"] for r in labels if r["execution_stack"] == "browserless"})},
        "dataset_features_sha256": _sha256(run_dir / "dataset" / "features.csv"),
        "dataset_labels_sha256": _sha256(run_dir / "dataset" / "labels.csv"),
        "split_rationale": "browserless client families are held out between train and validation; real-browser negatives occur in both"}
    (run_dir / "split-manifest.json").write_text(json.dumps(split_manifest, indent=2) + "\n", encoding="utf-8")
    manifest = {"schema_version": "collection-run/1", "experiment_id": plan["experiment_id"],
                "plan_sha256": _sha256(plan_path), "event_file": str(event_file),
                "event_features": feature_manifest, "dataset": dataset_manifest,
                "packet_extractions": packet_manifest, "packet_joins": join_manifests,
                "joined_packet_connection_count": len(joined_rows),
                "event_only_connection_count": sum(row.get("feature_source") == "server-events-only"
                                                    for row in combined_rows),
                "split_manifest": "split-manifest.json",
                "attempt_count": len(outcomes),
                "successful_task_count": sum(o["attempt"]["task_success"] for o in outcomes),
                "capture_count": sum(o["capture"].get("status") == "captured" for o in outcomes),
                "capture_failure_reasons": [o["capture"].get("error") for o in outcomes
                                            if o["capture"].get("status") != "captured"],
                "limitations": ["event-only features retained if packet capture lacks permission",
                                "local development data; not a representative research cohort"]}
    (run_dir / "collection-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _extract_and_join_captures(outcomes: list[dict], event_file: Path, run_dir: Path) -> tuple[list[dict], list[dict], list[dict]]:
    """Extract each episode capture and join flows to server connections; preserve all failures."""
    packet_dir = run_dir / "packet-observations"
    extraction_reports, join_reports, joined_rows = [], [], []
    for outcome in outcomes:
        capture = outcome.get("capture", {})
        if capture.get("status") != "captured" or not capture.get("capture_path"):
            continue
        episode_id = outcome["episode"]["episode_id"]
        packet_path = packet_dir / f"{episode_id}.tsv"
        joined_path = packet_dir / f"{episode_id}.joined.jsonl"
        try:
            extraction = tshark_extract(Path(capture["capture_path"]), packet_path)
            joined = join_and_aggregate(packet_path, event_file, joined_path)
            extraction_reports.append({"episode_id": episode_id, **extraction})
            join_reports.append({"episode_id": episode_id, **joined})
            joined_rows.extend(json.loads(line) for line in joined_path.read_text(encoding="utf-8").splitlines()
                               if line.strip())
        except (OSError, RuntimeError, ValueError) as exc:
            extraction_reports.append({"episode_id": episode_id, "status": "failed",
                                       "error": f"{type(exc).__name__}: {exc}"})
    return extraction_reports, join_reports, joined_rows


def _combine_feature_sources(joined_rows: list[dict], event_rows: list[dict]) -> list[dict]:
    """Use packet+endpoint features for joined connections; event fallback for the rest."""
    joined_connection_ids = {row.get("connection_id") for row in joined_rows}
    combined = [{**row, "feature_source": "packet-and-server-events"} for row in joined_rows]
    combined.extend(row for row in event_rows if row.get("connection_id") not in joined_connection_ids)
    return combined


def _register_task(control_port: int, session_id: str, seed: int) -> dict:
    request = urllib.request.Request(f"http://127.0.0.1:{control_port}/sessions",
        data=json.dumps({"session_id": session_id, "seed": seed}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def _active_event_file(output_dir: Path) -> Path:
    manifests = list(output_dir.glob("*/manifest.json"))
    active = []
    for path in manifests:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if value.get("status") == "partial":
            active.append(path.parent / "events.jsonl")
    if not active:
        raise RuntimeError("no active server event run found")
    if len(active) == 1:
        return active[0]
    # A crashed server leaves a partial manifest behind. The current server is the
    # latest-started partial run; only that process can own the configured port.
    return max(active, key=lambda path: json.loads((path.parent / "manifest.json").read_text(
        encoding="utf-8")).get("started_wall_ns", 0))


def _rss_bytes() -> int | None:
    try:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux reports KiB; macOS reports bytes. This project is Linux-first.
        return int(value * 1024)
    except (AttributeError, OSError, ValueError):
        return None


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
