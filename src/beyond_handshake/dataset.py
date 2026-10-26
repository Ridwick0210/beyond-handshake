"""Label-separated dataset assembly and an auditable categorical NB baseline."""

from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

FORBIDDEN = {"session_id", "run_id", "connection_id", "tcp_stream", "client_family", "execution_stack",
             "controller", "partition", "task_success", "task_id", "capture_quality", "ip", "port"}
NUMERIC_CONNECTION_FIELDS = ("tcp_packet_count", "tcp_client_to_server_packets", "tcp_flow_duration_seconds",
                             "tcp_initial_window", "tcp_mss", "tcp_window_scale", "h2_request_count")
CATEGORICAL_CONNECTION_FIELDS = ("endpoint_tls_version", "endpoint_alpn", "tls_handshake_types",
                                 "tls_offered_versions", "tls_cipher_suites_order",
                                 "tls_extension_types_order", "tls_alpn_offers", "tcp_syn_options_order",
                                 "h2_inbound_settings_order", "h2_inbound_frame_types", "h2_header_names_order")
ALLOWED_FEATURES = {"connection_count", *{name + "_mean" for name in NUMERIC_CONNECTION_FIELDS},
                    *CATEGORICAL_CONNECTION_FIELDS}
TLS_FEATURES = {"endpoint_tls_version", "endpoint_alpn", "tls_handshake_types", "tls_offered_versions",
                "tls_cipher_suites_order", "tls_extension_types_order", "tls_alpn_offers"}
H2_FEATURES = {"h2_inbound_settings_order", "h2_inbound_frame_types", "h2_header_names_order",
               "h2_request_count_mean"}
FEATURE_GROUPS = {"tls_only": TLS_FEATURES, "tls_plus_h2": TLS_FEATURES | H2_FEATURES,
                  "full": ALLOWED_FEATURES}


def build_dataset(features_jsonl: Path, labels_json: Path, output_dir: Path) -> dict:
    """Aggregate joined connections to sessions and write separate feature/label tables."""
    labels_raw = json.loads(labels_json.read_text(encoding="utf-8"))
    labels = {row["session_id"]: row for row in labels_raw}
    if len(labels) != len(labels_raw):
        raise ValueError("labels contain duplicate session_id values")
    for sid, label in labels.items():
        if label.get("execution_stack") not in {"browser", "browserless"}:
            raise ValueError(f"{sid}: execution_stack must be browser or browserless")
        if not label.get("client_family") or label.get("partition") not in {"train", "validation", "test"}:
            raise ValueError(f"{sid}: client_family and train/validation/test partition are required")
    family_partitions = defaultdict(set)
    group_partitions = defaultdict(set)
    for row in labels.values():
        if row["execution_stack"] == "browserless":
            family_partitions[row["client_family"]].add(row["partition"])
        for group_name in ("participant_id", "profile_group_id", "capture_block_id", "pair_id"):
            if row.get(group_name):
                group_partitions[(group_name, row[group_name])].add(row["partition"])
    split_leaks = [family for family, parts in family_partitions.items() if len(parts) > 1]
    if split_leaks:
        raise ValueError(f"browserless client families cross partitions: {split_leaks}")
    group_leaks = [key for key, parts in group_partitions.items() if len(parts) > 1]
    if group_leaks:
        raise ValueError(f"dependent groups cross partitions: {group_leaks}")
    per_session = defaultdict(list)
    source_counts = defaultdict(Counter)
    for line in features_jsonl.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        for sid in row.get("session_ids", []):
            if sid in labels:
                per_session[sid].append(row["features"])
                source_counts[sid][row.get("feature_source", "unknown")] += 1
    output_dir.mkdir(parents=True, exist_ok=True)
    feature_rows, label_rows, coverage_rows = [], [], []
    for sid, label in labels.items():
        conns = per_session.get(sid, [])
        if not conns:
            continue
        # Feature allowlist is explicit and contains only observation values, never registry metadata.
        row = {"session_id": sid, "connection_count": len(conns)}
        for field in NUMERIC_CONNECTION_FIELDS:
            vals = [c[field] for c in conns if c.get(field) is not None]
            row[field + "_mean"] = sum(vals) / len(vals) if vals else None
        for field in CATEGORICAL_CONNECTION_FIELDS:
            values = [c.get(field) for c in conns if c.get(field) not in (None, [], "")]
            row[field] = json.dumps(values, sort_keys=True, separators=(",", ":")) if values else "<missing>"
        feature_rows.append(row)
        counts = source_counts[sid]
        coverage_rows.append({"session_id": sid,
                              "packet_connection_count": counts["packet-and-server-events"],
                              "event_only_connection_count": counts["server-events-only"],
                              "unknown_source_connection_count": counts["unknown"],
                              "packet_complete": counts["packet-and-server-events"] == len(conns)})
        label_rows.append({"session_id": sid, "client_family": label["client_family"],
                           "execution_stack": label["execution_stack"], "partition": label["partition"],
                           "imitation_stage": label.get("imitation_stage"),
                           "controller": label.get("controller", "unknown"),
                           "task_id": label.get("task_id", "unknown"),
                           "participant_id": label.get("participant_id", ""),
                           "profile_group_id": label.get("profile_group_id", ""),
                           "capture_block_id": label.get("capture_block_id", ""),
                           "pair_id": label.get("pair_id", "")})
    if not feature_rows:
        raise ValueError("no sessions in labels matched joined feature rows")
    _write_csv(output_dir / "features.csv", feature_rows)
    _write_csv(output_dir / "labels.csv", label_rows)
    _write_csv(output_dir / "coverage.csv", coverage_rows)
    source_totals = Counter()
    for counts in source_counts.values():
        source_totals.update(counts)
    coverage_by_cohort: dict[tuple[str, str, str], dict[str, int]] = {}
    for row in coverage_rows:
        label = labels[row["session_id"]]
        cohort = (label["partition"], label["execution_stack"], label["client_family"])
        counts = coverage_by_cohort.setdefault(cohort, {"sessions": 0, "packet_complete_sessions": 0,
                                                        "packet_connections": 0, "event_only_connections": 0})
        counts["sessions"] += 1
        counts["packet_complete_sessions"] += int(row["packet_complete"])
        counts["packet_connections"] += row["packet_connection_count"]
        counts["event_only_connections"] += row["event_only_connection_count"]
    manifest = {"schema_version": "session-dataset/1", "row_count": len(feature_rows),
                "matched_session_count": sum(bool(per_session.get(sid)) for sid in labels),
                "unmatched_sessions": [sid for sid in labels if not per_session.get(sid)],
                "features_path": "features.csv", "labels_path": "labels.csv",
                "coverage_path": "coverage.csv", "source_connection_counts": dict(source_totals),
                "packet_complete_session_count": sum(row["packet_complete"] for row in coverage_rows),
                "coverage_by_cohort": [{"partition": key[0], "execution_stack": key[1],
                                        "client_family": key[2], **value}
                                       for key, value in sorted(coverage_by_cohort.items())],
                "joined_features_sha256": _sha256(features_jsonl), "label_registry_sha256": _sha256(labels_json),
                "label_feature_separation": True, "family_split_leaks": split_leaks}
    (output_dir / "dataset-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def evaluate_naive_bayes(dataset_dir: Path, output: Path) -> dict:
    """Fit a categorical NB baseline on train; report only the held-out family test partition."""
    with (dataset_dir / "features.csv").open(encoding="utf-8", newline="") as stream:
        features = {r["session_id"]: r for r in csv.DictReader(stream)}
    with (dataset_dir / "labels.csv").open(encoding="utf-8", newline="") as stream:
        labels = list(csv.DictReader(stream))
    if set(features) != {r["session_id"] for r in labels}:
        raise ValueError("feature and label session IDs do not match")
    observed_columns = set(next(iter(features.values()))) - {"session_id"}
    if not observed_columns <= ALLOWED_FEATURES:
        raise ValueError(f"feature table has unregistered fields: {sorted(observed_columns - ALLOWED_FEATURES)}")
    train = [r for r in labels if r["partition"] == "train"]
    test = [r for r in labels if r["partition"] == "test"]
    family_partitions = defaultdict(set)
    group_partitions = defaultdict(set)
    for row in labels:
        if row["execution_stack"] == "browserless":
            family_partitions[row["client_family"]].add(row["partition"])
        for group_name in ("participant_id", "profile_group_id", "capture_block_id", "pair_id"):
            if row.get(group_name):
                group_partitions[(group_name, row[group_name])].add(row["partition"])
    if any(len(parts) > 1 for parts in family_partitions.values()):
        raise ValueError("browserless client family leakage across partitions")
    if any(len(parts) > 1 for parts in group_partitions.values()):
        raise ValueError("dependent group leakage across partitions")
    if not train or not test or {r["execution_stack"] for r in train} != {"browser", "browserless"}:
        raise ValueError("need train and test rows, and both execution_stack classes in train")
    comparisons, full_predictions = {}, []
    for group, allowed in FEATURE_GROUPS.items():
        columns = sorted(observed_columns & allowed)
        train_counts = Counter(r["execution_stack"] for r in train)
        vocab = {col: {str(features[r["session_id"]].get(col) or "<missing>") for r in train} | {"<UNK>"}
                 for col in columns}
        cond: dict[str, dict[str, Counter]] = {c: {col: Counter() for col in columns} for c in train_counts}
        for label in train:
            sid, category = label["session_id"], label["execution_stack"]
            for col in columns:
                value = str(features[sid].get(col) or "<missing>")
                cond[category][col][value] += 1

        def score(sid: str, category: str) -> float:
            value = math.log(train_counts[category] / sum(train_counts.values()))
            for col in columns:
                item = str(features[sid].get(col) or "<missing>")
                if item not in vocab[col]:
                    item = "<UNK>"
                value += math.log((cond[category][col][item] + 1) /
                                  (train_counts[category] + len(vocab[col])))
            return value

        predictions = []
        for row in test:
            sid = row["session_id"]
            predicted = max(train_counts, key=lambda c: score(sid, c))
            predictions.append({"session_id": sid, "actual": row["execution_stack"], "predicted": predicted,
                                "score_browser": score(sid, "browser"),
                                "score_browserless": score(sid, "browserless")})
        tp = sum(p["actual"] == p["predicted"] == "browserless" for p in predictions)
        tn = sum(p["actual"] == p["predicted"] == "browser" for p in predictions)
        fp = sum(p["actual"] == "browser" and p["predicted"] == "browserless" for p in predictions)
        fn = sum(p["actual"] == "browserless" and p["predicted"] == "browser" for p in predictions)
        comparisons[group] = {"feature_columns": columns, "confusion": {"tn_browser": tn,
            "fp_browser_as_browserless": fp, "fn_browserless_as_browser": fn, "tp_browserless": tp},
            "accuracy": (tp + tn) / len(test),
            "browserless_recall": tp / (tp + fn) if tp + fn else None,
            "browser_false_positive_rate": fp / (fp + tn) if fp + tn else None}
        if group == "full":
            full_predictions = predictions
    full = comparisons["full"]
    report = {"schema_version": "baseline-evaluation/1", "model": "categorical-naive-bayes",
              "test_family_holdout": True, "train_count": len(train), "test_count": len(test),
              "features_sha256": _sha256(dataset_dir / "features.csv"),
              "labels_sha256": _sha256(dataset_dir / "labels.csv"),
              "common_test_cohort_for_all_groups": True, "comparisons": comparisons,
              "feature_columns": full["feature_columns"], "confusion": full["confusion"],
              "accuracy": full["accuracy"], "browserless_recall": full["browserless_recall"],
              "browser_false_positive_rate": full["browser_false_positive_rate"],
              "limitations": ["engineering baseline only", "no uncertainty intervals", "test set must remain untouched"]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    _write_csv(output.with_suffix(".predictions.csv"), full_predictions)
    return report
