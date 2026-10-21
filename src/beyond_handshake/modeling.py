"""Transparent Phase 12 baselines; final test partitions are never read."""

from __future__ import annotations

import csv
import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path

from beyond_handshake.dataset import ALLOWED_FEATURES, FEATURE_GROUPS


def train_baselines(dataset_dir: Path, output_dir: Path, max_false_positive_rate: float = 0.05,
                    feature_group: str = "full") -> dict:
    """Fit logistic regression and random forest on train, choose cutoffs on validation only."""
    try:
        import joblib
        import numpy as np
        import pandas as pd
        import sklearn
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.impute import SimpleImputer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder, StandardScaler
    except ImportError as exc:
        raise RuntimeError("Phase 12 requires the optional 'ml' dependencies; run `uv sync --extra ml`") from exc

    features_path, labels_path = dataset_dir / "features.csv", dataset_dir / "labels.csv"
    with features_path.open(encoding="utf-8", newline="") as stream:
        features = {r["session_id"]: r for r in csv.DictReader(stream)}
    with labels_path.open(encoding="utf-8", newline="") as stream:
        labels = list(csv.DictReader(stream))
    if not labels or set(features) != {r["session_id"] for r in labels}:
        raise ValueError("features and labels must have identical nonempty session IDs")
    if feature_group not in FEATURE_GROUPS:
        raise ValueError(f"unknown feature group: {feature_group}")
    _validate_packet_coverage(dataset_dir, labels)
    observed_columns = set(next(iter(features.values()))) - {"session_id"}
    if not observed_columns or not observed_columns <= ALLOWED_FEATURES:
        raise ValueError("feature file contains no registered features or contains forbidden fields")
    registered_columns = sorted(observed_columns & FEATURE_GROUPS[feature_group])
    if not registered_columns:
        raise ValueError(f"feature group {feature_group} has no columns in this dataset")
    train = [r for r in labels if r["partition"] == "train"]
    validation = [r for r in labels if r["partition"] == "validation"]
    if not train or not validation:
        raise ValueError("Phase 12 requires train and validation; final test is not used")
    for rows, name in ((train, "train"), (validation, "validation")):
        if {r["execution_stack"] for r in rows} != {"browser", "browserless"}:
            raise ValueError(f"{name} must contain browser and browserless sessions")
    _validate_group_partitioning(labels)

    all_numeric = [c for c in registered_columns if c.endswith("_mean") or c == "connection_count"]
    excluded_unobserved = [c for c in all_numeric if all(
        features[r["session_id"]].get(c) in (None, "") or math.isnan(float(features[r["session_id"]][c]))
        for r in train)]
    columns = [c for c in registered_columns if c not in excluded_unobserved]
    if not columns:
        raise ValueError("no features have observations in train; cannot fit a model")
    numeric = [c for c in all_numeric if c in columns]
    categorical = [c for c in columns if c not in numeric]
    transform = ColumnTransformer([
        ("numeric", Pipeline([("impute", SimpleImputer(strategy="median", add_indicator=True)),
                              ("scale", StandardScaler())]), numeric),
        ("categorical", Pipeline([("impute", SimpleImputer(strategy="constant", fill_value="<missing>")),
                                  ("onehot", OneHotEncoder(handle_unknown="ignore"))]), categorical),
    ], remainder="drop")
    matrix = {sid: _feature_row(row, registered_columns, all_numeric) for sid, row in features.items()}
    y_train = np.asarray([int(r["execution_stack"] == "browserless") for r in train])
    y_val = np.asarray([int(r["execution_stack"] == "browserless") for r in validation])
    x_train = pd.DataFrame([matrix[r["session_id"]] for r in train], columns=registered_columns)[columns]
    x_val = pd.DataFrame([matrix[r["session_id"]] for r in validation], columns=registered_columns)[columns]
    models = {
        "logistic-regression": LogisticRegression(max_iter=2000, class_weight="balanced", random_state=0),
        "random-forest": RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                                 class_weight="balanced", random_state=0, n_jobs=1),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, estimator in models.items():
        pipeline = Pipeline([("preprocess", transform), ("classifier", estimator)])
        pipeline.fit(x_train, y_train)
        classifier = pipeline.named_steps["classifier"]
        if hasattr(classifier, "predict_proba"):
            scores = pipeline.predict_proba(x_val)[:, 1]
            score_kind = "uncalibrated_positive_class_probability"
        else:
            scores = pipeline.decision_function(x_val)
            score_kind = "decision_score"
        threshold, metrics = _select_threshold(y_val.tolist(), scores.tolist(), max_false_positive_rate)
        bundle_path = output_dir / f"{name}.joblib"
        joblib.dump({"pipeline": pipeline, "feature_columns": columns, "numeric_columns": numeric,
                     "categorical_columns": categorical, "positive_label": "browserless",
                     "threshold": threshold, "score_kind": score_kind,
                     "excluded_unobserved_features": excluded_unobserved,
                     "max_validation_fpr": max_false_positive_rate,
                     "feature_group": feature_group,
                     "sklearn_version": sklearn.__version__, "feature_schema": "session-dataset/1",
                     "features_sha256": _sha256(features_path), "labels_sha256": _sha256(labels_path)},
                    bundle_path)
        roundtrip_scores = score_bundle(bundle_path, x_val)
        if not np.allclose(scores, roundtrip_scores, rtol=1e-12, atol=1e-12):
            raise RuntimeError(f"serialized {name} bundle did not reproduce validation scores")
        results[name] = {"bundle": bundle_path.name, "threshold": threshold,
                         "score_kind": score_kind, "validation": metrics,
                         "bundle_sha256": _sha256(bundle_path)}
        predictions_path = output_dir / f"{name}-validation-predictions.csv"
        with predictions_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["session_id", "actual_browserless", "score", "threshold", "predicted_browserless"])
            writer.writerows((row["session_id"], int(row["execution_stack"] == "browserless"),
                              float(score), threshold, int(float(score) >= threshold))
                             for row, score in zip(validation, scores))
    majority_label = int(sum(y_train) > len(y_train) / 2)
    majority_predictions = [majority_label] * len(y_val)
    protocol_predictions = [int(_alpn_is_non_h2(features[r["session_id"]].get("endpoint_alpn")))
                            for r in validation]
    report = {"schema_version": "phase12-model-selection/1", "created_at_utc": datetime.now(UTC).isoformat(),
              "train_rows": len(train), "validation_rows": len(validation), "test_rows_read": 0,
              "feature_group": feature_group,
              "feature_columns": columns, "excluded_unobserved_features": excluded_unobserved,
              "features_sha256": _sha256(features_path),
              "labels_sha256": _sha256(labels_path), "sklearn_version": sklearn.__version__,
              "threshold_selection": "maximize validation recall subject to validation browser FPR <= cap; ties choose higher threshold",
              "rule_baselines": {
                  "train_majority_class": {"predicted_label": "browserless" if majority_label else "browser",
                      "validation": _confusion_metrics(y_val.tolist(), majority_predictions)},
                  "protocol_rule_non_h2_is_browserless": {"fixed_rule": "ALPN http/1.1 predicts browserless; otherwise browser",
                      "validation": _confusion_metrics(y_val.tolist(), protocol_predictions)}},
              "models": results,
              "limitations": ["development cohort only", "validation metrics are model-selection estimates, not final results",
                              "raw model scores are not calibrated confidence", "holdout test remains sealed"]}
    (output_dir / "model-selection.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def score_bundle(bundle_path: Path, rows) -> list[float]:
    """Score ordered feature records with a trusted local Phase 12 bundle."""
    import joblib
    import numpy as np
    import pandas as pd

    bundle = joblib.load(bundle_path)
    columns = bundle["feature_columns"]
    frame = rows.copy() if isinstance(rows, pd.DataFrame) else pd.DataFrame(rows)
    if list(frame.columns) != columns:
        raise ValueError("feature order/schema differs from the model bundle")
    for col in bundle["numeric_columns"]:
        frame[col] = pd.to_numeric(frame[col], errors="coerce")
    for col in bundle["categorical_columns"]:
        frame[col] = frame[col].fillna("<missing>")
    pipeline = bundle["pipeline"]
    classifier = pipeline.named_steps["classifier"]
    if hasattr(classifier, "predict_proba"):
        return pipeline.predict_proba(frame)[:, 1].astype(float).tolist()
    return np.asarray(pipeline.decision_function(frame), dtype=float).tolist()


def _feature_row(row: dict, columns: list[str], numeric: list[str]) -> dict:
    result = {}
    for col in columns:
        value = row.get(col)
        if col in numeric:
            try:
                result[col] = float(value) if value not in (None, "") else math.nan
            except ValueError:
                result[col] = math.nan
        else:
            if value not in (None, "", "<missing>") and isinstance(value, str) and value.startswith("["):
                try:
                    value = json.dumps(json.loads(value), separators=(",", ":"), sort_keys=True)
                except json.JSONDecodeError:
                    pass
            result[col] = value if value not in (None, "") else "<missing>"
    return result


def _alpn_is_non_h2(value: str | None) -> bool:
    if not value or value == "<missing>":
        return False
    try:
        values = json.loads(value)
        return bool(values) and "h2" not in values
    except json.JSONDecodeError:
        return value != "h2"


def _confusion_metrics(y_true: list[int], predicted: list[int]) -> dict:
    tn = sum(y == 0 and p == 0 for y, p in zip(y_true, predicted))
    fp = sum(y == 0 and p == 1 for y, p in zip(y_true, predicted))
    fn = sum(y == 1 and p == 0 for y, p in zip(y_true, predicted))
    tp = sum(y == 1 and p == 1 for y, p in zip(y_true, predicted))
    return {"n": len(y_true), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def _validate_group_partitioning(labels: list[dict]) -> None:
    families: dict[str, set[str]] = {}
    groups: dict[tuple[str, str], set[str]] = {}
    for row in labels:
        if row["execution_stack"] == "browserless":
            families.setdefault(row["client_family"], set()).add(row["partition"])
        for key in ("participant_id", "profile_group_id", "capture_block_id", "pair_id"):
            if row.get(key):
                groups.setdefault((key, row[key]), set()).add(row["partition"])
    if any(len(p) > 1 for p in families.values()):
        raise ValueError("browserless client family crosses partitions")
    if any(len(p) > 1 for p in groups.values()):
        raise ValueError("participant/profile/block/pair group crosses partitions")


def _validate_packet_coverage(dataset_dir: Path, labels: list[dict]) -> None:
    """Do not let class-correlated capture gaps become predictive missing values."""
    coverage_path = dataset_dir / "coverage.csv"
    if not coverage_path.is_file():
        manifest_path = dataset_dir / "dataset-manifest.json"
        if manifest_path.is_file() and json.loads(manifest_path.read_text(
                encoding="utf-8")).get("coverage_path"):
            raise ValueError("dataset coverage sidecar is missing")
        return  # Legacy synthetic fixtures have no measurement-source sidecar.
    with coverage_path.open(encoding="utf-8", newline="") as stream:
        coverage = {row["session_id"]: row for row in csv.DictReader(stream)}
    fitted = [row for row in labels if row["partition"] in {"train", "validation"}]
    if set(coverage) != {row["session_id"] for row in labels}:
        raise ValueError("coverage and label session IDs differ")
    has_packets = any(int(coverage[row["session_id"]]["packet_connection_count"]) > 0
                      for row in fitted)
    if has_packets:
        incomplete = [row for row in fitted
                      if coverage[row["session_id"]]["packet_complete"] != "True"]
        if incomplete:
            counts = {}
            for row in incomplete:
                key = row["execution_stack"]
                counts[key] = counts.get(key, 0) + 1
            raise ValueError("partial packet coverage across train/validation sessions; "
                             f"incomplete by class: {counts}. Recollect or build an explicit event-only dataset")


def _select_threshold(y_true: list[int], scores: list[float], cap: float) -> tuple[float, dict]:
    if not 0 <= cap <= 1 or len(y_true) != len(scores) or not y_true:
        raise ValueError("invalid threshold selection inputs")
    negatives = sum(y == 0 for y in y_true)
    positives = sum(y == 1 for y in y_true)
    if not negatives or not positives:
        raise ValueError("validation requires both classes")
    candidates = sorted(set(scores) | {math.inf}, reverse=True)
    eligible = []
    for threshold in candidates:
        predicted = [s >= threshold for s in scores]
        fp = sum(p and y == 0 for p, y in zip(predicted, y_true))
        tp = sum(p and y == 1 for p, y in zip(predicted, y_true))
        fpr, recall = fp / negatives, tp / positives
        if fpr <= cap:
            eligible.append((recall, threshold, fp, tp, fpr))
    recall, threshold, fp, tp, fpr = max(eligible, key=lambda x: (x[0], x[1]))
    return threshold, {"n": len(y_true), "tn": negatives - fp, "fp": fp, "fn": positives - tp,
                      "tp": tp, "false_positive_rate": fpr, "recall": recall,
                      "precision": tp / (tp + fp) if tp + fp else None}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest
