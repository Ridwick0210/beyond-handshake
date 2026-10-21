"""Describe what this pilot can and cannot verify about client profile fidelity."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


def fidelity_report(features_path: Path, labels_path: Path, output_path: Path) -> dict:
    with features_path.open(encoding="utf-8", newline="") as stream:
        features = {row["session_id"]: row for row in csv.DictReader(stream)}
    labels = list(json.loads(labels_path.read_text(encoding="utf-8")))
    dimensions = ("endpoint_tls_version", "endpoint_alpn", "h2_inbound_settings_order",
                  "h2_inbound_frame_types", "h2_header_names_order")
    by_client: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for label in labels:
        row = features.get(label["session_id"])
        if row is None:
            continue
        client = label["client_family"]
        for dimension in dimensions:
            value = row.get(dimension)
            if value not in (None, "", "<missing>"):
                by_client[client][dimension][value] += 1
    comparisons = []
    for actual, profile, expected_target in (
        ("mozilla-firefox", "curl-impersonate", "Chrome 150 (curl-cffi profile target)"),):
        actual_features = by_client.get(actual, {})
        profile_features = by_client.get(profile, {})
        details = []
        for dimension in dimensions:
            left, right = actual_features.get(dimension, Counter()), profile_features.get(dimension, Counter())
            left_values, right_values = set(left), set(right)
            if not left_values or not right_values:
                status = "not_observed"
            elif left_values == right_values:
                status = "matched"
            else:
                status = "mismatched"
            details.append({"component": dimension, "status": status,
                            "actual_browser_values": dict(left), "impersonator_values": dict(right),
                            "interpretation": "exploratory cross-client comparison; not a target-profile fidelity test"})
        comparisons.append({"actual_client_family": actual, "impersonator_family": profile,
                            "claimed_target": expected_target, "target_browser_available": False,
                            "overall_status": "approximate_not_verified",
                            "components": details,
                            "reason": "No real Chrome 150 executable was available to compare against the impersonation profile."})
    report = {"schema_version": "client-fidelity/1", "comparisons": comparisons,
              "feature_source": "server-events-only",
              "not_observed": ["ClientHello cipher/extension order", "TCP SYN options", "GREASE behavior",
                               "wire-level H2 frame ordering before endpoint parsing"],
              "interpretation": "These observations verify negotiation and endpoint-visible structure, not full browser equivalence."}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
