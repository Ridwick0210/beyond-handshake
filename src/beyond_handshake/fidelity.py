"""Describe what this pilot can and cannot verify about client profile fidelity."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


def fidelity_report(features_path: Path, labels_path: Path, output_path: Path,
                    attempts_path: Path | None = None) -> dict:
    with features_path.open(encoding="utf-8", newline="") as stream:
        features = {row["session_id"]: row for row in csv.DictReader(stream)}
    labels = list(json.loads(labels_path.read_text(encoding="utf-8")))
    packet_dimensions = ("tls_cipher_suites_order", "tls_extension_types_order",
                         "tls_alpn_offers", "tcp_syn_options_order")
    dimensions = (*packet_dimensions, "endpoint_tls_version", "endpoint_alpn",
                  "h2_inbound_settings_order", "h2_inbound_frame_types", "h2_header_names_order")
    by_client: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for label in labels:
        row = features.get(label["session_id"])
        if row is None:
            continue
        client = label["client_family"]
        for dimension in dimensions:
            value = row.get(dimension)
            if value not in (None, "", "<missing>"):
                # Dataset cells contain one value per joined connection. Compare
                # connection observations, not whole-session arrays: a browser may
                # open two connections where an impersonator opens only one.
                try:
                    observations = json.loads(value)
                except json.JSONDecodeError:
                    observations = value
                if not isinstance(observations, list):
                    observations = [observations]
                for observation in observations:
                    by_client[client][dimension][json.dumps(
                        observation, sort_keys=True, separators=(",", ":"))] += 1
    chrome_versions: Counter = Counter()
    chrome_hashes: Counter = Counter()
    if attempts_path is not None:
        for line in attempts_path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            attempt = record.get("attempt", record)
            if attempt.get("client_family") != "google-chrome":
                continue
            chrome_versions[attempt.get("adapter_version", "unknown")] += 1
            for step in attempt.get("steps", []):
                if step.get("chrome_binary_sha256"):
                    chrome_hashes[step["chrome_binary_sha256"]] += 1
    comparisons = []
    comparison_specs = [
        ("mozilla-firefox", "curl-impersonate", "Chrome 150 (curl-cffi profile target)"),
        ("mozilla-firefox", "go-client-family", "Chrome 150 (Go tls-client profile target)"),
    ]
    if "google-chrome" in by_client:
        comparison_specs.extend((
            ("google-chrome", "curl-impersonate", "Chrome 150 (curl-cffi profile target)"),
            ("google-chrome", "go-client-family", "Chrome 150 (Go tls-client profile target)"),
        ))
    for actual, profile, expected_target in comparison_specs:
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
        is_chrome_reference = actual == "google-chrome"
        version_matches = bool(chrome_versions) and all(
            value.startswith("Google Chrome 150.") for value in chrome_versions)
        if is_chrome_reference and not version_matches:
            overall_status = "version_mismatch" if chrome_versions else "not_comparable"
            reason = ("Installed Chrome version differs from the Chrome 150 profile target."
                      if chrome_versions else "Chrome executable version was not recorded in attempts.")
        else:
            overall_status = "approximate_not_verified"
            reason = ("Component observations remain exploratory; full profile parity has not been audited."
                      if is_chrome_reference else
                      "No real Chrome 150 executable was available to compare against the impersonation profile.")
        comparisons.append({"actual_client_family": actual, "impersonator_family": profile,
                            "claimed_target": expected_target,
                            "actual_browser_versions": dict(chrome_versions) if is_chrome_reference else {},
                            "actual_browser_binary_hashes": dict(chrome_hashes) if is_chrome_reference else {},
                            "target_browser_available": is_chrome_reference and version_matches,
                            "overall_status": overall_status,
                            "components": details,
                            "reason": reason})
    observed_packet_dimensions = [dimension for dimension in packet_dimensions
                                  if any(by_client[client].get(dimension) for client in by_client)]
    report = {"schema_version": "client-fidelity/1", "comparisons": comparisons,
              "feature_source": "packet-and-server-events" if observed_packet_dimensions else "server-events-only",
              "observed_packet_dimensions": observed_packet_dimensions,
              "not_observed": [dimension for dimension in packet_dimensions
                               if dimension not in observed_packet_dimensions] +
                              ["GREASE behavior", "wire-level H2 frame ordering before endpoint parsing"],
              "interpretation": "Cross-family differences are exploratory. Chrome 150 target fidelity remains unverified without a matching real browser."}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
