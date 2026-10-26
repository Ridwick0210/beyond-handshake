#!/usr/bin/env python3
"""Summarize paired I2/I3 pilot costs from recorded attempts and loopback PCAPs.

The figure is a development diagnostic. Captured frame bytes include transport
overhead and are not application payload bytes; CPU and memory are not measured.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path


def captured_bytes(path: Path) -> int:
    result = subprocess.run(
        ["tshark", "-r", str(path), "-T", "fields", "-e", "frame.len"],
        capture_output=True, text=True, check=True,
    )
    return sum(int(line) for line in result.stdout.splitlines() if line.strip())


def paired_costs(episodes_path: Path) -> dict:
    pairs: dict[tuple[str, str], dict[int, dict]] = defaultdict(dict)
    for line in episodes_path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        episode, attempt, capture = row["episode"], row["attempt"], row["capture"]
        stage = episode.get("imitation_stage")
        if episode["adapter"] not in {"curl-cffi", "go-tls-client"} or stage not in (2, 3):
            continue
        if not attempt["task_success"] or capture.get("status") != "captured":
            raise ValueError(f"failed task/capture in pair {episode['pair_id']}")
        key = (episode["client_family"], episode["pair_id"])
        if stage in pairs[key]:
            raise ValueError(f"duplicate stage in pair {episode['pair_id']}")
        pairs[key][stage] = {
            "wall_ms": (attempt["end_wall_ns"] - attempt["start_wall_ns"]) / 1_000_000,
            "captured_bytes": captured_bytes(Path(capture["capture_path"])),
        }
    by_family: dict[str, list[dict]] = defaultdict(list)
    for (family, pair_id), stages in pairs.items():
        if set(stages) != {2, 3}:
            raise ValueError(f"incomplete I2/I3 pair {pair_id}")
        by_family[family].append({
            "wall_ms": stages[3]["wall_ms"] - stages[2]["wall_ms"],
            "captured_bytes": stages[3]["captured_bytes"] - stages[2]["captured_bytes"],
        })
    if not by_family:
        raise ValueError("no paired I2/I3 observations")
    return {family: {
        "pairs": len(deltas),
        "mean_i3_minus_i2_wall_ms": statistics.mean(row["wall_ms"] for row in deltas),
        "mean_i3_minus_i2_captured_bytes": statistics.mean(row["captured_bytes"] for row in deltas),
        "deltas": deltas,
    } for family, deltas in sorted(by_family.items())}


def plot_costs(summary: dict, path: Path) -> None:
    """Plot paired differences and their means using the installed gnuplot."""
    families = list(summary)
    if len(families) != 2:
        raise ValueError("cost figure expects exactly two client families")
    positions = {families[0]: 1, families[1]: 13}
    colors = {families[0]: "#0072B2", families[1]: "#D55E00"}
    blocks = []
    for metric in ("captured_bytes", "wall_ms"):
        for family in families:
            start = positions[family]
            blocks.append("".join(f"{start + index} {row[metric]:.6f}\n"
                                  for index, row in enumerate(summary[family]["deltas"])) + "e\n")
        for family in families:
            start = positions[family]
            mean = statistics.mean(row[metric] for row in summary[family]["deltas"])
            blocks.append(f"{start - 0.5} {mean:.6f}\n{start + len(summary[family]['deltas']) - 0.5} {mean:.6f}\ne\n")
    script = f"""
set terminal svg size 1100,440 dynamic font 'sans,12'
set output {json.dumps(str(path.resolve()))}
set multiplot layout 1,2 title 'Stage 3 minus Stage 2: paired development costs'
set border 3
set grid ytics
set xrange [0:23]
set xtics ({json.dumps(families[0])} 5.5, {json.dumps(families[1])} 17.5)
set zeroaxis
set key top left
set ylabel 'Captured frame bytes per attempt'
plot '-' using 1:2 with points pt 7 ps 0.8 lc rgb '{colors[families[0]]}' title 'I3 - I2 per pair', \
     '-' using 1:2 with points pt 7 ps 0.8 lc rgb '{colors[families[1]]}' notitle, \
     '-' using 1:2 with lines lw 3 lc rgb '{colors[families[0]]}' title 'family mean', \
     '-' using 1:2 with lines lw 3 lc rgb '{colors[families[1]]}' notitle
{''.join(blocks[:4])}
set ylabel 'Client task wall time difference (ms)'
plot '-' using 1:2 with points pt 7 ps 0.8 lc rgb '{colors[families[0]]}' notitle, \
     '-' using 1:2 with points pt 7 ps 0.8 lc rgb '{colors[families[1]]}' notitle, \
     '-' using 1:2 with lines lw 3 lc rgb '{colors[families[0]]}' notitle, \
     '-' using 1:2 with lines lw 3 lc rgb '{colors[families[1]]}' notitle
{''.join(blocks[4:])}
unset multiplot
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["gnuplot"], input=script, text=True, check=True, capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--episodes", type=Path, required=True)
    parser.add_argument("--plot", type=Path)
    args = parser.parse_args()
    summary = paired_costs(args.episodes)
    if args.plot:
        plot_costs(summary, args.plot)
    print(json.dumps({family: {key: value for key, value in result.items() if key != "deltas"}
                      for family, result in summary.items()}, indent=2))


if __name__ == "__main__":
    main()
