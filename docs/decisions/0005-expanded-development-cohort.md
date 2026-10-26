# Decision 0005 — Expand the local development cohort

**Date:** 2026-10-26 (Asia/Kolkata)

## Decision

Collect a new, separate 100-episode development cohort under `local-dev-cross-layer-v3`. The primary label remains real browser stack versus browserless client. Each episode runs the same deterministic catalog task against the same loopback TLS endpoint. The planner randomizes the schedule using seed `20261026` and assigns all partitions before collection.

| Partition | Browser stack | Browserless families | Planned episodes |
|---|---|---|---:|
| Train | Firefox, 20 | Python stdlib, 20; Go stdlib, 20 | 60 |
| Validation | Firefox, 20 | curl-cffi `chrome150`, 20 | 40 |

The curl profile is the development strong-impersonation condition. Go stdlib is an independently implemented ordinary client. The final-test family remains reserved and uncollected. Repetition increases the local development sample but does not add a second browser implementation, task, operating system, or network environment. Validation figures remain development estimates.

The `bh experiment develop` command checks capture permissions and adapter availability, starts the local server, generates the frozen plan, collects sessions with per-episode PCAPs, and trains TLS-only, TLS-plus-HTTP/2, and full-feature logistic regression and random forest baselines only when every planned task succeeds, every capture reports zero drops, and every session has packet-complete joined evidence. A failed gate leaves the raw and derived artifacts for inspection and writes no new model bundles.

## Why this cohort

The corrected 40-session pilot established that the packet join and model pipeline work on one small loopback cohort. This new cohort tests whether adding an ordinary independent Go implementation to training changes the development comparison against the already available curl impersonator. It also exercises collection automation at a larger scale before planning a research cohort with another browser and held-out strong impersonator.

## Limits and next decision

Do not pool these episodes with the earlier pilot as though they were independent environments. Do not tune a final-test threshold using the reserved family. Before research-core collection, secure a matching Chrome browser build, another independently implemented strong impersonator, additional tasks and an independent network path, then freeze a new split and target claim. Dataset and model acceptance remain evidence based.
