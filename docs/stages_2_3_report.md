# Stage 2/3 two-visit development pilot

The corrected local pilot is `local-imitation-stages-2-3-warm-cache-dev-v3`. It compares I2 and I3 on the same two-visit synthetic task. Curl-cffi I2/I3 pairs are in train; Go tls-client I2/I3 pairs are in validation; Firefox appears in both partitions. Each browserless family has 10 paired task seeds. The final test was not collected or read.

## Capture and task evidence

Command: `sg wireshark -c 'UV_CACHE_DIR=/tmp/bh-uv-cache GOCACHE=/tmp/bh-go-tls-build-cache GOMODCACHE=/tmp/bh-go-tls-mod-cache ./scripts/bh experiment develop --config configs/stages_2_3_development.json --output-dir data/interim/stages-2-3-run3 --model-dir artifacts/models/stages-2-3-run3 --server-config configs/server.toml'`.

The run completed in 400.58 seconds. All 60/60 tasks succeeded; 60/60 loopback captures were extracted and joined to endpoint events; 60/60 sessions passed the packet-completeness gate; there were zero event-only fallbacks and zero reported capture drops among 3,127 received packets. Train has 10 Firefox and 20 curl sessions; validation has 10 Firefox and 20 Go tls-client sessions. Captures, attempts, labels, and models remain ignored local artifacts under the stated output directories.

| Client condition | Successful / planned | Discovered references | Network resource fetches | Cache hits |
|---|---:|---:|---:|---:|
| curl-cffi I2 | 10/10 | 0 | 0 | 0 |
| curl-cffi I3 | 10/10 | 80 | 30 | 50 |
| Go tls-client I2 | 10/10 | 0 | 0 | 0 |
| Go tls-client I3 | 10/10 | 80 | 30 | 50 |

Each I3 attempt discovered eight references across two visits, fetched three distinct static assets, and served five references from its in-memory cache. The task's duplicate save/confirmation on visit two is accepted by the local oracle. These counts verify this controlled workload's scripted resource behavior; they do not establish browser cache fidelity.

## Development models and cost

Logistic regression and random forest were fitted for TLS-only (7 features), TLS+H2 (11), and full (19). Every configuration used 30 train and 30 validation sessions and reported `tn=10, fp=0, fn=0, tp=20` at a threshold selected on this same validation set. `test_rows_read=0`. TLS+H2 and full did not improve the validation confusion counts over TLS-only. The scores are uncalibrated; these small, reused validation results are model-selection checks, not detector accuracy estimates.

`python scripts/stage_cost.py --episodes data/interim/stages-2-3-run3/local-imitation-stages-2-3-warm-cache-dev-v3/episodes.jsonl --plot docs/figures/stages_2_3_cost.svg` regenerated the [paired cost figure](figures/stages_2_3_cost.svg). For each family, the script pairs I2/I3 by the planned pair ID, sums `frame.len` over the per-attempt port-8443 PCAP, and compares task wall time. With 10 pairs per family, mean I3−I2 captured bytes were +2,672.5 for curl-cffi and +2,591.6 for Go tls-client; mean client-task wall time differences were +2.97 ms and +2.41 ms, respectively. These are loopback captured frame bytes, including transport overhead, not HTTP payload. The plot displays individual paired differences and means. Client-process CPU and peak memory remain unmeasured, so no CPU-cost claim is made.

The fidelity command compared each browserless family to the available Firefox observations and saved `fidelity-report.json` locally. Both comparisons report `approximate_not_verified`: Firefox is not the targeted Chrome 150 build. The matching Chrome binary, independent profile parity audit, a third held-out strong client family, broader browser/human and task coverage, and final frozen-threshold testing remain outstanding.

## Versioned correction

The first 60-session attempt, `local-imitation-stages-2-3-warm-cache-dev-v2` under `data/interim/stages-2-3-run2/`, passed the packet/task measurement gate and fitted models. Review of its Go I3 resource counts revealed a URL-resolution bug: detail-page relative asset URLs were resolved against `/start`, leaving only start-page resources loaded. Its Go I3 attempts therefore found 4 references, made 2 resource fetches, and had 2 cache hits each. The code was corrected to resolve references against the actual detail-page URL, then recollected under the distinct v3 experiment ID. The v2 artifacts are preserved for audit and are not used for the corrected Stage 3 comparison.
