# Expanded local development run (v3)

**Run date:** 2026-10-26 (Asia/Kolkata)
**Target:** browserless client versus real browser network stack
**Status:** development measurement and model pipeline; no final-test result

## Collection and quality

`configs/development_experiment_v3.json` froze 100 randomized episodes before collection. The local automation command was `sg wireshark -c './scripts/bh experiment develop'`. It took 667.19 seconds end to end, including five-second minimum captures, task execution, TShark extraction, joining, quality checks, and training.

| Cohort | Sessions | Task successes | Packet-complete rows |
|---|---:|---:|---:|
| Train: Firefox browser | 20 | 20 | 20 |
| Train: Python stdlib browserless | 20 | 20 | 20 |
| Train: Go stdlib browserless | 20 | 20 | 20 |
| Validation: Firefox browser | 20 | 20 | 20 |
| Validation: curl-cffi `chrome150` browserless | 20 | 20 | 20 |
| Total | 100 | 100 | 100 |

All 100 PCAPs were saved. TShark extraction and socket tuple/time joining produced 100 unique packet and server-event connection rows, with no event-only fallback. Dumpcap reported 4,737 received packets and zero drops across the episode captures. The quality gate passed before training. The dataset manifest records label/feature separation and zero browserless family split leaks.

The run files are ignored local artifacts under `data/interim/captured-v3/local-dev-cross-layer-v3/`. The source PCAPs, server event log, labels, feature tables, collection manifest, and automated development report remain available there. Model bundles and validation prediction tables are ignored under `artifacts/models/local-dev-cross-layer-v3/`.

## Development model result

The trainer fit logistic regression and a 300-tree random forest on 60 train sessions. It selected thresholds on 40 validation sessions under an empirical browser false-positive cap of 5%. For TLS-only, TLS plus HTTP/2, and all registered features, both models produced the same validation counts: 20/20 Firefox classified as browser and 20/20 curl-cffi classified as browserless. The majority-class rule classified all 20 Firefox sessions as browserless; the fixed non-H2 protocol rule missed all 20 curl-cffi sessions. `test_rows_read` was zero for every model group.

| Feature group | Features | Logistic validation TN/FP/FN/TP | Forest validation TN/FP/FN/TP |
|---|---:|---|---|
| TLS only | 7 | 20 / 0 / 0 / 20 | 20 / 0 / 0 / 20 |
| TLS + HTTP/2 | 11 | 20 / 0 / 0 / 20 | 20 / 0 / 0 / 20 |
| Full | 19 | 20 / 0 / 0 / 20 | 20 / 0 / 0 / 20 |

A separate timed rerun of full-feature training on this 100-row dataset took 1.29 seconds wall time and about 172 MiB peak RSS. That time includes Python startup, fitting both models, writing bundles, and scoring validation; it excludes data collection and extraction.

These validation counts show no measured gain from HTTP/2 or TCP features in this cohort: TLS alone separated the observed Firefox and curl configurations. The small sample and one browser build can reflect implementation signatures. Thresholds were selected on these same validation rows, so the displayed rates are model-selection checks, not estimates of deployment accuracy. Zero observed Firefox false positives among 20 validation sessions gives weak precision for a low false-positive claim. The curl profile's Chrome 150 target parity is still unverified against an actual matching Chrome executable.

## Next data needed

1. Add a matching real Chrome build and compare its TLS/H2 observations with curl-cffi `chrome150` before making fidelity claims.
2. Add another independently implemented strong impersonator, then reserve a separate independent family for a locked final test. The ordinary Go `net/http` client already in train is a useful family control but does not fill that role.
3. Add at least one more task and a second measured network path or host. Freeze task and path partitions before collection.
4. Independently verify selected ClientHello and TCP option fields against packet bytes or Wireshark decode; measure process cost with reliable per-client accounting.
5. Only after those conditions are ready, freeze the research collection schedule, models, and threshold; evaluate the untouched test panel once with uncertainty and coverage reporting.
