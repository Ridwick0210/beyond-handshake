# Local capture pilot report

**Date:** 2026-10-22 (Asia/Kolkata)
**Scope:** local development measurement, not final detector evaluation.

## First permission-enabled run

The initial capture run under `data/interim/captured/local-dev-cross-layer-v1/` completed 40/40 task attempts and produced 40 PCAPs. After re-extraction with TShark 4.6.9 and the corrected TCP boolean parser, only 21/40 sessions had both a client SYN and a client-direction ClientHello: 20/20 Firefox, 1/10 curl-impersonate, and 0/10 Python stdlib. The fixed startup delay caused class-correlated missing packet evidence. No packet-feature model was fitted to this mixed cohort; the Phase 12 coverage gate rejects it. See decision 0004.

## Corrected development run

The revised plan `configs/development_experiment_v2.json` produced 40/40 task successes and 40/40 saved PCAPs under `data/interim/captured-v2/local-dev-cross-layer-v2/`. Capture started before the client and stayed active through task completion plus the configured minimum window. The saved dumpcap logs report 2,042 received packets and zero dropped packets across the 40 captures.

The final derived rebuild is `data/interim/captured-v2/local-dev-cross-layer-v2-rebuild-v3/`. Its TShark extraction found one unique, complete server/packet join per planned session: 40/40 with client SYN and ClientHello. The raw `tcp.options` bytes yielded a TCP SYN option order in 40/40 sessions. Its dataset has 40 matched rows, with 10 browser and 10 browserless rows in each of train and validation, and zero event-only fallback rows. The rebuild manifest records capture health, extraction versions, checksums, and per-cohort coverage. Raw PCAPs and model files remain Git-ignored.

## Development models and fidelity

The Phase 12 trainer fit logistic regression and random forest separately for TLS-only, TLS plus HTTP/2, and full feature groups, using the same 20 train and 20 validation sessions in each comparison. All six model/group combinations had validation confusion counts `tn=10, fp=0, fn=0, tp=10` at thresholds selected from validation under the configured 5% empirical browser FPR cap. This is a pipeline result on a very small cohort with different browserless families in train and validation; it is not an estimate of deployment accuracy or low false-positive risk. The final test partition was not opened (`test_rows_read=0`). Local reports and hashed bundles are under `artifacts/models/local-dev-cross-layer-v2-rebuild-v3/`.

The saved fidelity comparison finds observable TLS cipher and extension order differences between Firefox and curl-impersonate. Both negotiated TLS 1.3 and HTTP/2. This is an exploratory cross-family comparison, not a Chrome 150 target-parity test: a matching real Chrome build was unavailable. The full component report is in the ignored rebuild directory.

## Remaining gates

The run does not establish performance against an untouched third browserless family, other browser versions, environments, tasks, or human traffic. It does not validate every TShark field against an independent decoder, quantify collector overhead, provide reliable per-process cost metrics, or complete the preregistered grouped model search and uncertainty analysis. Treat the 40-session run as development evidence only.
