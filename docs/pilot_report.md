# Local development pilot report

**Run:** `data/interim/local-dev-cross-layer-v1/` (initial event-only run)
**Date:** 2026-10-22 (Asia/Kolkata)  
**Purpose:** exercise the collection, feature, split, and training pipeline; this is not a research sample.

## Cohort and execution

The frozen plan contains 40 sessions: 20 headless Firefox sessions (10 train, 10 validation), 10 Python standard-library sessions (train), and 10 curl-cffi `chrome150` profile sessions (validation). All 40 task attempts reached the server-side success oracle. Feature and label tables contain 40 matched sessions; feature/label separation is verified. The ordered train and validation session lists and their hashes are in the ignored local artifact `data/interim/local-dev-cross-layer-v1/split-manifest.json`.

The server ran on localhost with TLS 1.3. Firefox negotiated HTTP/2; Python stdlib negotiated HTTP/1.1; curl-cffi `chrome150` negotiated HTTP/2. These client family conditions are confounded with adapter implementation and selected protocol behavior. They cannot support a general browser-versus-automation inference.

## Capture and feature coverage

TShark 4.6.9 is installed and its field inventory was read. All 40 packet-capture attempts failed because this environment cannot access loopback capture interfaces or raw capture privileges. No PCAP exists for this pilot. The dataset therefore contains server-event features only: negotiated TLS version and ALPN plus endpoint-observed H2 settings, frame-type, and header-name sequences. TCP SYN fields and ClientHello cipher/extension/version offers were unavailable and were excluded from modeling as unobserved.

## Fidelity observations

The curl-cffi profile declares Chrome 150 as its emulation target. No real Chrome 150 executable was available, so exact profile fidelity is **not verified**. The exploratory comparison against Firefox 157 found TLS 1.3 and ALPN h2 for both, with differences in initial H2 settings and request-header structure. This is not a browser-target parity test. See the local ignored artifact `data/interim/local-dev-cross-layer-v1/fidelity-report.json` for the full component report.

## Development baseline

Logistic regression and random forest were fit on 20 train sessions and thresholds were selected on 20 validation sessions with a 5% empirical browser FPR cap. Both produced 10/10 browser and 10/10 browserless classifications on validation. The majority-class baseline and a fixed `ALPN != h2` rule each detected 0/10 validation browserless sessions while keeping observed browser FPR at 0/10. There are only 10 observations per validation class, and the held-out class is one curl-cffi implementation/profile. The apparent separation is therefore an implementation/task-specific smoke-test result, not an estimate of population performance, robust FPR, unseen-family transfer, or AI-agent detection. The final test family remains reserved and was not read. See the ignored model selection report under `artifacts/models/local-dev-cross-layer-v1/`.

## Measurement and cost limits

Task wall times and orchestrator CPU deltas are recorded per attempt. Reliable per-client process-tree CPU, peak memory, subprocess count, wire bytes, capture-drop rate, and paired instrumentation-overhead estimates were not obtained. These cost columns must not be compared as if they were complete resource accounting.

## Required work before research collection

1. Run on a host where loopback packet capture is authorized; verify real TShark extraction and joins against Wireshark, including packet loss and SYN/ClientHello correctness.
2. Collect an actual Chrome version matching the impersonation target; compare TLS ClientHello, TCP options, ALPN, and initial H2 settings under a frozen canonicalization policy.
3. Add an independent third browserless implementation family for the reserved final test. Preserve separate real-browser negatives in every partition.
4. Complete grouped feature-family ablations, cut-off-aware prefixes, protocol compatibility and majority baselines, bounded model search, uncertainty estimates, and cost accounting before claiming Phase 12 acceptance.
5. Freeze the protocol, dataset membership, code, preprocessing, threshold, and bundle hashes before opening the reserved family test.
