# Implementation progress

**Last updated:** 2026-10-22 (Asia/Kolkata)

This page distinguishes working prototype components from complete requirements in `MASTER_BUILD_DOCUMENT.md`. Components through Phase 12 exist, but acceptance remains evidence-based. No final-test dataset or supported research finding exists.

## Phase 0 — Scope and protocol

- Created the scope decision, experiment protocol, master build document, and pilot configuration.
- Primary target remains browserless HTTP stack versus a real browser network stack. Controller identity is separate metadata; the project cannot infer AI identity or malicious intent.
- The pilot binds only to loopback. The independent control plane also binds only to `127.0.0.1`.

## Phase 1 — Package and environment

- Added the `bh` CLI wrapper, package metadata, locked dependencies, strict TOML config, and `bh doctor` capability reporting.
- Runtime dependency: `h2==4.4.1`. Optional adapter dependency: `curl-cffi==0.16.3` in the `impersonation` extra.
- `uv sync` created `.venv`; the wrapper now uses `.venv` when present.

## Phase 2 — Events and run storage

- Existing schema dataclasses and bounded append-only JSONL writer are active. H2 events now use `stream_id` in the envelope.
- TLS, ordered HTTP header names, request/response timing, task transitions, H2 frame metadata, ordered SETTINGS entries, and observer health events are represented in event logs.
- Header values are redacted by default, including H2 pseudo-header values; `:path` is reduced to a route category. H2 DATA/HPACK payload bytes are not copied into event payloads.
- Generated certificates, captures, event data, and attempts remain ignored by Git.

## Phase 3 — TLS and HTTP/1.1 endpoint

- The localhost TLS server supports HTTP/1.1 and advertises ALPN `h2` and `http/1.1`.
- Keeps the standard-library `ThreadingHTTPServer` implementation from the offline prototype rather than the build document's `asyncio`/`h11` design. This implementation choice is documented in the Phase 0–3 decision record; phase acceptance for the prescribed h11 lifecycle is not claimed.
- Local CA certificate verification succeeded in HTTP/1.1 and h2 clients. A deliberate wrong-CA rejection test is still outstanding.

## Phase 4 — HTTP/2 and structural observation

- Added a single-owner-per-connection `hyper-h2` server path. Each TLS connection's handler thread is the sole owner of its H2 state machine.
- Added a bounded incremental frame observer for both directions. It recognizes the client preface, split/combined frame headers, SETTINGS entries in original order, unknown setting IDs, and ACK frames. It does not decode HPACK itself.
- Inbound H2 header order comes from `hyper-h2` request events with header normalization disabled. Values are redacted according to the config policy.
- Outbound responses are chunked by stream and connection flow-control windows. A deterministic 192 KiB asset was received fully over h2, exercising WINDOW_UPDATE handling.
- Not yet covered: simultaneous streams, reset while flow-control blocked, malformed protocol isolation, exhaustive split-point tests for all frame types, or comparison against an independent Wireshark decode.

## Phase 5 — Workload and success oracle

- Added one deterministic synthetic catalog search/detail/save task. A seed chooses the task term; content does not encode client family or imitation stage.
- Added same-origin CSS/JavaScript/SVG routes and a deterministic 192 KiB asset; all URLs remain under the task origin.
- Added a stateful success oracle with invalid transition rejection, duplicate-save handling, and a separate loopback control server on port 8444. Task routes are shared by HTTP/1.1 and h2.
- Added task session registration and outcome commands. Session state is currently in memory and is lost when the server restarts.
- Additional documentation-search and form workloads, external-URL boundary tests, and a persistent control-plane ledger remain outstanding.

## Phase 6 — Packet capture and TCP/TLS observations

- Added `bh capture doctor`, TShark field-inventory parsing, and a bounded-duration dumpcap helper restricted to Linux loopback interface `lo` and the configured task port. It does not elevate privileges.
- Environment check on 2026-10-22: TShark 4.6.9 and tcpdump are installed; TShark exposes 269,374 field records. `dumpcap` cannot execute and tcpdump cannot enumerate interfaces here (`getifaddrs: Operation not permitted`); loopback capture also lacked `CAP_NET_RAW`, so no real PCAP was produced. Added `bh capture extract` for TShark-versioned packet fields and `bh capture join` for unique socket-tuple/time association, JSONL connection features, and an explicit join-quality report.
- Join and feature assembly are tested with packet/event fixtures only. Real TShark extraction, ClientHello reassembly correctness, capture-drop/coverage statistics, and IPv6 behavior remain unverified. Event-only server features are an explicitly limited fallback, not packet-level TLS/TCP evidence.
- Added `docs/feature_dictionary.md` with sources, definitions, exclusions, and known limits for the first feature schema.
- Do not treat server-side TLS metadata as packet-level ClientHello/TCP evidence.

## Phase 7 — Client adapters

- Added an ordinary trusted HTTP/1.1 control runner using one persistent `http.client` connection.
- Added a `curl_cffi` adapter whose profile name is validated against the installed package's `BrowserType` API. The actual pilot used `chrome150`; it negotiated TLS 1.3 and h2 at the server and completed the oracle-defined task. Recorded ancestry: `curl_cffi → curl-impersonate → libcurl`.
- Added an isolated headless Firefox runner using a temporary profile and temporary Firefox installation tree with a per-run policy trusting only the local lab CA. Firefox 157.0.1 completed the oracle task over TLS/h2; temporary files were cleaned up. Chrome/Chromium, Go/Rust adapters, and three independent implementation families remain outstanding.
- The curl profile is a configured imitation target, not a real Chrome browser or proof of matching all browser behavior.

## Dataset and baseline analysis pipeline (engineering implementation)

- Added `bh dataset build` to combine joined observation features with a separate label registry. It validates browser/browserless labels and train/validation/test metadata, rejects client-family split leakage, and writes `features.csv`, `labels.csv`, and a manifest.
- Added `bh dataset evaluate`, a train-only categorical Naive Bayes baseline evaluated on the test partition. It compares TLS-only, TLS-plus-HTTP/2, and full features on common test rows and reports confusion counts, accuracy, browserless recall, browser false-positive rate, and full-model per-session scores. This is an engineering baseline, not research evidence.
- Synthetic unit fixtures verify separation and family split checks. There are no real packet captures, labeled browser sessions, performance estimates, or confidence intervals.

## Phases 8–12 — Prototype components and evidence

- Phase 8: added deterministic experiment planning and collection that records every attempt, oracle outcome, lifecycle, costs, packet captures, and dataset manifests. Successful captures are extracted with TShark, joined to server connections, and included as cross-layer features; event-only observations fill in connections without a successful packet join. Capture/extraction/join failures remain recorded in the manifest.
- Phases 9–10: added an allowlisted event-feature path and session aggregation. It observes negotiated endpoint TLS and endpoint-observed H2 structure; it cannot recover ClientHello offers, TCP SYN details, or raw packet timing. Complete preregistered feature-group ablations and cutoff-aware prefix features remain incomplete.
- Phase 11: planner requires both browser and browserless sessions in train and validation and rejects browserless-family overlap. `configs/development_experiment.json` schedules 40 local episodes: Firefox in both partitions, stdlib browserless in train, and curl-cffi Chrome impersonation in validation. A third independent family is reserved and not collected.
- Phase 12: added optional scikit-learn logistic regression and random forest pipelines, preprocessing fit on train only, validation-only cutoff selection under a configurable browser FPR cap, and hashed joblib bundles. The final test partition is not opened by this command. Any validation figures are development estimates only.
- Collected the configured 40 sessions: 40/40 task-oracle successes, 40 matched feature rows, 20 train and 20 validation. All 40 packet captures failed on host capture permissions; the dataset is event-only. `split-manifest.json`, `fidelity-report.json`, and a report of this pilot were saved. The reserved test family was not collected or opened.
- Logistic regression and random forest each classified the 20 validation rows correctly at the chosen validation threshold (10/10 in each class). The result is only a pipeline smoke test on one held-out impersonation profile and a tiny dataset; do not report this as detector performance.
- Model artifacts are ignored under `artifacts/models/local-dev-cross-layer-v1/`; they include hashed joblib bundles and validation prediction CSVs. The model score round-trip and feature-order guard are tested.
- Follow-up after the local pilot: the orchestrator was connected to the existing TShark extraction and tuple/time join functions so a future permission-enabled collection will actually feed PCAP-derived features into the dataset. The prior 40-run dataset remains event-only; this integration still needs a successful host capture run to validate it end to end.

## Verification run on 2026-10-22

- `UV_CACHE_DIR=/tmp/bh-uv-cache uv run --extra ml python -m unittest discover -s tests -v`: 19 tests passed.
- `uv add --optional ml scikit-learn joblib pandas` resolved the optional ML dependencies; lockfile records scikit-learn 1.9.1, joblib 1.6.0, and pandas 3.0.6.
- `./scripts/bh capture doctor`: confirms TShark 4.6.9 and its field inventory, but no loopback capture due interface/raw-socket permissions.
- `./scripts/bh experiment collect ...`: 40 task successes, 40 matched event-only rows, 0 captured PCAPs. `./scripts/bh model train ...`: saved logistic and forest bundles; each has 10/10 correct among 10 validation examples per class. Threshold and prediction artifacts are recorded, and `test_rows_read` is 0.
- `./scripts/bh fidelity ...`: generated component-level exploratory comparison; Chrome 150 fidelity is `approximate_not_verified` because an actual matching browser executable was unavailable.
- Local HTTPS smoke tests: `stdlib-http.client` completed all five task routes over HTTP/1.1; `curl_cffi==0.16.3` with `chrome150` completed the same task over h2; both reached `task_success=true`. The current client reported actual negotiated protocol `h2` and TLS 1.3 was observed by the server.
- A `chrome150` h2 request retrieved a deterministic 192 KiB asset byte-for-byte, validating the current server's response flow-control path.
- These are engineering checks only. They do not establish detector accuracy, cross-family generalization, browser parity, or research evidence.

## Remaining work before the project can claim Phases 0–12 acceptance

1. Replace or formally amend the Phase 3 `asyncio`/`h11` requirement and finish negative TLS/HTTP correctness tests.
2. Complete H2 concurrent-stream, reset, decoder-comparison, and protocol-error tests.
3. Expand tasks and persist run/session manifests and oracle outcomes.
4. Arrange authorized host/container capture capability and validate extraction against real PCAPs/Wireshark, SYN/ClientHello fields, packet loss, and joins.
5. Add independently implemented Go/Rust adapters and a third independent browserless family; current cohorts do not support final held-out evaluation. Obtain a real Chrome version that matches the curl-cffi profile for fidelity testing.
6. Implement all preregistered feature groups, cutoff-aware features, protocol-rule and majority baselines, bounded model search, uncertainty reporting, and reliable per-process cost measurement.
