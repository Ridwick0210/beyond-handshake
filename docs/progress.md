# Implementation progress

**Last updated:** 2026-10-22 (Asia/Kolkata)

This page distinguishes working prototype features from the complete requirements in `MASTER_BUILD_DOCUMENT.md`. No detector, trained model, research result, or final-test dataset exists.

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
- Environment check on 2026-10-22: neither `tshark` nor `dumpcap` is installed. Added `bh capture extract` for TShark-versioned packet fields and `bh capture join` for unique socket-tuple/time association, JSONL connection features, and an explicit join-quality report. TCP SYN/TLS ClientHello values are extracted when supported by the TShark field inventory; HTTP/2 metadata comes from endpoint events because it is encrypted in PCAP.
- Join and feature assembly are tested with synthetic packet/event fixtures only. Real TShark extraction, ClientHello reassembly correctness, capture-drop/coverage statistics, and IPv6 behavior remain unverified until tools are installed.
- Added `docs/feature_dictionary.md` with sources, definitions, exclusions, and known limits for the first feature schema.
- Do not treat server-side TLS metadata as packet-level ClientHello/TCP evidence.

## Phase 7 — Client adapters

- Added an ordinary trusted HTTP/1.1 control runner using one persistent `http.client` connection.
- Added a `curl_cffi` adapter whose profile name is validated against the installed package's `BrowserType` API. The actual pilot used `chrome150`; it negotiated TLS 1.3 and h2 at the server and completed the oracle-defined task. Recorded ancestry: `curl_cffi → curl-impersonate → libcurl`.
- Added manual task URL instructions. A real Chrome/Chromium or Playwright runner is not available: no browser binary or Playwright installation was found. Go/Rust adapters, task timeout supervision, process-tree cleanup, and three independent implementation families remain outstanding.
- The curl profile is a configured imitation target, not a real Chrome browser or proof of matching all browser behavior.

## Dataset and baseline analysis pipeline (engineering implementation)

- Added `bh dataset build` to combine joined observation features with a separate label registry. It validates browser/browserless labels and train/validation/test metadata, rejects client-family split leakage, and writes `features.csv`, `labels.csv`, and a manifest.
- Added `bh dataset evaluate`, a train-only categorical Naive Bayes baseline evaluated on the test partition. It compares TLS-only, TLS-plus-HTTP/2, and full features on common test rows and reports confusion counts, accuracy, browserless recall, browser false-positive rate, and full-model per-session scores. This is an engineering baseline, not research evidence.
- Synthetic unit fixtures verify separation and family split checks. There are no real packet captures, labeled browser sessions, performance estimates, or confidence intervals.

## Verification run on 2026-10-22

- `UV_CACHE_DIR=/tmp/networks-uv-cache uv lock --check --offline` and `uv sync --locked --offline --extra impersonation`: completed successfully.
- Previous suite: 11 tests passed. Current suite: 15 tests pass, including TShark adapter behavior through a fake CLI fixture, unique tuple/time join, label-feature separation, family split rejection, and baseline evaluation on synthetic fixtures.
- `./scripts/bh doctor`: reports valid config, local certificate present, h2 available, and missing browser/capture tools.
- Local HTTPS smoke tests: `stdlib-http.client` completed all five task routes over HTTP/1.1; `curl_cffi==0.16.3` with `chrome150` completed the same task over h2; both reached `task_success=true`. The current client reported actual negotiated protocol `h2` and TLS 1.3 was observed by the server.
- A `chrome150` h2 request retrieved a deterministic 192 KiB asset byte-for-byte, validating the current server's response flow-control path.
- These are engineering checks only. They do not establish detector accuracy, cross-family generalization, browser parity, or research evidence.

## Remaining work before the project can claim the build document's Phases 3–7 acceptance

1. Replace or formally amend the Phase 3 `asyncio`/`h11` requirement and finish negative TLS/HTTP correctness tests.
2. Complete H2 concurrent-stream, reset, decoder-comparison, and protocol-error tests.
3. Expand tasks and persist run/session manifests and oracle outcomes.
4. Install approved capture tools, validate extraction against real PCAPs and Wireshark decode, verify SYN/ClientHello fields and packet loss, and produce capture coverage reports.
5. Run a real browser using a temporary isolated profile with the lab CA trusted, and implement cleanup/cancellation. Add independently implemented Go/Rust adapters only after the first end-to-end runner is stable.
6. Expand the baseline to preregistered grouped model comparisons, locked split manifests, uncertainty/ablation reporting, and protocol feature groups after real measurement and provenance are validated.
