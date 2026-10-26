# Data collection and model plan

**Updated:** 2026-10-26 (Asia/Kolkata)

## Current automated development path

The default `bh experiment develop` command now runs the 100-episode v3 plan. It checks local browser and client adapters, lab CA, ML dependencies, authorized loopback capture, TShark fields, free disk space, and unused output paths. It starts the loopback server, registers one synthetic task per episode, captures packets through task completion, extracts TShark fields, joins each capture to endpoint events, and builds a label-separated dataset. The model stage runs only after 100% task success, complete packet joins, zero reported capture drops, and exact planned cohort counts. It writes TLS-only, TLS-plus-HTTP/2, and full-feature logistic regression and random forest bundles. A failed gate leaves artifacts for diagnosis and does not create model bundles.

The completed run and model comparisons are in [development_v3_report.md](development_v3_report.md). Reruns must use a new experiment ID and output paths; old raw files and saved models are not overwritten.

## Next collection design

| Gate | Required work | Evidence to save |
|---|---|---|
| Browser parity | Obtain and pin a real Chrome build corresponding to the chosen curl profile; add a browser runner with isolated CA trust | Exact binary/version/hash, observed TLS/H2 comparison, task success |
| Family diversity | Add a second strong browserless implementation for development and a third independent one for the untouched family test | Dependency ancestry, supported profile, binary/module hashes, protocol observations |
| Task and path diversity | Implement at least one additional synthetic task and a controlled second network path | Same success oracle, preassigned task/path conditions, capture health |
| Measurement audit | Compare selected TShark ClientHello and TCP options with an independent decode; measure client process cost | Parity report, drop/coverage tables, cost method |
| Research freeze | Lock partitions, capture blocks, models, feature groups, threshold rule, and exclusion criteria before final collection | Versioned plan and hashes, untouched test manifest |

Use the master document's 2,400-attempt grid as a budgeting example, not a mandatory or statistically sufficient count. Set actual cell counts only after measuring variance, runtime, storage, and the number of independent browser/client families. Keep browserless families disjoint across partitions. Preserve all attempted sessions in the ledger and report task success and packet coverage by cohort. Train preprocessing on the training partition, choose the operating threshold on validation, then apply the frozen bundle once to the test panel.

The next practical implementation milestone is the matching Chrome runner and a second strong impersonator. Repeating the existing Firefox-versus-curl loopback task would add rows but little information about generalization.

## Stage 0 and stage 1 implementation

`configs/stages_0_1_development.json` is a 60-session development schedule: 20 Firefox references, 20 curl_cffi sessions (10 per stage, train), and 20 Go-family sessions (10 per stage, validation). Stage 0 uses ordinary client defaults. Stage 1 selects `chrome150` for curl_cffi and `chrome_150` for Go `tls-client`, disables HTTP/3 in the Go runner, and supplies the declared Chrome-like request-header template. Both conditions in each family/repetition share the same deterministic task seed and pair ID. The stage remains label metadata and is not added to model features.

This schedule is a wiring and pilot plan, not a final evaluation design. The Go comparison also changes the HTTP/TLS client implementation between stages (`net/http` to `tls-client`); do not attribute a measured difference to the browser profile alone. Chrome is not installed in the current environment, so neither Chrome profile can yet be declared matched to an actual browser. Stage 0 and stage 1 collection should wait until these conditions and the fidelity limitation are accepted in the experiment protocol.

## Stage 2 and stage 3 pilot schedule

`configs/stages_2_3_development.json` assigns 10 paired curl_cffi I2/I3 episodes to train, with Firefox negatives in train/validation and Go tls-client I1 as the validation browserless family. The curl family does not cross partitions. I2 is an explicit no-op contrast for curl_cffi because its I1 runner already maintains a session, cookie jar, and persistent connection. I3 discovers and loads allowed first-party resources and caches only responses explicitly marked `max-age`; stage metadata records resource counts separately from model inputs. This schedule is not collected or research evidence. The workload has a cold cache per attempt and only an in-attempt repeated-script cache hit; warm-cache revisit semantics remain unimplemented.
