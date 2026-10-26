# Data collection and model plan

**Updated:** 2026-10-27 (Asia/Kolkata)

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

The Chrome runner is now implemented and a 20-session local Chrome 156 versus Chrome 150-profile pilot was captured (`docs/chrome156_fidelity_pilot.md`). This establishes that real Chrome can be measured with verified local CA trust; it does not satisfy matching-version parity. The next practical milestone is an exact Chrome 150 build or a supported profile for the installed Chrome version, followed by a predeclared matching-version fidelity run and a second independent strong impersonator. Repeating the existing loopback task would add rows but little information about generalization.

## Stage 0 and stage 1 implementation

`configs/stages_0_1_development.json` is a 60-session development schedule: 20 Firefox references, 20 curl_cffi sessions (10 per stage, train), and 20 Go-family sessions (10 per stage, validation). Stage 0 uses ordinary client defaults. Stage 1 selects `chrome150` for curl_cffi and `chrome_150` for Go `tls-client`, disables HTTP/3 in the Go runner, and supplies the declared Chrome-like request-header template. Both conditions in each family/repetition share the same deterministic task seed and pair ID. The stage remains label metadata and is not added to model features.

This schedule is a wiring and pilot plan, not a final evaluation design. The Go comparison also changes the HTTP/TLS client implementation between stages (`net/http` to `tls-client`); do not attribute a measured difference to the browser profile alone. Chrome 156 is installed and has been captured, but neither Chrome 150 profile can be declared matched to that newer browser. A matching-version comparison remains required.

## Stage 2 and stage 3 pilot schedule

`configs/stages_2_3_development.json` now assigns paired I2/I3 conditions in both browserless families: curl_cffi in train and Go tls-client in validation, with Firefox references in both. I2 and I3 both complete the same task twice in one client session; I3 additionally discovers and loads first-party static resources and honors explicit `max-age` across the second visit. Pair IDs and task seeds match within a family/repetition. Stage metadata and resource counts remain separate from model features. The versioned 60-session pilot was collected with complete packet capture and is documented in `docs/stages_2_3_report.md`. It is development evidence only; real Chrome profile parity and final-test performance remain unavailable.
