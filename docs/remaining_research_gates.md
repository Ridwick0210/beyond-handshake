# Remaining research gates

This checklist tracks the work needed beyond the local prototype. A code path or a planned run is not evidence that its measurement gate has passed. Keep the final-test partition sealed until the protocol, cohort, threshold, and model are frozen.

## Implemented, evidence still required

- [x] Add a second shared workload: `docs-search-answer-v1`, a synthetic documentation search and answer-submission task. The same oracle is used by browser and direct clients; `task_id` stays in labels/metadata and is excluded from model features.
- [x] Add a 40-episode development schedule in `configs/docs_search_answer_development.json`: Firefox references in train and validation, curl-cffi in train, and Go tls-client in validation. This is a task-specific development schedule, not a task-held-out generalization test.
- [x] Isolate each adapter in a worker and record sampled worker/descendant CPU and peak aggregate RSS. This uses Linux `/proc` at a 20 ms interval. It is not cgroup accounting and can miss short-lived processes.
- [ ] Run the task schedule after Go dependencies build and capture permissions are available. Preserve every attempt, failed cost measurement, packet-coverage result, and oracle outcome.
- [ ] Once both workload datasets exist, define a task-held-out split (train on one task, evaluate on the other) or keep results explicitly task-specific. Do not combine sessions with a random row split.
- [ ] Check cost-meter agreement on every adapter against cgroup v2 or another process-tree accounting source on a capable Linux host. Report server/client co-location and sampling limitations.

## Controlled network condition — blocked on host capability and topology

- [ ] Provide or provision a second Linux VM/host and a controlled client-to-server route. The current development origin, control plane, and capture helper are loopback-only; changing a label or adding delay to loopback does not create a real path shift.
- [ ] On that host, configure a documented N0 direct-LAN baseline and N1 controlled delay/loss at a network point traversed by client traffic. Record direction, configured and observed parameters, interface, kernel, and route.
- [ ] Grant the collector only the required packet-capture capability and grant the network administrator the privileges needed to configure the shaping point. The current environment cannot open netlink (`ip`/`tc`: `Operation not permitted`), and capture permissions must be checked independently.
- [ ] Extend the run contract to identify the actual origin, control endpoint, capture interface, and path condition; verify packet and endpoint joins over that topology before collecting a cohort.
- [ ] Keep path condition out of predictor features. Treat N1 as a held-out environment shift unless the preregistration says otherwise.

## Third independent client family — not yet selected

- [ ] Identify a third browserless implementation with a pinned build/profile, verified protocol behavior, and documented TLS/HTTP2 ancestry. Keep the entire family out of model fitting and threshold selection.
- [ ] Do not count `wreq` as independent from Chrome solely because it is a Rust client: its upstream project states it uses BoringSSL, which is also Chrome's TLS implementation ancestry. If used as an engineering comparison, label the shared ancestry and do not use it to satisfy the independent-family gate.
- [ ] Before adding an adapter, prove CA verification, task-oracle success, negotiated H2, packet completeness, capture joins, and fidelity on development-only sessions.
- [ ] If no credible third family is available, freeze a two-family engineering study and downgrade all unseen-family claims rather than substitute wrappers around an existing stack.

## Human-browser false-positive evidence — requires participants

- [ ] Prepare a participant-facing consent and data-handling protocol before collection. Collect only the minimum needed for the task; do not retain names, account data, cookies, or unrelated browsing traces.
- [ ] Use user-mediated sessions in the same controlled task and declared browser environment. Keep participant identity separate from model features; preserve withdrawals/exclusions without relabeling them as task failures.
- [ ] Compute human-browser false-positive rate with participant-level uncertainty, not by treating repeated sessions from one person as independent.
- [ ] Until these data exist, report scripted real-browser false positives only and make no human-FPR claim.

## Final freeze and evaluation

- [ ] Complete independent packet/TLS/H2 audits and capture-health gates for the chosen runs.
- [ ] Freeze the feature registry, task/environment splits, client configurations, threshold, and model before opening the reserved test family/conditions.
- [ ] Run the reserved evaluation once; report failures, exclusions, uncertainty, cost, task success, and negative findings. Do not tune on those outcomes.
