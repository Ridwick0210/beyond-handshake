# Decision 0003: Phase 4–7 pilot implementation scope

**Date:** 2026-10-22 (Asia/Kolkata)
**Status:** Accepted for local engineering validation; research acceptance remains open.

## Context

The initial prototype used the Python standard library because PyPI was unavailable during its first build. The required project direction is still the cross-layer research design in `MASTER_BUILD_DOCUMENT.md`, but a runnable local demonstration was needed before the next review.

## Decision

- Add the pinned `hyper-h2` state machine and retain the existing threaded TLS server. Each connection thread owns its H2 state; a separate loopback control server is excluded from measured task traffic.
- Add a deterministic, server-rendered catalog workload and server-side oracle shared by HTTP/1.1 and h2.
- Keep `curl_cffi` optional and pin it separately from core dependencies. Validate the selected impersonation profile against the installed API; write adapter ancestry and profile into each attempt record.
- Limit capture support to a bounded loopback-only dumpcap command and installed TShark capability inventory. Do not guess packet fields or claim TCP/TLS feature extraction without a verified TShark build and trace comparison.
- Do not install or trust the lab CA system-wide. A real-browser adapter remains unavailable until a browser and isolated trust setup can be tested.

## Consequences

This provides a demo path for H1 and h2 plus a success oracle, but it does not satisfy the full build document's Phase 3 asyncio/h11 design or Phase 6/7 acceptance criteria. No classifier, accuracy statement, unseen-family result, or AI-specific claim is supported. `docs/progress.md` records the concrete implementation and remaining gaps.
