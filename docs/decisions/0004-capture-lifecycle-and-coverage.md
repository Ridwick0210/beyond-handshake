# 0004 — Capture lifecycle and packet coverage gate

**Date:** 2026-10-22

The first permission-enabled development collection (`local-dev-cross-layer-v1`) used a fixed five-second capture and began the client after a fixed half-second delay. A saved PCAP verified that TShark 4.6.9 emits TCP flag fields as `True`/`False`; the old parser expected `1`/`0`. Re-extraction with corrected flag parsing and explicit TLS decoding found complete SYN and ClientHello evidence for 20/20 Firefox sessions, 1/10 curl-impersonate sessions, and 0/10 Python stdlib sessions. The capture startup delay therefore correlated with client family. This run is an instrumentation pilot, not a valid packet-feature training cohort.

For subsequent collections, the collector waits until the capture process is alive before starting the client. It keeps capture active through task completion and for at least the configured `capture_seconds` after capture startup, with a maximum of task deadline plus capture window plus 15 seconds. Actual duration and the maximum are recorded per capture. This changes the observation-window interpretation for new collections, so results from the old fixed-window run must not be pooled with them as if measured identically.

The packet join now requires the full socket tuple, a unique time match, a client SYN, and a client-direction ClientHello. A finished collection can be re-extracted into a new directory without modifying raw captures or server events. The dataset writes packet coverage to a sidecar file; Phase 12 training rejects mixed packet/event-only train or validation cohorts. Pure event-only development analysis remains explicitly labeled as such.

Remaining verification: the readiness signal checks that the capture process is alive after startup; it does not prove the first packet is already being written. A new permission-enabled collection must demonstrate balanced SYN/ClientHello coverage by class and inspect capture drop statistics before packet-level model fitting.
