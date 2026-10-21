# Decision 0001: prototype scope and research target

**Date:** 2026-10-21 (Asia/Kolkata)
**Status:** Accepted as the initial implementation scope.
**Evidence available:** The project proposal deck and `docs/MASTER_BUILD_DOCUMENT.md`; no collected dataset or source implementation existed at the start of this work.

## Decision

The primary target is the execution stack: browserless HTTP automation versus a real browser network stack. A human using Chrome and a script controlling Chrome are both browser-stack negatives. The project will not claim that network traffic proves a client is an AI agent or that a client is malicious.

The first prototype implements Phases 0–3 of the master build document: scope/protocol notes, package setup, core schemas/event storage, and a localhost HTTPS server supporting HTTP/1.1. HTTP/2 observation, packet capture, real workload generation, client adapters, classification, and research findings remain future work.

## Demonstration claim

The current prototype can demonstrate a local TLS endpoint and record HTTP/1.1 request metadata. It cannot yet compare TLS fingerprints, observe HTTP/2 settings, identify an AI agent, or report detection performance.

## Environment and constraints

- Development host currently provides Python 3.14.8, uv 0.12.19, OpenSSL 3.5.9, and curl.
- The workspace has no usable Git repository metadata; its `.git` directory is empty. Do not initialize or alter Git metadata without a later explicit task.
- The server binds to `127.0.0.1` by default and accepts only configured hostnames.
- Generated TLS private keys and raw run data stay under ignored local/data directories.

## Next decision gate

Before Phase 4, verify the pinned `h2` public API, preserve the original client byte order, and design the single-owner flow-control path. Before Phase 6, verify the actual capture interface and packet-field availability on the target host.
