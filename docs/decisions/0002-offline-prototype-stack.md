# Decision 0002: use the standard library for the first local prototype

**Date:** 2026-10-21 (Asia/Kolkata)
**Status:** Accepted for Phases 0–3 only.

## Context

The build document originally proposed `h11`, `h2`, Pydantic, and PyYAML. The workspace host has no PyPI DNS/network access, and Pydantic was not installed. The host does have Python 3.14's standard library, OpenSSL, and uv.

## Decision

Implement Phase 3 with `http.server.ThreadingHTTPServer`, `ssl`, `tomllib`, dataclasses, and JSON from the Python standard library. Keep the runtime dependency list empty so `uv lock --offline` succeeds. This produces an immediately runnable local HTTPS/HTTP/1.1 demonstration without vendoring code or pretending packages installed.

This is a prototype choice, not a change to the planned HTTP/2 architecture. Phase 4 should add and lock `h2` when a package source is available. HTTP/2 state handling and raw frame observation must not be implemented by extending this HTTP/1.1 server with an improvised protocol parser.

## Consequences

- Configuration is TOML rather than YAML.
- The current HTTP server relies on Python's standard parser and supports the local prototype's simple routes; it is not a production server.
- `scripts/bh` runs directly from `src/` without installing the project.
- No automated tests or network smoke checks were run during this implementation task.
- Research claims about HTTP/2, TLS fingerprints, TCP, detection, or performance remain unsubstantiated.
