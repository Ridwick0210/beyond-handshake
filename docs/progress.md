# Implementation progress

## 2026-10-21 — Phases 0–3 implemented; runtime smoke checks pending

### Phase 0: scope

- Created `docs/decisions/0001-scope.md` and `docs/experiment_protocol.md`.
- Locked the primary distinction to browserless HTTP automation versus a real browser stack. The controller identity is separate metadata.
- Recorded the current environment and the empty `.git` limitation.

### Phase 1: package setup

- Created the Python package metadata, CLI entry point, offline dependency lock, config, and ignore rules.
- Environment: Python 3.14.8, uv 0.12.19, OpenSSL 3.5.9.
- `UV_CACHE_DIR=/tmp/networks-uv-cache uv lock --offline` completed successfully. The application has no runtime third-party dependencies.
- PyPI access failed due DNS/network restrictions. The implementation uses Python standard library modules for TOML and HTTP/1.1, rather than the planned PyYAML/Pydantic/h11 stack.

### Phase 2: schemas and storage

- Implemented event/run dataclasses with explicit validation, strict TOML config parsing, bounded queued JSONL event writer, partial/complete/failed manifests, and artifact hashing.
- No research or real traffic data has been collected.

### Phase 3: local HTTPS/HTTP/1.1 endpoint

- Implemented a standard-library `ThreadingHTTPServer` wrapped with server-side TLS, HTTP/1.1 only, host allowlist, request/header/body limits, a status/demo page, and connection/request/response events.
- Added `bh doctor`, `bh cert create`, and `bh server` commands plus a local-only wrapper.
- Generated ignored development CA/certificate/key files under `local/tls/` for the configured loopback hostnames.
- HTTP/2, packet capture, workload oracle, and detection are not implemented in this phase.

## Validation log

- `uv lock --offline`: completed successfully.
- Local CA and server certificate generation command: completed successfully; it printed paths and kept private key files mode `0600`.
- Automated tests and server/curl smoke checks have not been run. No accuracy or research findings exist.
