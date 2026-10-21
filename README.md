# Beyond Handshake

A local prototype for studying which server-observable network signals distinguish browserless automation from real browser networking. The primary target is the **execution stack**. The prototype cannot determine whether a person or an AI chose the actions, and it does not identify malicious intent.

## Current status

Phases 0–3 are implemented: scope and protocol notes, a Python CLI, versioned event/run schemas, bounded JSONL event logging, a local development CA helper, and a localhost HTTPS server that records HTTP/1.1 metadata.

HTTP/2 observation, TCP/ClientHello packet capture, a task site and success oracle, browser/client adapters, a dataset, classifier, and evaluation results do not exist yet. The homepage states these limits explicitly. Logs from the current server are development artifacts, not research data.

## Requirements

- Python 3.12 or newer. The current development host has Python 3.14.
- OpenSSL CLI for local certificate generation.
- No Python runtime packages are required by the current implementation.

The environment has restricted access to PyPI, so the project uses the standard library in this initial implementation. The full build document describes a later `h2` based HTTP/2 implementation. Do not use the current server to claim cross-layer or HTTP/2 detection.

## Run the local prototype

The workspace already contains a generated local certificate under ignored `local/tls/`. Start the server from the repository root:

```sh
./scripts/bh doctor
./scripts/bh server --config configs/server.toml
```

For a clean checkout with no local certificate, generate it once before starting the server:

```sh
./scripts/bh cert create --hostname localhost --hostname 127.0.0.1 --hostname ::1 --out local/tls
```

The certificate command refuses to overwrite existing key material.

In a second terminal:

```sh
curl --cacert local/tls/ca.pem https://127.0.0.1:8443/
curl --cacert local/tls/ca.pem https://127.0.0.1:8443/healthz
```

The CA and key files are private local development material under ignored `local/`. The server listens on `127.0.0.1` and only accepts the configured `Host` values. It does not need or request administrator access. To use a browser, import `local/tls/ca.pem` as a trusted authority in a **dedicated temporary browser profile**. Do not install the lab CA in the system-wide trust store. Remove the profile and CA when finished.

Stop the server with Ctrl+C. Each run is written under `data/raw/<run_id>/` and contains `events.jsonl` plus `manifest.json`. A graceful stop marks the manifest complete and hashes the event file. An interrupted process leaves a partial run.

## Development commands

```sh
./scripts/bh --help
./scripts/bh doctor --output local/environment.json
uv lock --offline
```

`uv lock --offline` can resolve this dependency-free project without PyPI. A normal editable package install may need the setuptools build backend available in the local cache or package index. The checked-in `scripts/bh` wrapper provides an install-free local route by running Python with `src/` on `PYTHONPATH`.

## Data handling

- Header names and order are logged; header values are redacted by default.
- With `retain_safe_header_values = true`, only the allowlisted non-sensitive fields in the handler may retain values. Cookie and authorization values are always redacted.
- Request bodies, query values, TLS key logs, and raw packets are not written by the current server.
- This code does not collect participant data. Add consent and a data-handling protocol before any human study.

## Project documents

- [Master build document](docs/MASTER_BUILD_DOCUMENT.md)
- [Scope decision](docs/decisions/0001-scope.md)
- [Initial experiment protocol](docs/experiment_protocol.md)
- [Implementation progress](docs/progress.md)
