# Beyond Handshake

A local prototype for studying which server-observable network signals distinguish browserless automation from real browser networking. The primary target is the **execution stack**. The prototype cannot determine whether a person or an AI chose the actions, and it does not identify malicious intent.

## Current status

Prototype components now cover Phases 0–12: TLS/HTTP1/H2 server, event logging, a deterministic task oracle, Python stdlib/curl-cffi/headless Firefox clients, an independent Go stdlib client, packet extraction/join code, event-only feature extraction, experiment planning/collection, grouped train/validation splits, and transparent model training. The latest automated local development run collected 100 packet-complete sessions and trained the planned baseline models. These loopback cohorts remain development artifacts rather than research evidence. The final test family remains reserved and unopened.

## Requirements

- Python 3.12 or newer. The current development host has Python 3.14.
- Go 1.24 or newer is required only to build the independent `go-stdlib` adapter.
- OpenSSL CLI for local certificate generation.
- `h2==4.4.1` is required for HTTP/2. `curl-cffi==0.16.3` is optional for the impersonation adapter.
- Optional `ml` extra provides scikit-learn/joblib for Phase 12 baseline bundles.

Install the locked core and optional impersonation dependencies with `uv sync --locked --extra impersonation` when package access is available. The server remains local-only; no detection model or research finding is included.

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
curl --http1.1 --cacert local/tls/ca.pem https://127.0.0.1:8443/
curl --http1.1 --cacert local/tls/ca.pem https://127.0.0.1:8443/healthz
```

The separate HTTP control plane listens on loopback port `8444`. Register a deterministic task, then run the ordinary control or a profile exposed by the installed `curl_cffi` API:

```sh
./scripts/bh task register --seed 1234
./scripts/bh client profiles
./scripts/bh client run SESSION_ID --adapter stdlib
./scripts/bh client run ANOTHER_SESSION_ID --profile chrome150
./scripts/bh task outcome SESSION_ID
```

The register command prints the session ID. Use a new session ID for every attempt. The `curl_cffi` profile name is validated against the installed package at runtime; its profile label is a client configuration, not proof of an actual Chrome browser. `./scripts/bh client manual <session-id>` prints a URL for human completion.

Build and run the independent Go standard-library adapter with a fresh registered session:

```sh
make go-client
./scripts/bh client run SESSION_ID --adapter go-stdlib
```

This adapter uses Go `net/http` and `crypto/tls`; it is an ordinary independent browserless family, not a browser-impersonation profile. It keeps certificate verification enabled and accepts only a loopback HTTPS origin. See [the client registry](docs/client_registry.md) for ancestry and claim boundaries.

`./scripts/bh capture doctor` reports TShark fields and whether loopback capture works in the current environment. On this host the ordinary unprivileged shell cannot capture, while a host shell authorized through the `wireshark` group produced the recorded development captures. Packet extraction and analysis commands are implemented; new collection still requires explicitly authorized loopback capture:

```sh
./scripts/bh capture extract --pcap local/captures/run.pcapng --output local/derived/packets.tsv
./scripts/bh capture join --packets local/derived/packets.tsv --events local/runs/RUN/events.jsonl --output local/derived/joined.jsonl
./scripts/bh dataset build --features local/derived/joined.jsonl --labels local/labels.json --output-dir local/derived/dataset
./scripts/bh dataset evaluate --dataset-dir local/derived/dataset --output local/derived/evaluation.json
```

The label registry is separate JSON metadata with `session_id`, `execution_stack` (`browser` or `browserless`), `client_family`, and a preassigned `partition` (`train`, `validation`, or `test`). The builder rejects client families assigned to multiple partitions and writes feature and label CSVs separately. The evaluator compares TLS-only, TLS-plus-HTTP/2, and full feature groups on the same held-out rows using a categorical Naive Bayes engineering baseline; it does not replace preregistered model selection, uncertainty analysis, or external validation.

The development schedule and Phase 12 training commands are:

```sh
uv sync --locked --extra impersonation --extra ml
./scripts/bh experiment plan --config configs/development_experiment.json --output data/interim/dev-plan.json
./scripts/bh experiment collect --plan data/interim/dev-plan.json --output-dir data/interim
./scripts/bh model train --dataset-dir data/interim/local-dev-cross-layer-v1/dataset --output-dir artifacts/models/local-dev-v1
./scripts/bh fidelity --features data/interim/local-dev-cross-layer-v1/dataset/features.csv --labels data/interim/local-dev-cross-layer-v1/labels.json --output artifacts/evaluations/fidelity.json
```

These commands produce local development artifacts only. A successful run does not establish generalization, and the final test family is not collected by the planner.

For a larger automated development collection, first build the Go adapter and install the locked ML and impersonation extras, then run the cohort command from the project root in a shell authorized for local loopback capture:

```sh
make go-client
uv sync --locked --extra impersonation --extra ml
sg wireshark -c './scripts/bh experiment develop'
```

The default [v3 configuration](configs/development_experiment_v3.json) schedules 100 local sessions. The command starts and stops the local server, saves a frozen plan and per-episode captures under ignored `data/interim/captured-v3/`, checks task success and packet coverage, then trains the three feature groups under ignored `artifacts/models/local-dev-cross-layer-v3/`. It refuses to train if the measurement gate fails. See [decision 0005](docs/decisions/0005-expanded-development-cohort.md) for the exact split and limits.

The CA and key files are private local development material under ignored `local/`. The server listens on `127.0.0.1` and only accepts the configured `Host` values. It does not need or request administrator access. To use a browser, import `local/tls/ca.pem` as a trusted authority in a **dedicated temporary browser profile**. Do not install the lab CA in the system-wide trust store. Remove the profile and CA when finished.

Stop the server with Ctrl+C. Each run is written under `data/raw/<run_id>/` and contains `events.jsonl` plus `manifest.json`. A graceful stop marks the manifest complete and hashes the event file. An interrupted process leaves a partial run.

## Development commands

```sh
./scripts/bh --help
./scripts/bh doctor --output local/environment.json
uv lock --offline
```

Run the unit tests with `make test-unit`. The checked-in `scripts/bh` wrapper uses the project `.venv` when present and otherwise falls back to the system Python.

## Data handling

- Header names and order are logged; header values are redacted by default.
- With `retain_safe_header_values = true`, only the allowlisted non-sensitive fields in the handler may retain values. Cookie and authorization values are always redacted.
- Request bodies and query values are not written to server events. Packet captures and TLS key logs are not produced unless separately enabled by a future capture workflow.
- This code does not collect participant data. Add consent and a data-handling protocol before any human study.

## Project documents

- [Master build document](docs/MASTER_BUILD_DOCUMENT.md)
- [Scope decision](docs/decisions/0001-scope.md)
- [Initial experiment protocol](docs/experiment_protocol.md)
- [Client registry](docs/client_registry.md)
- [Data collection plan](docs/data_collection_plan.md)
- [Expanded development run report](docs/development_v3_report.md)
- [Implementation progress](docs/progress.md)
