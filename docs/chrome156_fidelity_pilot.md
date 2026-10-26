# Real Chrome local fidelity pilot — 2026-10-27

This is a development measurement, not a completed detector, Chrome 150 parity result, or final-test cohort. The reserved test family was not collected.

## Fixture and trust

- Config: `configs/chrome156_profile150_fidelity_pilot.json`; experiment ID `local-chrome156-profile150-fidelity-pilot-v2`.
- Real browser: Google Chrome 156.0.8078.47; executable SHA-256 `aea09d69ce7f24d5901f6bfb15dd44d0c856e793e0a498f8d8393ec7d2c308ec`.
- Browserless targets: curl-cffi 0.16.3 `chrome150` and Go tls-client `chrome_150`. These do not target the installed Chrome version.
- Chrome ran headless with a temporary profile and temporary NSS database containing the local lab CA, bind-mounted over the legacy user NSS path with bubblewrap. No certificate-verification bypass flag was used. The normal browser profile and trust database were not modified.
- Schedule: 5 Chrome and 5 curl-cffi train sessions; 5 Chrome and 5 Go tls-client validation sessions. One synthetic task and one local loopback path. No model fitting was performed.

## Measured outcome

The first v1 collection completed 20 task/capture attempts but failed dataset construction: the collector chose a stale partial server event manifest using a wall-clock ranking. Its raw artifacts remain local and excluded. The collector now asks the live loopback control plane for its run ID and selects that run's exact event file. The v2 pilot was recollected from a new plan and output path.

For v2, `collection-manifest.json` reports 20/20 task successes, 20/20 captured sessions, 20/20 packet-complete dataset rows, 23 uniquely joined packet/server connections, no event-only connections, no unmatched sessions or family-split leaks, and zero reported drops among 1,085 received packets. The event file is bound to server run `20261026T193857Z-2814d166`.

The exploratory fidelity report compares per-connection observation sets, so Chrome opening two otherwise identical connections does not create a false mismatch. Against both browserless families, observed ALPN offers, TCP SYN-option order, endpoint TLS version/ALPN, and inbound H2 SETTINGS order have matching value sets. TLS cipher-suite and extension-order value sets, H2 frame-type sequences, and H2 header-name orders differ. These are literal observed-set comparisons on five sessions per browserless family, not a controlled estimate of profile fidelity; GREASE and connection/workload variation are not normalized or independently audited. Overall status is `version_mismatch` for both comparisons because Chrome 156 is not the Chrome 150 target.

## Reproduction and remaining gates

With the local server running, `BH_CERTUTIL` pointing to NSS `certutil`, and loopback capture permission:

```sh
UV_CACHE_DIR=/tmp/bh-uv-cache ./scripts/bh experiment plan --config configs/chrome156_profile150_fidelity_pilot.json --output data/interim/chrome156-fidelity-pilot-v2-plan.json
sg wireshark -c 'BH_CERTUTIL=/path/to/certutil UV_CACHE_DIR=/tmp/bh-uv-cache ./scripts/bh experiment collect --plan data/interim/chrome156-fidelity-pilot-v2-plan.json --output-dir data/interim/chrome156-fidelity-pilot-v2 --server-config configs/server.toml'
UV_CACHE_DIR=/tmp/bh-uv-cache ./scripts/bh fidelity --features data/interim/chrome156-fidelity-pilot-v2/local-chrome156-profile150-fidelity-pilot-v2/dataset/features.csv --labels data/interim/chrome156-fidelity-pilot-v2/local-chrome156-profile150-fidelity-pilot-v2/labels.json --attempts data/interim/chrome156-fidelity-pilot-v2/local-chrome156-profile150-fidelity-pilot-v2/episodes.jsonl --output data/interim/chrome156-fidelity-pilot-v2/local-chrome156-profile150-fidelity-pilot-v2/fidelity-report.json
```

All run artifacts remain ignored locally. To claim Chrome-target fidelity, obtain a reproducibly pinned real Chrome 150 binary (or an impersonation profile matching Chrome 156), repeat the comparison with locked versions and task conditions, independently check packet parsing, and audit H2 observation semantics. Broader tasks, paths, browser/client families, human data, and the frozen final test remain outstanding.
