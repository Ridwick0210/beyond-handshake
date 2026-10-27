# Chrome 150 matching-milestone pilot — 2026-10-27

This is a local development pilot, not a final-test result or proof of exact Chrome fingerprint parity. It used the same synthetic catalog task and loopback path as the prior Chrome 156 pilot. No model was fitted or selected from these sessions.

## Frozen local inputs

- Official Chrome for Testing index: `https://googlechromelabs.github.io/chrome-for-testing/latest-versions-per-milestone-with-downloads.json`, milestone 150 entry queried on 2026-10-27.
- Linux64 archive: `https://storage.googleapis.com/chrome-for-testing-public/150.0.7871.124/linux64/chrome-linux64.zip`; archive SHA-256 `ccb11556d5946fcf15f09d175c34d8e4b4293a8ef2eb7c4efc28cb60ac4d12fd`.
- Browser: Google Chrome for Testing 150.0.7871.124; executable SHA-256 `2a71c17fb1e713cf02486e28fad8f8da89dcffb7d49ff234e21dee35e9f986e1`. The binary is extracted under ignored `local/`; no system browser was replaced.
- NSS certutil: Fedora `nss-tools-3.131.0-1.fc44.x86_64` extracted locally, without system installation. Chrome used a temporary profile and a temporary lab-CA NSS database via bubblewrap. Certificate and hostname verification stayed enabled.
- Browserless configurations: curl-cffi 0.16.3 `chrome150` and Go tls-client `chrome_150`, both at imitation stage 1. These profile names specify a Chrome *milestone*, not the exact `.124` build.
- Plan: `configs/chrome150_profile150_fidelity_pilot.json`, experiment `local-chrome150-profile150-fidelity-pilot-v1`: 5 Chrome train, 5 Chrome validation, 5 curl train, and 5 Go validation sessions. The independent final-test family remained reserved.

## Actual evidence

Collection completed 20/20 tasks, 20/20 captures, and 20/20 packet-complete dataset rows. It produced 21 unique packet/server joins, no event-only fallback, no unmatched sessions or family-split leaks, and zero reported capture drops among 1,021 received packets. The collector used live server run `20261027T054049Z-23a13589`.

The exploratory fidelity comparator compares per-connection value sets and replaces RFC 8701 GREASE code points with a declared placeholder in TLS cipher/extension lists. Against both browserless families, cipher-suite order, ALPN offers, TCP SYN-option order, endpoint TLS version/ALPN, and inbound H2 SETTINGS-order value sets matched. TLS extension-order sets, H2 frame-type sequences, and H2 header-name sequences differed. Chrome may generate additional connections/requests and load resources that stage-1 browserless clients do not; H2 sequence differences are therefore **not** isolated protocol-implementation differences. Extension observations require a closer canonical/order comparison before attributing them to a particular client feature.

An independent stdlib wire decoder in `src/beyond_handshake/capture_audit.py` checked the saved PCAPNG packets against the TShark TSV extraction. Across all 20 captures, it compared 80 client SYN option byte strings and 40 single-segment ClientHello cipher/extension lists; there were no mismatches, unaudited captures, or incomplete single-segment ClientHellos. This validates those selected extraction fields on this fixture, **not** TCP reassembly in general or performance under a second network path.

A separate four-session lab run (`configs/h2_audit_pilot.json`) enabled server-side TLS key logging solely for local decryption. `src/beyond_handshake/h2_audit.py` compared Wireshark's PDML decoding with endpoint events: five inbound SETTINGS frames and 29 ordered request-header-name lists agreed, with no mismatches. The audit key log remains ignored locally with mode `0600`; a server safeguard now creates optional key logs with owner-only permissions and refuses symlink targets. This is selected-fixture validation, not exhaustive H2 observer correctness across malformed or concurrent traffic.

Overall comparison status remains `approximate_not_verified`: the Chrome milestone matches the target, but neither impersonation profile pins `.124`, and complete protocol parity has not been independently established. No participant or final-test claim follows from this pilot.

## Reproduction

The Chrome archive and NSS utility stay out of Git. With Chrome extracted to ignored `local/chrome-for-testing-150.0.7871.124/` and NSS certutil extracted to ignored `local/nss-tools-3.131.0/`, start the normal loopback server, then:

```sh
UV_CACHE_DIR=/tmp/bh-uv-cache ./scripts/bh experiment plan --config configs/chrome150_profile150_fidelity_pilot.json --output data/interim/chrome150-fidelity-pilot-v1-plan.json
sg wireshark -c 'BH_CHROME_BIN=/home/rithu/Dev/networks/local/chrome-for-testing-150.0.7871.124/chrome-linux64/chrome BH_CERTUTIL=/home/rithu/Dev/networks/local/nss-tools-3.131.0/usr/bin/certutil UV_CACHE_DIR=/tmp/bh-uv-cache ./scripts/bh experiment collect --plan data/interim/chrome150-fidelity-pilot-v1-plan.json --output-dir data/interim/chrome150-fidelity-pilot-v1 --server-config configs/server.toml'
UV_CACHE_DIR=/tmp/bh-uv-cache uv run python -m beyond_handshake.capture_audit --collection-manifest data/interim/chrome150-fidelity-pilot-v1/local-chrome150-profile150-fidelity-pilot-v1/collection-manifest.json --output data/interim/chrome150-fidelity-pilot-v1/local-chrome150-profile150-fidelity-pilot-v1/independent-packet-audit.json
UV_CACHE_DIR=/tmp/bh-uv-cache uv run python -m beyond_handshake.h2_audit --collection-manifest data/interim/h2-audit-pilot-v1/local-h2-decrypt-audit-pilot-v1/collection-manifest.json --keylog local/h2-audit.keylog --output data/interim/h2-audit-pilot-v1/local-h2-decrypt-audit-pilot-v1/independent-h2-audit.json
```

The collection output directory must be new on rerun, with a new experiment ID. The original raw runs are ignored and retained locally. The H2 command requires the separate four-session keylog-enabled run and is not reproducible from the 20-session pilot's captures alone. Remaining gates include robust multi-segment TCP/TLS audit, broader H2 correctness tests, per-client CPU/peak-memory costs, additional tasks/paths, human-browser sessions, and a third independent strong client family before freezing and opening a final test.
