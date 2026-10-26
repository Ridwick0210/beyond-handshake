# Client registry

This registry records the implementation family and claim boundary for each local adapter. Controller identity is separate metadata and is not a model target. A profile name describes configuration; it does not prove parity with a real browser.

| Adapter | Execution stack | Implementation family and ancestry | Protocol behavior | Status and permitted interpretation |
|---|---|---|---|---|
| `firefox` | `browser` | Mozilla Firefox / Gecko / NSS | Browser-selected TLS and HTTP version; observed at the endpoint | Real browser network stack in an isolated temporary profile. Headless scripted control remains controller metadata. |
| `curl-cffi` | `browserless` | `curl_cffi` → curl-impersonate → libcurl | Selected installed impersonation profile; commonly HTTP/2 | Strong impersonation configuration, but not an actual Chrome binary and not verified browser parity unless a matching browser comparison passes. |
| `stdlib` | `browserless` | Python `http.client` / `ssl` | HTTP/1.1 forced through ALPN | Ordinary diagnostic control, not an impersonator. |
| `go-stdlib` | `browserless` | Go `net/http` / `crypto/tls` | HTTP/2 attempted through the standard transport, with negotiated protocol reported | Independently implemented ordinary browserless family. It is not Go `tls-client` and does not claim browser impersonation. |
| `go-tls-client` | `browserless` | Go `tls-client` → fhttp / uTLS | Pinned `chrome_150` profile, HTTP/3 disabled, ordered HTTP/2/profile behavior observed at endpoint | Stages 1–3 use the same verified local CA. Profile parity must be checked against a real matching Chrome binary. |

## Go adapter build and trust boundary

The source is under `clients/go_stdlib/` and the module declares Go 1.24. `make go-client` builds the ignored local binary `local/bin/bh-go-client` with `-trimpath`. The Python bridge invokes the binary with an argument array, records `go version` from the binary, and obtains task success from the independent loopback control plane.

The Go process rejects non-loopback origins, loads only the explicitly supplied lab CA, keeps certificate and hostname verification enabled, bounds response bodies, disables automatic redirects, and validates that the server-provided item route remains inside the registered session. Build time is excluded from per-attempt execution time.

The adapter is available to development plans. It has not been collected as a final-test family, and merely adding it does not establish unseen-family generalization or research-core acceptance.

## Stage 0 and stage 1 development conditions

`configs/stages_0_1_development.json` schedules paired stage conditions with the same task seed per family/repetition:

- Stage 0 runs curl_cffi without `impersonate` or added browser headers; the Go condition uses ordinary `net/http`/`crypto/tls`.
- Stage 1 runs curl_cffi with the explicit `chrome150` profile and header template; the Go condition uses Go `tls-client` with `profiles.Chrome_150` and the same declared header values.

The Go stage comparison changes the client library as well as the fingerprint configuration. Interpret it as an ordinary-Go-to-impersonation-stack comparison, not a clean within-library treatment effect. The curl_cffi stages hold the library constant. The browser-profile header template is an experimental configuration and is not evidence of exact Chrome parity.

## Stage 2 and stage 3 development conditions

`configs/stages_2_3_development.json` schedules 10 paired curl_cffi I2/I3 repetitions in train, 10 paired Go tls-client I2/I3 repetitions in validation, and 10 Firefox references in each partition. Each I2/I3 pair uses the same task seed and performs two task visits in one client session. Each family stays in one partition. This gives I2 and I3 the same navigation/task workload before resource fetching is added. I2 adds a revisit relative to I1, but not a new cookie or connection toggle: curl_cffi I1 already uses a persistent `requests.Session`, and Go tls-client I1 already retains its client/transport. Go I2 does not claim an explicit cookie jar.

I3 fetches stylesheet, script, and image URLs discovered in task HTML; it follows CSS `url(...)` references; caps discovery at 32 resources per page; restricts requests to the same HTTPS origin and session asset path; and uses an in-memory cache only when the server explicitly returns `Cache-Control: max-age`. Static task assets use a one-hour policy; task/API responses remain `no-store`. The cache survives the second visit within an attempt. Both adapters load resources sequentially, so this is a bounded emulation of the controlled local page, not browser-equivalent scheduling or cache behavior. Resource counts are evaluation metadata, never model features. See `docs/stages_2_3_report.md` for observed results and limits.
