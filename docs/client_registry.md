# Client registry

This registry records the implementation family and claim boundary for each local adapter. Controller identity is separate metadata and is not a model target. A profile name describes configuration; it does not prove parity with a real browser.

| Adapter | Execution stack | Implementation family and ancestry | Protocol behavior | Status and permitted interpretation |
|---|---|---|---|---|
| `firefox` | `browser` | Mozilla Firefox / Gecko / NSS | Browser-selected TLS and HTTP version; observed at the endpoint | Real browser network stack in an isolated temporary profile. Headless scripted control remains controller metadata. |
| `curl-cffi` | `browserless` | `curl_cffi` → curl-impersonate → libcurl | Selected installed impersonation profile; commonly HTTP/2 | Strong impersonation configuration, but not an actual Chrome binary and not verified browser parity unless a matching browser comparison passes. |
| `stdlib` | `browserless` | Python `http.client` / `ssl` | HTTP/1.1 forced through ALPN | Ordinary diagnostic control, not an impersonator. |
| `go-stdlib` | `browserless` | Go `net/http` / `crypto/tls` | HTTP/2 attempted through the standard transport, with negotiated protocol reported | Independently implemented ordinary browserless family. It is not Go `tls-client` and does not claim browser impersonation. |
| `go-tls-client` | `browserless` | Go `tls-client` → fhttp / uTLS | Pinned `chrome_150` profile, HTTP/3 disabled, ordered HTTP/2/profile behavior observed at endpoint | Stage-1 impersonation configuration. Local CA verification remains enabled; profile parity must be checked against a real matching Chrome binary. |

## Go adapter build and trust boundary

The source is under `clients/go_stdlib/` and the module declares Go 1.24. `make go-client` builds the ignored local binary `local/bin/bh-go-client` with `-trimpath`. The Python bridge invokes the binary with an argument array, records `go version` from the binary, and obtains task success from the independent loopback control plane.

The Go process rejects non-loopback origins, loads only the explicitly supplied lab CA, keeps certificate and hostname verification enabled, bounds response bodies, disables automatic redirects, and validates that the server-provided item route remains inside the registered session. Build time is excluded from per-attempt execution time.

The adapter is available to development plans. It has not been collected as a final-test family, and merely adding it does not establish unseen-family generalization or research-core acceptance.

## Stage 0 and stage 1 development conditions

`configs/stages_0_1_development.json` schedules paired stage conditions with the same task seed per family/repetition:

- Stage 0 runs curl_cffi without `impersonate` or added browser headers; the Go condition uses ordinary `net/http`/`crypto/tls`.
- Stage 1 runs curl_cffi with the explicit `chrome150` profile and header template; the Go condition uses Go `tls-client` with `profiles.Chrome_150` and the same declared header values.

The Go stage comparison changes the client library as well as the fingerprint configuration. Interpret it as an ordinary-Go-to-impersonation-stack comparison, not a clean within-library treatment effect. The curl_cffi stages hold the library constant. The browser-profile header template is an experimental configuration and is not evidence of exact Chrome parity.
