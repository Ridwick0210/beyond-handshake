# Initial experiment protocol

**Version:** draft 0.1 · 21 October 2026 · **Status:** development protocol only

## Research question

Which server-observable signals remain useful for distinguishing browserless automation from a real browser stack after TLS and HTTP/2 impersonation, across unseen client implementations and environments? A secondary question measures runtime and resource costs as imitation becomes more complete.

## Target and labels

- Positive class: a browserless HTTP client performing the task.
- Negative class: a real browser network stack, whether manually operated or controlled by automation.
- Controller (`human`, `script`, or optionally `llm`) is a separate factor, not the primary label.
- “Browserless-like” is a stack classification; it is not proof of AI identity, intent, or maliciousness.

## Initial design

The first prototype serves a local HTTPS endpoint that terminates TLS itself. It supports HTTP/1.1 only. The endpoint logs connection metadata, ordered request header names, normalized routes, status, and server-side request timings. Values of sensitive headers are redacted by default. The server binds to loopback and uses a locally generated CA trusted explicitly by the client.

This prototype does not yet collect packet-level TCP signals, a reassembled TLS ClientHello fingerprint, HTTP/2 settings, browser activity, task success, or cost measurements. These are planned additions and must be verified before being used in a claim.

## Development pilot

Use one manually operated Chrome session and one ordinary HTTP client only to validate TLS trust, routing, event writing, and inspectable logs. Such a comparison is an easy engineering check and is not the primary research comparison. Do not train a classifier from it.

## Research evaluation planned

Compare TLS-only, TLS + HTTP/2, then additional TCP and application behavior on the same eligible sessions. Evaluate strong impersonators separately from naive clients. Group repeated sessions and capture blocks. Reserve a true implementation family for an untouched final test. Balance task, host OS, path, and collection order where possible. Report completion, coverage, false-positive counts, uncertainty, and cost along with detection metrics.

## Exclusions and amendments

No development pilot is research evidence. Measurement failures remain in an audit ledger. Task failure is not automatically a measurement exclusion. Changes to labels, observation window, features, or splits require a decision record and a new test cohort if the original final test has already been inspected.
