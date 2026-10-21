# Initial experiment protocol

**Version:** draft 0.2 · 22 October 2026 · **Status:** development protocol only

## Research question

Which server-observable signals remain useful for distinguishing browserless automation from a real browser stack after TLS and HTTP/2 impersonation, across unseen client implementations and environments? A secondary question measures runtime and resource costs as imitation becomes more complete.

## Target and labels

- Positive class: a browserless HTTP client performing the task.
- Negative class: a real browser network stack, whether manually operated or controlled by automation.
- Controller (`human`, `script`, or optionally `llm`) is a separate factor, not the primary label.
- “Browserless-like” is a stack classification; it is not proof of AI identity, intent, or maliciousness.

## Initial design

The current pilot serves a local HTTPS endpoint that terminates TLS itself and supports HTTP/1.1 plus HTTP/2. It logs TLS metadata, ordered/redacted headers, and structural H2 frame/SETTINGS events. One deterministic catalog workload has a server-side success oracle, and two browserless adapters can execute it. This is not a research dataset: packet-level TCP signals, reassembled TLS ClientHello fingerprints, packet-to-socket joining, a real browser runner, multiple independent client families, and cost accounting are still absent.

## Development pilot

Use the ordinary HTTP/1.1 control and one explicit `curl_cffi` profile only to validate TLS trust, routing, event writing, H2 observation, and inspectable logs. A real browser pilot requires a pinned browser and isolated per-profile CA trust setup. Such comparisons are engineering checks only; do not train a classifier from them.

## Research evaluation planned

Compare TLS-only, TLS + HTTP/2, then additional TCP and application behavior on the same eligible sessions. Evaluate strong impersonators separately from naive clients. Group repeated sessions and capture blocks. Reserve a true implementation family for an untouched final test. Balance task, host OS, path, and collection order where possible. Report completion, coverage, false-positive counts, uncertainty, and cost along with detection metrics.

## Exclusions and amendments

No development pilot is research evidence. Measurement failures remain in an audit ledger. Task failure is not automatically a measurement exclusion. Changes to labels, observation window, features, or splits require a decision record and a new test cohort if the original final test has already been inspected.
