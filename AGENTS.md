# Repository instructions

- Follow `docs/MASTER_BUILD_DOCUMENT.md` for project scope, phase order, data contracts, and permitted claims.
- Phases 0–12 have prototype components, but phase acceptance is evidence-based. Do not describe this as a completed detector or as PCAP-validated until raw capture and the remaining gates pass.
- Keep the prototype local-only by default. Never disable certificate verification in client examples.
- Do not put participant data, raw packet captures, TLS key logs, generated certificates, private keys, model files, or raw run artifacts in source control.
- Preserve the separation between labels/metadata and model features in later phases.
- When a coding agent finishes a phase, update `docs/progress.md` with actual files, commands, outcomes, and remaining gaps. Never invent test results.
