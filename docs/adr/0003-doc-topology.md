# 0003: Documentation topology — no monolithic spec

**Status:** accepted

V2 has no single design-spec document. The design surface is partitioned by job:

- `CONTEXT.md` — vocabulary and relationships (present-tense definitional).
- `docs/architecture.md` — current-state narrative, end-to-end flows, threat model (present-tense descriptive, ≤ 4 pages).
- `docs/adr/` — one ADR per hard-to-reverse decision with rationale and rejected alternatives (past-tense decisional).
- `api/openapi.yaml` — wire contract (present-tense normative).
- `ACCEPTANCE.md` — definition-of-done checklist (present-tense verifiable).
- `docs/superpowers/plans/*.md` — execution plans on demand, throwaway-ish.

## Considered options

- **Monolithic V2 spec document** (like the V1 spec at ~800 lines). Rejected: drifts from code; layered amendments lose decision provenance; AI agents that read fragmented docs do better with smaller, well-named files than one large file.
- **No documentation, code only.** Rejected after Codex pushback: ADRs are archaeology ("when did we decide X"), not onboarding ("what is the system now"). A current-state narrative is genuinely missing without `architecture.md`.
- **Partitioned doc surface (chosen).** Each doc has a single job; readers compose mental model from the index in CLAUDE.md.

## Consequences

- The Mattpocock skill family (`improve-codebase-architecture`, `tdd`, `diagnose`) natively reads `CONTEXT.md` + `docs/adr/`. This topology is on the well-trodden path for the operator's toolchain.
- Onboarding a new contributor or AI agent requires reading several files in order. CLAUDE.md must point at them in the right sequence (CONTEXT.md for language → architecture.md for shape → ADRs for rationale → openapi.yaml for wire → ACCEPTANCE.md for done criteria).
- Acceptance criteria scattering risk: mitigated by `ACCEPTANCE.md` as the single checklist.
- ADR `0001-007` plus this one are the baseline; future ADRs only when a decision is hard to reverse, surprising without context, and the result of a real trade-off.
