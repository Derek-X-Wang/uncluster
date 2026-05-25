# CLAUDE.md

Agent instructions for the Uncluster repo.

## V2 design — read in this order

Uncluster is mid-pivot to V2 (OpenSSH cert-authority gatekeeper model). V1 task-execution code still lives in the tree but is being removed per ADR-0002. Read these to build a mental model before touching code:

1. **[`/CONTEXT.md`](./CONTEXT.md)** — vocabulary and relationships. Defines Agent, Control plane, Caller, Caller token, SSH certificate, Subnet, Endpoint, Audit event, Policy. Use these exact terms.
2. **[`/docs/architecture.md`](./docs/architecture.md)** — current-state narrative. System purpose, components, end-to-end cert flow, ACL/Policy sync, operational lifecycle, threat model, implicit invariants.
3. **[`/docs/adr/`](./docs/adr/)** — decision rationale. Start with [`README.md`](./docs/adr/README.md) for the index. ADR-0001 through 0007 cover the load-bearing V2 decisions.
4. **[`/api/openapi.yaml`](./api/openapi.yaml)** — wire contract source of truth.
5. **[`/ACCEPTANCE.md`](./ACCEPTANCE.md)** — V2 definition of done; cross-references each slice issue.
6. **V1 spec is archived at** [`/docs/superpowers/specs/archive/2026-04-23-uncluster-v1-design.md`](./docs/superpowers/specs/archive/2026-04-23-uncluster-v1-design.md) — SUPERSEDED; reference only for historical context.

Open work tracked as GitHub issues #1–#18 (slice graph in their bodies); critical path to MVP: #1 → #3 → #4 → #5 → #6 → #9 → #10 → #11 → #12.

When adding new code: prefer the V2 vocabulary and shapes from above. Do not preserve V1 compatibility — slice #15 deletes V1 entirely.

## Agent skills

### Issue tracker

GitHub Issues via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical default vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
