# Architecture Decision Records

Append-only log of hard-to-reverse decisions for Uncluster V2. Each ADR captures the *why* a decision was made and the alternatives that were considered. The code, schema, and `docs/architecture.md` describe the *what* and *how*.

ADRs are written when a decision is:
1. Hard to reverse (cost of changing your mind later is meaningful).
2. Surprising without context (a future reader would wonder why).
3. The result of a real trade-off (genuine alternatives existed).

If any of those is absent, no ADR.

## Index

| #    | Title                                                              | Status     |
| ---- | ------------------------------------------------------------------ | ---------- |
| 0001 | [OpenSSH certificate authority for access](./0001-ssh-certificate-authority.md) | accepted   |
| 0002 | [V2 clean cut over incremental pivot](./0002-v2-clean-cut-pivot.md)             | accepted   |
| 0003 | [Documentation topology — no monolithic spec](./0003-doc-topology.md)           | accepted   |
| 0004 | [Agent privilege — install-time root, steady-state low-priv](./0004-agent-privilege-model.md) | accepted   |
| 0005 | [CA private key — plaintext file at rest](./0005-ca-key-storage.md)             | accepted   |
| 0006 | [Self-update — Control plane decides, GitHub serves bytes](./0006-self-update-channel.md) | accepted   |
| 0007 | [ACL — central management, agent-reflected, both must agree](./0007-acl-central-plus-agent-reflected.md) | accepted   |
| 0008 | [Tiered E2E CI architecture](./0008-tiered-e2e-ci.md)                                                    | accepted   |
| 0009 | [AI-agent-driven validation — tiers × safety classes](./0009-ai-agent-driven-validation.md)              | accepted   |

## Format

See [grill-with-docs/ADR-FORMAT.md](../../README.md) for the template. In short: title, 1–3 sentences capturing context + decision + why. Optional sections (Status, Considered Options, Consequences) only when they add value.
