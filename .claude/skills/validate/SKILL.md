---
name: validate
description: >
  Run Uncluster's repo-owned validation (ADR-0009): execute health checks on a
  real machine, capture redacted /tmp evidence, leave a durable breadcrumb, and
  report a terse pass/fail verdict. Use when asked to "validate this machine",
  "run the validate checks", "check the install for real", or to confirm an
  agent install is healthy beyond CI. This skill ORCHESTRATES — it does not
  define "healthy"; `uncluster agent doctor --json` does.
---

# validate

Thin agent-facing wrapper over the repo-owned `uncluster validate` command. All
the logic — which checks run, what "healthy" means, evidence capture, Caller
token redaction, the durable breadcrumb, and the safety-class refusal matrix —
lives in the Go command (`internal/validate` + `internal/cli/validate_cmd.go`)
and in `uncluster agent doctor --json`. CI, this skill, and the dogfood harness
all call that ONE implementation, so there is no second definition to drift
(ADR-0009 "one source of truth for healthy"). **Do not re-implement any health
check or doctor assertion here** — always shell out to the command.

## How to run

The only invocation this skeleton wires is the read-only `inspect` / `doctor`
check on the local machine:

```bash
uncluster validate --tier local --target this-machine --checks doctor --safety inspect
```

- Exit 0 → healthy. Non-zero → unhealthy (or a safety refusal).
- Prints a one-line verdict plus the evidence dir path
  (`/tmp/uncluster-validate/<run-id>/`, mode 0700).
- Appends one line to `~/.local/state/uncluster/validation.jsonl` recording
  `{ts, commit, dirty, tier, target, checks, result, evidence_path}`.

Report the verdict line and the evidence path back to the user verbatim. If the
run failed, read the evidence dir's `check-doctor.out` (the redacted
`doctor --json`) to explain *which* checks failed.

## Safety classes (ADR-0009 Axis 2)

Pass `--safety`:

- `inspect` (default) — read-only. The only class the auto-invoke hook (#107)
  may run. Safe to run unattended.
- `bounded` — writes only to throwaway/temp scopes and self-cleans.
- `privileged` — sudo/Administrator (real install, account/service creation).
  **Refused unless you also pass `--allow-mutate`.**
- `disruptive` — reboot / self-update / deprovision. **Refused unless you also
  pass `--allow-reboot`.**

Never pass `--allow-mutate` or `--allow-reboot` automatically or from a hook.
These authorize changes to a real machine; only do so on explicit human
instruction for this specific run. (In this skeleton slice the flags only
satisfy the gate — the mutating checks themselves land in a later slice.)

## Evidence & secrets

Evidence is ephemeral (`/tmp`) and Caller tokens are redacted before anything is
written to disk. Never copy raw evidence into a durable location or paste a
Caller token into the conversation. The breadcrumb is the durable record; it
carries no secrets.
