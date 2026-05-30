# 0009: AI-agent-driven validation — tiers × safety classes

**Status:** accepted

ADR-0008 tiered the hosted CI and punted everything hosted runners structurally cannot do (real macOS launchd system daemons, reboot survival, self-update on real hardware, true multi-physical-machine flows) to "T4 = human on real hardware." Human-in-the-loop is the single most expensive way to catch a bug, and it is exactly what a test exists to avoid. This ADR replaces the human-first framing with an **AI-agent-driven** validation model: an AI coding agent (the same kind that drives the afk-runner) runs the real-machine checks and captures evidence, leaving the human as a true last resort.

Validation is described by **two orthogonal axes**: *where/who runs it*, and *how dangerous it is*.

## Axis 1 — where/who (validation tier)

- **CI check** — hosted GitHub runners, automatic every PR. ADR-0008's T0–T3 live here.
- **Local-agent check** — an AI agent runs the validation directly on one real machine it has access to. The operator develops on a real Mac, so "validate on this machine" is trivially reachable: real launchd daemon start, reboot survival, self-update all become testable where development already happens.
- **Dogfood check** — an AI agent uses Uncluster's own SSH brokering to reach *another* machine and validate there. Dogfoods the product to test the product; the only tier that exercises the real cross-OS cross-machine promise.
- **Human check** — true last resort, only what no agent can do.

## Axis 2 — how dangerous (safety class)

Independent of tier. Determines what may auto-fire vs what requires explicit authorization.

- **inspect** — read-only (build, plist-lint, `agent doctor --json`, `sshd -T`, service-status reads). The only class permitted to auto-invoke.
- **bounded** — writes only to throwaway/temp scopes and self-cleans.
- **privileged** — `sudo`/Administrator: real `agent install`, account/service creation. Manual only, explicit `--allow-mutate`.
- **disruptive** — reboot, self-update, deprovision. Manual only, explicit `--allow-reboot`, implemented as a two-phase resumable check.

## Decisions

1. **Trigger by safety class, not by tier.** A Claude Code Stop / pre-push hook may auto-invoke **only `inspect`** (read-only) checks, path-sensitive to changes under the install/daemon/self-update code. `bounded` checks write to temp scopes and self-clean but still run **manually** (they touch the filesystem, so the auto-loop stays strictly read-only). The hook must **never** auto-run `privileged` or `disruptive` checks — auto-`sudo`+reboot on every commit would brick the operator's dev machine. Those stay explicit manual invocations.

2. **Evidence ephemeral, verdict durable-but-local.** Bulky evidence (logs, doctor output, `sshd -T`, service state) goes to `/tmp/uncluster-validate/<run-id>/` (mode 0700, Caller tokens redacted). A one-line-per-run breadcrumb goes to `~/.local/state/uncluster/validation.jsonl` — `{commit, dirty, tier, target, checks, result, evidence_path}` — durable and outside the repo. No repo-checked-in validation log pre-MVP. Rationale: pure-ephemeral would make "was this validated at commit X?" unanswerable without re-running, recreating the re-validation cost this whole model exists to kill; the breadcrumb preserves the answer for ~free.

3. **One source of truth for "healthy."** Checks are defined once, in the repo, as `uncluster agent doctor --json` plus the shared `scripts/ci/classify-step.sh` taxonomy. CI, the Local-agent skill, and Dogfood all call that same surface. No third definition to drift. (Existing drift — Unix `Doctor` under-checks vs the CI inline asserts; Windows `doctor` mutates despite a "no mutations" claim — is a prerequisite to fix.)

4. **One `validate` skill that orchestrates, not defines.** Contract roughly: `validate --tier local|dogfood --target this-machine|<agent> --checks doctor,install-smoke,policy-sync,cert-flow,self-update,reboot --safety inspect|bounded|privileged|disruptive --evidence-root /tmp/uncluster-validate`. Emits a terse in-conversation verdict plus the evidence dir + jsonl breadcrumb.

5. **Dogfood always runs a plain-`ssh` control first.** Reachability via plain ssh, then `uncluster ssh`. Plain-ssh works + uncluster-ssh fails → **product-class** failure. Neither works → **transport/environment-class**, not a clean product failure. No plain-ssh control configured → "dogfood transport failed; root cause indeterminate." Without the control, a dogfood failure is uninterpretable.

6. **Reboot survival is a two-phase resumable check**, not a hook: install + arm a post-reboot marker → reboot → after reboot, verify the service resurrected and heartbeats. Automatable; the reboot kills any in-process hook, so it cannot be a Stop hook.

## Considered options

- **Self-hosted macOS VM runner (tart).** Real booted macOS in CI, fully automated. Rejected by the operator: heavier infra than the problem warrants for a solo pre-MVP project, when an AI agent already runs on a real dev Mac and can validate there directly.
- **Pure-ephemeral `/tmp` results, no durable record.** The operator's first instinct. Adjusted: keep ephemeral evidence, add the cheap non-repo breadcrumb so validation state survives the run.
- **Durable repo-checked-in validation log as a release gate.** Rejected pre-MVP as heavier than needed; revisit if the project gains contributors or a real release cadence.
- **A fifth validation tier for "dangerous" checks.** Rejected in favor of the orthogonal safety class, which expresses danger without muddying the four-tier where/who vocabulary.

## Consequences

- Most of ADR-0008's "T4 = human on hardware" becomes automated AI-agent work; Human check shrinks to what no agent can reach.
- The dev-loop hook auto-runs only read-only `inspect` checks — fast, safe, catches plist/config/build regressions early. Mutating validation is deliberate and authorized.
- Mutating Local-agent checks require a preflight snapshot + restore plan and a validation lock (no two agents mutating the same real machine concurrently). Disruptive checks must not use the operator's production Agent identity without explicit opt-in.
- The Dogfood tier inherits a bootstrap dependency: it can only run once a live Uncluster deployment + plain-ssh control exist across the operator's machines. It validates the happy path; it cannot be the *first* thing to catch "SSH brokering is broken" — that stays CI/Local-agent's job.
- Implementation tracked as GitHub issues: the doctor/CI source-of-truth consolidation (prerequisite), then the `validate` skill, then the auto-invoke hook.
