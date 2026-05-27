# 0008: Tiered E2E CI architecture

**Status:** accepted

V2's load-bearing behavior is real SSH certificate auth — Caller obtains a cert from the Control plane, dials an Agent's Endpoint, and OpenSSH on the target enforces the CA + principals file (per ADR-0001, ADR-0007). Single-machine Docker Compose on one runner does not exercise that promise; full cross-OS cross-machine multi-runner orchestration on every PR does, but at high cost, slow runtimes, and rendezvous flake that AI-agent maintainers tend to paper over with retries instead of fixing.

Decision: **tiered CI by cadence**. Fast deterministic checks on every PR; cross-machine product validation nightly + `workflow_dispatch`; release-gate validation on self-hosted real hardware.

| Tier | Cadence | What runs |
|---|---|---|
| T0 | per-PR (existing matrix) | `go build / vet / test -race` on `ubuntu-latest`, `windows-latest`, `macos-latest` |
| T1 | per-PR | Docker Compose E2E on `ubuntu-latest`: Control plane + Agent + Caller containers, real sshd in Agent, full cert flow |
| T2 | per-PR (mac advisory until proven) | Per-OS install smoke: install Agent against loopback Control plane, verify service registration + heartbeat + doctor (Ubuntu / Windows / macOS) |
| T3 | nightly + `workflow_dispatch` | Cross-machine E2E via Tailscale rendezvous: Control plane + Linux/macOS/Windows Agents + Caller SSH to each |
| T4 | release | Self-hosted real hardware: reboot survival, real Windows OpenSSH, self-update rollback. `workflow_dispatch` only; never on `pull_request` |

## Considered options

- **(a) Maximalist multi-runner CI on every push.** Every PR runs the full cross-OS cross-machine flow. Catches everything but: ~$75-120/mo on hosted runners for a small-scale project, ~15-25 min runtime per PR, GHA cross-job networking is hostile (fresh VM per job; `services:` is Linux-only same-job; private networking helps Ubuntu/Windows only), AI maintainers tend to paper over rendezvous flakes with retries/skips/continue-on-error. Rejected: collapses the rendezvous-failure and product-failure into one signal.
- **(b) Conservative — Docker Compose on Ubuntu only.** Fast, cheap, simple. Rejected: V2's whole point is cross-OS cross-machine; single-machine Compose doesn't actually test the product. Per-OS install regressions (e.g. the Linux systemd unit name mismatch hotfixed as `113b747`) escape into HITL.
- **(c) Pragmatic middle — Compose + per-OS install smoke per PR, no cross-machine ever.** Better than (b) but still doesn't validate the product's marketed claim that a Caller on one OS can SSH to an Agent on a different OS.
- **(d) Tiered (chosen).** Maximal coverage at the right cadence. AI-agent-friendly because failure domains are engineered so an agent can tell rendezvous-failure from product-failure and fix the right thing.

## Consequences

- 9 implementation slices ship the ladder: T0 + T1a + T1b + T3a + T2-{linux,windows,mac-spike} + T3b + T4. See companion GitHub issues.
- **Rendezvous mechanism:** Tailscale. Aligns with Uncluster's Subnet model; supports cross-OS NAT traversal; GitHub's own private-networking docs flag Tailscale as the quickest overlay. Cloudflared/ngrok rejected — they tunnel HTTP, not the Caller→Agent SSH that Uncluster's product flow requires.
- **Tailscale auth:** workload identity federation (OIDC) preferred; OAuth client secret as fallback; static reusable ephemeral auth key only as last resort. Tailscale's GH action creates ephemeral nodes and cleans them up after the workflow completes.
- **Failure taxonomy** (the AI-agent guardrail): product failures = red required gate; rendezvous/bootstrap failures = advisory with artifacts. Workflows are written so an agent debugging a failure can immediately tell which class.
- **Quarantine rule:** 3 consecutive infra-class failures opens a `needs-triage` issue and auto-marks T3 advisory until fixed. Prevents agents from learning "add a retry" as the standard response to flakes.
- **Artifact discipline:** every role (Control plane, each Agent, Caller) uploads logs, `sshd -T`, principals files, issued cert, service status, network state on success and failure. Retention 14 days for T3 role artifacts (GH default 90 is excessive).
- **T2-mac starts as advisory.** `macos-latest` is arm64; install path mutates sshd/launchd/system users via `launchctl`/`/etc/ssh`/`dscl`/ACLs — exactly the surface hosted macOS may make difficult even when normal builds pass. Promote to required only after empirically green for N runs.
- **T4 is HITL by nature.** Rebooting a hosted runner kills its own job; reboot survival can only be validated when the rebooted machine is a *target*, not the active runner. Self-hosted hardware is the only path. T4 runs `workflow_dispatch`-only on protected branches/tags with explicit labels — never on `pull_request` (self-hosted runners + untrusted PR code = supply-chain risk per GitHub's own guidance).
- **Cost picture** at adopted shape, public-repo standard rates: per-PR (T0+T1+T2) ≈ $1.50-$2 worth of compute if billed (free on public repos); nightly T3 ≈ $0.50/run; T4 amortized over weeks. Self-hosted runners gained a $0.002/min platform charge for private repos per GitHub's Dec 2025 changelog — verify billing if the repo ever goes private.
- HITL footprint shrinks from "every PR risks an install-path regression escaping" to "release-cadence hardware validation pass." Aligns with the AI-agent-coding-era operator preference for minimizing human-in-the-loop.
