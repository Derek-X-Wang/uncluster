# 0004: Agent privilege — install-time root, steady-state low-priv

**Status:** accepted

`uncluster agent install` is a one-time privileged step (root on Unix, Administrator on Windows): writes `/etc/ssh/sshd_config.d/uncluster.conf` (and Windows equivalent), drops the CA pubkey, creates `/etc/ssh/auth_principals/`, creates a dedicated service account (`_uncluster` on macOS, `uncluster` on Linux, `NT SERVICE\UnclusterAgent` on Windows), and registers the service. Steady-state, the Agent process runs as that service account. The only privilege it needs is **write access to the principals directory**, granted via filesystem ACL.

Sshd reads `AuthorizedPrincipalsFile` per login attempt, so no reload is needed when principals change. No sudoers rule, no privileged restart hook, no long-running root process.

## Considered options

- **Fully autonomous root.** Agent runs as root indefinitely (like Tailscale's `tailscaled`, Docker's daemon). Rejected: long-running root for a security-adjacent process is too wide a blast radius even at personal scale.
- **Operator-mediated install.** Agent prints sudo commands for the operator to copy. Rejected: error-prone, bad UX, copy-paste typos break enrollment.
- **Privileged install + unprivileged steady-state with sudoers** (initial proposal). Rejected as overkill — sshd doesn't require reload for principal changes, so the sudoers rule was solving a non-problem.
- **Privileged install + unprivileged steady-state via dir ACL (chosen).** Service account owns nothing system-wide; only the principals dir grants it write access.

## Consequences

- Install requires root/Administrator and writes to system config (sshd_config.d, service registry). This is the one-time price of cross-platform gatekeeping.
- The Agent process itself cannot escalate privilege; a compromise yields only principals-file writes (which the policy already mirrors centrally — a defense-in-depth invariant per ADR-0007).
- Service account creation differs per platform: documented in `docs/architecture.md` operational lifecycle section.
- Re-running `uncluster agent install` on an already-enrolled host is idempotent and self-healing (rewrites missing config files, leaves intact ones).
