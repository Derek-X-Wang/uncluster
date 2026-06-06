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

## Windows amendment (#127): role-split — low-priv agent + LocalSystem principals writer

The "steady-state low-priv service account writes the principals dir directly" model holds on Unix but **breaks on Windows**. Win32-OpenSSH routes `AuthorizedPrincipalsFile` through a secure-permission check (`w32-sshfileperm.c check_secure_file_permission`) that silently *ignores* the file — denying login even with the correct principal present — unless **both**:

1. the file's **owner** is one of {Administrators, SYSTEM, the connecting user, TrustedInstaller}; and
2. **no principal outside that set holds any write-class right** (`FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_WRITE_EA`, `FILE_WRITE_ATTRIBUTES`, `WRITE_DAC`, `WRITE_OWNER`, `DELETE`).

Win32-OpenSSH does **not** exempt service/virtual accounts. So a `NT SERVICE\UnclusterAgent` write ACE on the file — or that account as owner — itself trips rule (2)/(1). And producing a file with owner=Administrators from the low-priv account requires `SeRestorePrivilege`/`SeTakeOwnershipPrivilege`, which it does not hold. There is no DACL-only fix: any path by which the low-priv agent can write the file content is exactly the write right sshd rejects.

**Decision: split the roles on Windows.** Two services:

- **`UnclusterAgent`** — stays `NT SERVICE\UnclusterAgent` (low-priv, network-facing). It enrolls, heartbeats, fetches and **validates** Policy. It **no longer holds any write access to `auth_principals`**; install removes that grant. It hands a validated desired-state to the writer and reports applied status back to the control plane.
- **`UnclusterPrincipalsWriter`** — a new **LocalSystem** service, no network, single fixed purpose: consume the agent's desired-state, render per-user principals files **owned by SYSTEM** (a LocalSystem process creates SYSTEM-owned files natively, so **no `SeRestore` is needed** — owner=SYSTEM satisfies rule 1), with a PROTECTED DACL of {SYSTEM: full, Administrators: full} and inheritance stripped (rule 2). It verifies the result and reports `applied_version`/`hash`. It writes **only** under `C:\ProgramData\ssh\auth_principals`; path, owner, and DACL are hardcoded — never taken from the payload. It re-validates every username/principal (charset, no traversal) before writing.

**Rejected — grant the agent `SeRestorePrivilege` (a single privilege, in-process).** `SeRestore` allows writing any file regardless of ACL and setting any owner SID — effectively machine-owner. It is *worse* than running the agent as LocalSystem outright, because it preserves the **fiction** of a bounded low-priv agent while handing it a system-wide compromise primitive. Running the agent as LocalSystem (option A) is an *honest* but ADR-0004-gutting stopgap, acceptable only as an explicitly-documented temporary bridge — never `SeRestore`.

**Threat-model note.** The split does not stop a compromised agent from *requesting* forged principals (it could already; principals authority is inherent to the agent's job, and ADR-0007 mirrors policy centrally as the defense). What the split *does* preserve is the load-bearing ADR-0004 property: **a compromised network-facing agent cannot become machine-owner.** The writer is the only privileged surface, and it is small, network-less, fixed-path, and privilege-stripped via `SERVICE_REQUIRED_PRIVILEGES_INFOW` so SCM removes every privilege it does not need.

This amendment is Windows-only; Unix/macOS keep the original dir-ACL model unchanged.
