# 0007: ACL — central management, agent-reflected, both must agree

**Status:** accepted

The ACL (`(caller_token_id, agent_id, username) → allow`) is owned by the Control plane: one source of truth, one CLI surface (`uncluster acl grant/revoke/ls`). Each Agent receives a projection of the ACL — its **Policy** — via heartbeat response, materializing it into `AuthorizedPrincipalsFile` entries under `/etc/ssh/auth_principals/<user>`. SSH login at the target requires *both* a valid CA-signed cert *and* the cert's principal to be listed in the target user's principals file. If either layer says no, login fails.

## Considered options

- **Central-only ACL.** Control plane is the sole gate; Agent trusts any valid CA cert. Rejected: makes the Agent's "Gatekeeper" role nominal; if the Control plane is compromised and signs a rogue cert, no local defense.
- **Agent-owned ACL.** Each Agent declares its own allowlist; Control plane reflects whatever Agents say. Rejected: distributed UX (change a permission = edit on a device); fan-out queries for "what can X reach" become expensive.
- **Central + agent-reflected, both must agree (chosen).** Central is the management surface; Agent's principals file is the local veto. Compromised Control plane → no escalation: rogue cert's principal isn't in the target's file → sshd rejects.

## Consequences

- Two layers stay in sync via heartbeat (typically 10s drift). Disconnected Agents retain stale Policy until reconnect; per-Agent `fail-closed-after` configuration is opt-in (see S5 / `uncluster agents set --fail-closed-after`).
- Principal in cert = the Caller's opaque token ID (e.g. `caller_k4m8j3x2`), one principal per cert. Principals file lines = the same opaque IDs.
- ACL change → next Agent heartbeat (≤10s) → principals file rewritten atomically → future logins reflect the change. Existing SSH sessions are unaffected.
- "Defense in depth" is the load-bearing reason for the redundancy; do not collapse to a single layer without an ADR overturning this one.
