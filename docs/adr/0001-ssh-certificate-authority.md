# 0001: OpenSSH certificate authority for access

**Status:** accepted

The Control plane is an OpenSSH user certificate authority. Each Agent's sshd is configured once with `TrustedUserCAKeys /etc/ssh/uncluster_ca.pub` plus `AuthorizedPrincipalsFile`. On a Caller's request, the Control plane signs a short-lived (default 5 min, max 15 min) certificate over the Caller's existing SSH pubkey. The Caller presents `key + cert` to the target's sshd; sshd accepts if the cert is signed by the trusted CA, has not expired, and carries a principal listed in the target user's `AuthorizedPrincipalsFile`.

## Considered options

- **Authorized_keys management.** Control plane tells each Agent to add/remove pubkeys per Caller. Rejected: per-login mutation, race conditions, weak revocation (rewrite file), accumulated cruft, every grant changes target state.
- **Tailscale SSH delegation.** Let Tailscale ACLs do the auth. Rejected: locks the project to Tailscale; doesn't work on plain LAN or when Tailscale is blocked; the operator's two-tailnet setup splits ACLs anyway.
- **SSH certificate authority** (chosen). Standard OpenSSH primitive; revocation = short TTL + principal removal; one-time sshd config per device; audit log = CA issuance log.

## Consequences

- Control plane holds a high-value secret (the CA private key). Loss = re-provision the CA pubkey on every Agent. See ADR-0005.
- Each Agent requires one-time privileged sshd configuration. See ADR-0004.
- The Caller's existing SSH keypair is reused — Uncluster signs a certificate over it, doesn't replace it.
- KRL (Key Revocation List) is deferred to post-V2. V2 revocation = TTL expiry + principal removal at next policy sync.
