# 0005: CA private key — plaintext file at rest

**Status:** accepted

The Control plane's CA private key is written by `uncluster server bootstrap` to `$XDG_DATA_HOME/uncluster/ca` with file mode `0600`, owned by the Control plane service account. No passphrase encryption, no OS keychain integration, no HSM. Same threat posture as V1's plaintext SQLite database.

## Considered options

- **Passphrase-encrypted key with prompt at server start.** Rejected: adds friction at every boot; blocks unattended restart (which a homelab daemon should support); losing the passphrase is functionally the same as losing the key.
- **OS keychain / HSM integration** (macOS Keychain, GNOME Secret Service, YubiKey). Rejected: platform-specific code; complex; overkill for personal-scale single-operator setup.
- **Plaintext file mode 0600 (chosen).** Matches the existing security posture established for V1 SQLite token hashes. Operator owns disk-level encryption (FileVault, LUKS).

## Consequences

- Anyone with read access to `$XDG_DATA_HOME/uncluster/ca` can forge unlimited SSH certificates for any Caller + target + username combination, valid up to the cert TTL (5–15 min) after which they sign more. The Control plane host is therefore the trust crown jewel.
- The CA pubkey (`ca.pub`) is non-secret and may be copied freely; it lives on every Agent.
- Backup is the operator's responsibility; the file path is documented in `docs/architecture.md`. No `uncluster server ca export` command ships in V2.
- Rotation is a documented manual procedure (mint new CA, distribute new pubkey via heartbeat policy pull, retire old after all Agents acknowledge). Automation deferred.
