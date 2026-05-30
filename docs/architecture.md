# Uncluster V2 Architecture

Current-state narrative of how the system works. Names follow `CONTEXT.md`. Rationale for choices lives in `docs/adr/`. Wire contract is `api/openapi.yaml`. Definition of done is `ACCEPTANCE.md`.

## 1. System purpose

Uncluster turns a small group of personal machines into a managed pool of SSH-reachable compute. An **Agent** runs on each device and gatekeeps inbound SSH access. A **Control plane** acts as the SSH certificate authority and as the registry of who-can-reach-what. **Callers** — typically AI assistants on a workstation (e.g. Claude Code) — ask the Control plane for a short-lived SSH certificate for a target, then SSH directly. No custom transport, no exec on the agent — SSH carries the session.

## 2. Components

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          operator's workstation                              │
│                                                                              │
│   uncluster CLI (Caller token + SSH keypair)                                │
│         │                                                                    │
│         │ POST /v1/certs   GET /v1/agents/{id}                              │
│         ▼                                                                    │
└─────────┼────────────────────────────────────────────────────────────────────┘
          │ HTTPS                              ▲ SSH (with cert)
          ▼                                    │
┌─────────────────────────────────┐            │
│       Control plane             │            │
│   uncluster server start         │            │
│   ├── HTTP API (chi router)     │            │
│   ├── SQLite (XDG_DATA_HOME)    │            │
│   │     ├── agents              │            │
│   │     ├── agent_subnets       │            │
│   │     ├── agent_endpoints     │            │
│   │     ├── tokens              │            │
│   │     ├── acl                 │            │
│   │     ├── agent_policy_state  │            │
│   │     └── cert_issuance_events│            │
│   └── CA private key (0600)     │            │
└─────────────────────────────────┘            │
       ▲                                       │
       │ heartbeat (10s) + register / update-plan
       │                                       │
┌──────┴──────────┐  ┌─────────────────┐  ┌────┴────────────┐
│ Agent (macOS)   │  │ Agent (Linux)   │  │ Agent (Windows) │
│ launchd unit    │  │ systemd unit    │  │ SCM service     │
│ user _uncluster │  │ user uncluster  │  │ NT SERVICE\...  │
│                 │  │                 │  │                 │
│ Maintains:      │  │ (same as left)  │  │ (same; paths    │
│  /etc/ssh/      │  │                 │  │  under          │
│   uncluster_ca  │  │                 │  │  C:\ProgramData\│
│   sshd_config.d │  │                 │  │  ssh\)          │
│   auth_princip- │  │                 │  │                 │
│   als/<user>    │  │                 │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

The Agent's job is narrow: heartbeat → receive Policy → write principals files. It never participates at the SSH login moment; sshd does the auth itself using the CA pubkey + principals files the Agent maintains.

## 3. Happy-path SSH cert flow

```
caller (Claude Code)            Control plane                  agent (windows-rig)
       │                              │                                 │
       │  GET /v1/agents/windows-rig  │                                 │
       │  Authorization: caller token │                                 │
       │ ────────────────────────────►│                                 │
       │ ◄── {endpoints, subnets}     │                                 │
       │                              │                                 │
       │  POST /v1/certs              │                                 │
       │  {agent, username, pubkey, ttl}                                │
       │ ────────────────────────────►│                                 │
       │                              │  resolve name→id                │
       │                              │  ACL row check                  │
       │                              │  ca.Sign(pubkey, principal=     │
       │                              │            caller_token_id,     │
       │                              │            ttl≤900s)            │
       │                              │  write cert_issuance_events     │
       │ ◄── {cert, valid_after,      │                                 │
       │      valid_before, key_id}   │                                 │
       │                              │                                 │
       │  ssh -i id_ed25519           │                                 │
       │      -o CertificateFile=...  │                                 │
       │      derek@<endpoint>        │                                 │
       │ ──────────────────────────────────────────────────────────────►│
       │                              │            sshd checks:         │
       │                              │            1. cert signed by ca.pub? ✓
       │                              │            2. valid_after ≤ now ≤ valid_before? ✓
       │                              │            3. cert principal ∈ /etc/ssh/auth_principals/derek? ✓
       │                              │            → shell opens
       │ ◄────────────── shell session ────────────────────────────────►│
```

Notes:
- The Agent is not in the request path at SSH login time. It already wrote the principals file via a prior heartbeat. The Control plane is not in the request path either — only sshd validates.
- `valid_after = now - 30s` (clock skew defense).
- The cert principal is the Caller's token ID, opaque (`caller_k4m...`). The unix username `derek` is independent — sshd matches "is any cert principal listed in `auth_principals/derek`?"

## 4. ACL → Policy sync

The Control plane is the source of truth for **ACL rows**: `(caller_token_id, agent_id, username) → allow`. For each Agent, the projection of that ACL is the **Policy** — `{unix_username: [caller_token_id, ...]}`. The Policy is versioned (monotonic `policy_version`) and hashed (blake3 over canonicalized JSON) per Agent.

```
operator: uncluster acl grant claude-mbp windows-rig --as derek
       │
       ▼
Control plane: INSERT INTO acl ... ; policy_version[windows-rig]++
       │
       ▼ (≤ 10s — next heartbeat)
Agent (windows-rig) heartbeats with applied_hash=H_old
       │
       ▼
Control plane: H_old ≠ H_new → response carries
                {policy: {version: V, hash: H_new, principals: {derek: [caller_...], root: [...]}}}
       │
       ▼
Agent atomic apply:
  for (user, principals) in policy:
    validate principal charset (no newline/whitespace/comma/glob)
    write /etc/ssh/auth_principals/<user>.tmp, fsync, rename
  for user not in policy:
    rm /etc/ssh/auth_principals/<user>
  record (applied_version=V, applied_hash=H_new, last_apply_status="ok")
       │
       ▼ (next heartbeat reports applied_version=V → server sees match → policy: null)
```

If `applied_status="failed"`, `applied_version` does not advance; Control plane keeps re-sending policy until a successful apply is reported.

## 5. Operational lifecycle

### 5.1 Bootstrap

```
$ uncluster server bootstrap --db ~/.local/share/uncluster/uncluster.db
[1/3] Generating ed25519 CA keypair                ok
[2/3] Writing ca.pub  + ca (mode 0600)             ok
[3/3] Minting first caller token                   ok

ca pubkey:  ssh-ed25519 AAAAC3Nz...
caller token (shown ONCE): uct_caller_k4m8j3x2_9f2a...

$ uncluster server start --addr :17777 &
```

### 5.2 Enroll an Agent

```
# on server
$ uncluster server token create --kind=join --label=windows-rig
uct_join_xxx (15 min, single-use)

# on target, Administrator/sudo
$ pbpaste | sudo uncluster agent install \
    --server=https://uncluster.home.example.com:17777 \
    --name=windows-rig \
    --subnet=home-tailnet \
    --subnet=home-lan \
    --token-stdin
[1/8] Verifying sshd installed                                  ok
[2/8] Registering with control plane                            ok (agent_id=ag_01J...)
[3/8] Writing CA pubkey                                         ok
[4/8] Writing sshd_config drop-in                               ok
[5/8] Creating principals dir + ACL for service account         ok
[6/8] Creating service account                                  ok
[7/8] Installing service (auto-start enabled)                   ok
[8/8] Starting service                                          ok
```

### 5.3 Grant access

```
# on operator workstation
$ uncluster acl grant claude-mbp windows-rig --as derek
# ≤ 10s later, /etc/ssh/auth_principals/derek on windows-rig contains caller_k4m...
```

### 5.4 SSH

```
$ uncluster ssh windows-rig -- whoami
derek
```

### 5.5 Revoke (safe)

```
# revoke just the ACL row — agent stays online
$ uncluster acl revoke claude-mbp windows-rig --as derek
# principal removed from auth_principals/derek within 10s; future logins fail
```

### 5.6 Deprovision a whole Agent

```
$ uncluster agents rm windows-rig
# control plane: 410 response on next heartbeat
# agent: wipes principals, writes .deprovisioned marker, exits; supervisor doesn't restart
```

### 5.7 CA rotation (manual procedure, no automation in V2)

1. `uncluster server ca generate --new` writes `ca.next` alongside `ca`.
2. Control plane signs new certs with new CA, distributes new pubkey via heartbeat policy pull. Agents append to `uncluster_ca.pub` (`TrustedUserCAKeys` accepts multiple keys).
3. Operator confirms all Agents have ack'd new pubkey.
4. `uncluster server ca retire-old` removes old key; Agents drop old pubkey on next pull.

### 5.8 Self-update

```
# operator publishes a new version
$ uncluster server update set --version=v2.0.2 \
    --asset-url-template='https://github.com/Derek-X-Wang/uncluster/releases/download/{version}/uncluster-{os}-{arch}' \
    --sha256-url-template='https://github.com/Derek-X-Wang/uncluster/releases/download/{version}/checksums.txt'

# each Agent on next heartbeat:
# - receives check_update command pointer
# - GETs /v1/agent/update-plan
# - downloads binary + checksum file
# - verifies SHA256
# - atomic swap (POSIX rename / Windows .new/.old)
# - service supervisor restarts
# - on failure-to-start (30s window), wrapper reverts to previous binary
```

## 6. Threat model

| Threat | Mitigation |
|---|---|
| **Control plane disk leak** | CA private key + token hashes exposed. Operator owns FileVault / LUKS. Cert TTL keeps blast radius bounded to TTL window per cert; tokens hashed (argon2id). |
| **Control plane host compromise** | Attacker can sign arbitrary certs. Per ADR-0007, Agents still gate via principals files — the rogue cert's principal must already be in the target's principals file or it fails to log in. Limits damage to "callers already permitted somewhere." |
| **Caller token leak** | Attacker can request certs for whatever the token's ACL allows. Mitigations: short cert TTL (5–15 min), token revocation surface (`uncluster server token revoke`), audit log shows abnormal issuance. |
| **Caller SSH private key leak** | Attacker still needs the Caller token to obtain a cert over the stolen pubkey. Token is the durable gate. |
| **Agent token leak** | Attacker can heartbeat as the Agent (poison `last_seen_at`, observe policy). Cannot grant access (ACL is server-owned). Operator detects via stale `last_apply` reports / suspicious metrics; revokes via `agents rm`. |
| **Agent compromised** | Service account can write principals files. Defense: Policy from Control plane overwrites local edits on next heartbeat (apply is rewrite, not merge). Attacker can briefly add principals; operator detects via audit log of `cert_issuance_events` (or the lack of corresponding ACL row in the Control plane). |
| **CA private key leak** | All certs forgeable until CA rotated. Single highest-value secret. Operator notified by anomaly detection (cert issuance with no API call). Recovery = bootstrap new CA, redistribute pubkey to all Agents, retire old. |
| **Stolen + revoked-but-cached cert** | Cert valid until `valid_before`. No KRL in V2 — operator accepts up-to-TTL exposure (default ≤ 5 min). |
| **Compromised heartbeat (MITM)** | TLS protects the channel. Optional `server_https_pin` returned at enrollment lets Agents pin Control plane's TLS cert fingerprint and refuse to follow rogue replacements. |
| **Agent offline → stale Policy** | Optional `fail-closed-after` per Agent: after N hours offline, Agent wipes principals (deny everything). Default lenient. |

## 7. Implicit invariants

- **Subnet is reachability data, not authorization.** A Caller declaring it can reach `home-tailnet` is unverified; the network does the real gating. `subnet` is not a permission scope and never appears in cert requests.
- **An Agent does not participate at the moment of SSH login.** Agent's only steady-state job is the principals file. sshd performs the actual auth using the CA pubkey + that file.
- **Caller token = durable identity.** SSH keypair = ephemeral artifact that gets signed. Rotate the keypair freely; rotate the token only when leaked or assigned to a new entity.
- **Cert principal = caller token ID, opaque.** Never a username, never a human-readable label. One principal per cert.
- **Apply is rewrite, not merge.** Agent atomic Policy apply replaces files in full; user files absent from Policy are deleted from disk. This makes the Agent's view drift-free relative to central truth.
- **Bidirectional version handshake.** Heartbeat carries both `desired_version` (last seen from server) and `applied_version` (what's actually on disk). Codex pushback resolved: "received policy" ≠ "successfully applied policy."

## 8. Where each concern lives in code

| Concern | Code |
|---|---|
| CA crypto | `internal/ca/` |
| Cert signing endpoint | `internal/server/handlers_certs.go` |
| ACL CRUD + projection | `internal/server/handlers_acl.go`, `internal/server/policy.go` |
| Heartbeat handler + envelope | `internal/server/handlers_agent.go`, `internal/api/types.go` |
| Audit writes | `internal/server/audit.go` |
| Agent install + sshd config + service | `internal/gatekeeper/` (`install_unix.go`, `install_windows.go`, `install_launchd_*.go`, `service_*.go`, `install_drift.go`) |
| Agent principals apply (Policy → files) | `internal/agent/policy.go` |
| Agent self-update | `internal/agent/selfupdate.go`, `internal/agent/updatehost.go` |
| Agent health diagnose (`doctor`) | `internal/gatekeeper/doctor_*.go`, `internal/gatekeeper/health.go` (`DoctorResults.HealthChecks` — the one doctor→wire mapping shared by heartbeat, `doctor --json`, and `validate`) |
| Validation tool (`uncluster validate`, ADR-0009) | `internal/validate/`, `internal/cli/validate_cmd.go`, skill at `.claude/skills/validate/` |
| `uncluster ssh` wrapper | `internal/cli/ssh_cmd.go` |
| `uncluster acl ...` | `internal/cli/acl_cmd.go` |
| `uncluster audit ...` | `internal/cli/audit_cmd.go` |
| Schema migrations | `internal/store/migrations.go` |

## 9. First-run security guidance

- **macOS Gatekeeper.** First run of an unsigned `uncluster` binary is blocked. Resolve by right-click → Open in Finder once; subsequent runs are whitelisted. Documented in install output of `uncluster agent install`.
- **Windows SmartScreen.** First run of an unsigned `.exe` is blocked. Resolve by right-click → Properties → Unblock, or `Unblock-File` in PowerShell. Documented in Windows install output.
- **Apple notarization and Windows code signing are not provided in V2.** The trust model is "operator built/downloaded the binary from an authoritative source they control."

## 10. Backup

The operator owns backup of two assets:

- `$XDG_DATA_HOME/uncluster/ca` — the CA private key. Loss = re-provision pubkey on every Agent.
- `$XDG_DATA_HOME/uncluster/uncluster.db` — the SQLite registry. Loss = lose ACL, audit history, agent registrations. Re-enrollment of Agents required.

Both are plain files; any backup tool (Time Machine, restic, rsync) works. No tooling shipped in V2.
