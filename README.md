# Uncluster

A lightweight personal compute layer: treat a handful of your own machines as a
pool you can reach over SSH, without copying long-lived keys around. A thin
**Control plane** acts as an SSH **certificate authority**; a minimal **Agent**
on each device gatekeeps inbound SSH; AI **Callers** (e.g. Claude Code on your
laptop) obtain short-lived, signed SSH certificates to connect.

> **Status:** pre-MVP. V2 (the cert-authority model below) is code-complete and
> CI-validated on Linux/macOS/Windows; real cross-machine dogfooding is in
> progress. Expect rough edges.

## Why not just plain SSH?

Plain SSH optimizes for "get me in." Uncluster optimizes for **least-privilege,
revocable, audited access** — which is what handing SSH to AI agents demands:

- **No standing keys.** Callers present a certificate with a 5-minute TTL
  (15 max), not a key that lives forever in `authorized_keys`. Steal it → dead
  in minutes.
- **One source of truth.** Grant/revoke in a central ACL; Agents mirror it into
  `AuthorizedPrincipalsFile` automatically. No editing every host.
- **Identity ≠ key.** A Caller is identified by a revocable token; rotate your
  SSH keypair freely without touching the ACL.
- **Audited.** Every certificate issuance is an immutable record at the Control
  plane.

See [`CONTEXT.md`](./CONTEXT.md) for the vocabulary (Agent, Caller, Control
plane, Subnet, Endpoint, Policy) and [`docs/architecture.md`](./docs/architecture.md)
for the full design.

## Install

**macOS** (Homebrew):
```bash
brew install derek-x-wang/tap/uncluster
```

**Windows** — download the binary from the
[latest release](https://github.com/Derek-X-Wang/uncluster/releases/latest)
(`uncluster-windows-amd64.exe`) to a stable path such as `C:\uncluster\uncluster.exe`.
> Don't install the Windows **agent** via Scoop: `uncluster agent install`
> registers a system service bound to the binary's path, and a per-user Scoop
> shim plus Scoop's own auto-update would conflict with the agent's managed
> self-update. Scoop is fine for using `uncluster` purely as a CLI/Caller.

**Linux / other** — grab the matching binary from the
[releases page](https://github.com/Derek-X-Wang/uncluster/releases/latest).

Every release also publishes per-asset `.sha256` files; verify before running.

---

## Setup guide: Mac control plane + Windows agent

End goal: from your Mac, run `uncluster ssh windows-rig` and land in a shell on
your Windows machine, authenticated by a short-lived certificate. Both machines
must be on the **same LAN/Wi-Fi**.

Roles: **Mac** = Control plane + Caller. **Windows** = Agent (the machine you
SSH *into*).

### Phase 0 — gather three facts

- **Mac LAN IP** (Mac terminal): `ipconfig getifaddr en0` (try `en1` if blank) → call it `MAC_IP`.
- **Windows username** (Windows PowerShell): `whoami` → the part after `\` is `WIN_USER`.
- Agent name will be `windows-rig`.

### Phase 1 — Mac: control plane + caller

```bash
# 1. Generate the CA and mint your first Caller token (copy BOTH the token and its id).
uncluster server bootstrap

# 2. Start the control plane — leave this running; use a new terminal tab for the rest.
uncluster server start --addr :7777

# 3. (New tab) Point the Caller CLI at the control plane and store the Caller token.
uncluster config set server=http://127.0.0.1:7777
printf '%s' 'PASTE_CALLER_TOKEN' | uncluster config set --stdin   # NOTE: no 'token' word; --stdin handles it

# 4. Mint a JOIN token for the Windows machine (copy it).
uncluster server token create --kind join --label windows-rig
```

You also need an SSH keypair the Caller signs into certs. If
`~/.ssh/id_ed25519.pub` already exists, **use it — do not run `ssh-keygen`**
(it would overwrite your existing key). Only if you have none:
`ssh-keygen -t ed25519`.

### Phase 2 — Windows: enable SSH + get the binary

Open **PowerShell as Administrator** (Start → type PowerShell → Run as administrator).

```powershell
# Turn on the OpenSSH server (fresh Windows boxes don't have it running).
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
# If your Wi-Fi profile is "Public", inbound SSH is blocked — make it Private:
Get-NetConnectionProfile
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private

# Download the agent binary to a fixed system path.
New-Item -ItemType Directory -Force -Path C:\uncluster | Out-Null
Invoke-WebRequest -Uri https://github.com/Derek-X-Wang/uncluster/releases/latest/download/uncluster-windows-amd64.exe -OutFile C:\uncluster\uncluster.exe
setx /M PATH "$env:PATH;C:\uncluster"
```
Close and reopen the admin PowerShell so PATH refreshes; `uncluster --version` should work.

### Phase 3 — Windows: enroll + install (elevated PowerShell)

```powershell
$env:UNCLUSTER_TOKEN = "PASTE_JOIN_TOKEN"
uncluster agent join --server http://MAC_IP:7777 --name windows-rig
uncluster agent install     # configures sshd, registers the agent + principals-writer services, sets ACLs
uncluster agent doctor      # every line should read [ok ]
```

### Phase 4 — Mac: grant access + connect

```bash
# Confirm the agent is online and advertised its real LAN IP (not a Hyper-V/WSL virtual adapter).
uncluster agents ls

# Grant: this Caller may log into windows-rig as WIN_USER. Use the Caller-token id from Phase 1.
uncluster acl grant CALLER_TOKEN_ID windows-rig --as WIN_USER

# Connect (first time, accept the host key).
uncluster ssh windows-rig --as WIN_USER
```

At the remote prompt, `whoami` should show `windows-rig\WIN_USER`. You're in —
cert-signed, no key left on the box, gated by the principals file the writer
service maintains.

**Run a one-off command instead of a shell** (this is the AI-Caller path):
```bash
uncluster ssh windows-rig --as WIN_USER -- whoami
```

### Troubleshooting

- **`agents ls` shows a `172.x` / virtual address.** Windows often enumerates
  Hyper-V/WSL adapters first; the agent may advertise one the Mac can't reach.
  Set an endpoint override for the real LAN IP (see `docs/architecture.md`).
- **`agent doctor` fails a check.** It names the exact problem and the fix.
- **Mac can't be reached from Windows.** Confirm both are on the same network
  and the Mac firewall allows inbound on `:7777`
  (System Settings → Network → Firewall).

---

## Documentation

- [`CONTEXT.md`](./CONTEXT.md) — domain vocabulary and relationships.
- [`docs/architecture.md`](./docs/architecture.md) — current-state design, cert flow, threat model.
- [`docs/adr/`](./docs/adr/) — decision records.
- [`api/openapi.yaml`](./api/openapi.yaml) — wire contract.

## License

[Apache-2.0](./LICENSE).
