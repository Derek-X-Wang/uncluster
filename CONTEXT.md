# Uncluster

A lightweight personal compute layer. Treats a group of personal machines as a pool of usable resources by running a minimal **Agent** on each device and a thin **Control plane** that gates access. AI **Callers** (e.g. Claude Code on the operator's main workstation) consume the registry to discover machines and obtain time-limited SSH access via certificates.

## Language

**Agent**:
Process running on each device. Minimal by design — self-updates, reports status to the **Control plane**, and acts as that device's **Gatekeeper** by managing its SSH lifecycle (sshd config, principal list, firewall, key rotation). Runs with elevated privilege.
_Avoid_: daemon, worker, node-agent

**Control plane**:
Single server holding the registry of **Agents** and acting as the SSH **certificate authority**. Issues short-lived **SSH certificates** to authorized **Callers**.
_Avoid_: master, server (overloaded), backend, broker

**Caller**:
A consumer of the `uncluster` CLI that wants outbound SSH access to a device — typically an AI assistant on a workstation (e.g. Claude Code on the operator's MacBook) or the operator running CLI commands directly. Identified to the **Control plane** by a **Caller token**; brings its own SSH keypair (which gets signed into an **SSH certificate** per request). **Callers** and **Agents** are *separate roles* — an **Agent** never acts as a **Caller** on its own behalf. If a device needs outbound SSH from some local process, the operator mints a separate **Caller token** for that process.
_Avoid_: client, user (overloaded), principal (collides with SSH cert principal), "AI agent" (overloaded with **Agent**)

**Caller token**:
Durable bearer credential held by a **Caller**, used to authenticate cert-signing requests to the **Control plane**. Format follows V1: `uct_caller_<id>_<secret>`. Revocable. The token is the identity the ACL is keyed on — a **Caller** can rotate its SSH keypair freely without touching the ACL.
_Avoid_: API key, password

**Gatekeeper**:
The **Agent**'s role in mediating access to its device. Not a separate component — describes what the **Agent** does (one-time sshd config, ongoing principal-list updates, deciding which **Callers** are allowed).

**SSH certificate**:
Short-lived OpenSSH user certificate (default 5 min TTL, max 15 min) signed by the **Control plane**'s CA, presented by a **Caller** at login. Encodes the cert principal (the **Caller**'s token ID, opaque), the local target username, validity window, and an audit-shaped `key_id`. Revocation = TTL expiry + principal removal from target's `AuthorizedPrincipalsFile` at next policy sync. KRL is deferred to post-V2.
_Avoid_: token (collides with control-plane auth tokens), key (a cert is not a key)

**Subnet**:
A network reachability scope an **Agent** advertises — operator-defined free-string label like `home-tailnet`, `work-tailnet`, `home-lan`. A single **Agent** can sit on multiple **Subnets** and announce all of them. First-class in the registry (own table, indexed) for fast filtering — *not* a permission scope (physical reachability is the real gate). **Callers** filter the registry by **Subnet** to discover what they can actually reach.
_Avoid_: network, tailnet (only one Subnet kind)

**Endpoint**:
The `(Subnet, address)` pair an **Agent** advertises for each **Subnet** it sits on — e.g. `(home-tailnet, 100.64.0.7)`, `(home-lan, 192.168.1.50)`. A **Caller** picks which **Endpoint** to dial when SSHing. Each **Agent** has one or more **Endpoints**, one per **Subnet** it claims. **Endpoints** are self-asserted by the **Agent** — reachability data, not security facts; never used to authorize.
_Avoid_: address (ambiguous), interface (overloaded)

**Audit event**:
Immutable record of a **Control plane** decision — primarily cert issuances (`(request_id, ts, caller_token_id, target_agent_id, username, cert_principal, pubkey_fingerprint, ttl, serial, key_id, outcome, denial_reason)`). The operator-queryable history of "who got access to what." Distinct from application logs.
_Avoid_: log entry (overloaded), trace

**Policy**:
The per-**Agent** projection of the central ACL — the map `{unix_username: [caller_token_id, ...]}` that gets materialized into `AuthorizedPrincipalsFile` entries on that **Agent**. Versioned monotonically (`desired_version` issued by **Control plane**, `applied_version` reported back by **Agent** via heartbeat). The two-sided versioning catches "policy delivered but file write failed silently."
_Avoid_: ruleset, rules (too generic)

## Relationships

- A **Control plane** issues **SSH certificates** to **Callers** after checking the permission graph.
- An **Agent** trusts the **Control plane**'s CA pubkey (one-time sshd config) and gates SSH login by **SSH certificate** validity plus `AuthorizedPrincipalsFile`.
- An **Agent** belongs to one or more **Subnets**, advertising an **Endpoint** for each.
- A **Caller** discovers reachable **Agents** by filtering the registry on **Subnet**, then dials the matching **Endpoint**.

## Example dialogue

> **Dev:** "When Claude Code on the MBP wants to SSH into windows-rig, what actually moves?"
> **Operator:** "Claude Code is a **Caller** — it runs the `uncluster` CLI on the MBP and holds a **Caller token**. It asks the **Control plane** to sign its SSH pubkey for `derek@windows-rig` for 5 minutes. **Control plane** checks the permission graph, signs the **SSH certificate**, returns it with a `key_id` recorded as an **Audit event**. Claude Code presents the cert to windows-rig's sshd, which trusts our CA pubkey, sees the principal `caller_k4m...` in `AuthorizedPrincipalsFile`, and opens the session. The **Agent** on windows-rig — the small binary installed there — didn't participate at login time. Its only jobs are the one-time sshd config and keeping its principals file in sync with the **Control plane**'s policy (mirrored via heartbeat)."

> **Dev:** "Could the **Agent** on the MBP do the same — initiate SSH outward?"
> **Operator:** "No, **Agents** are receive-side gatekeepers, not **Callers**. If a local process on the MBP needed outbound SSH access, I'd mint a separate **Caller token** for it and grant ACL rows. The role is the gate, not the process."

## Flagged ambiguities

- **"tube"** (operator vocab) = the gatekept SSH access path. Maintaining the tube = sshd install/config + principal list + firewall + key rotation, i.e. everything the **Gatekeeper** does. Use **Gatekeeper** in docs.
- **"server"** appears in V1 spec to mean the **Control plane**. Use **Control plane**; "server" is overloaded with sshd + control plane + the operator's home box.
