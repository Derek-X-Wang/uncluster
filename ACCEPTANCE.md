# Uncluster V2 — Acceptance criteria

The "done" definition for V2. Cross-references the per-slice acceptance criteria in GitHub issues.

V2 is considered shipped when **all of the following** hold on a fresh machine:

## Bootstrap

- [ ] `uncluster server bootstrap` generates a CA keypair, mode 0600 on private. (#3)
- [ ] `uncluster server start` serves `/healthz`. (#3)
- [ ] First caller token printed once with `uct_caller_<id>_<secret>` format. (#3)

## Enrollment

- [ ] Operator can mint a join token: `uncluster server token create --kind=join`. (#3)
- [ ] Linux box: `sudo uncluster agent install` enrolls the Agent end-to-end; `uncluster agent doctor` reports all checks ok. (#5)
- [ ] macOS box: same. (#5)
- [ ] Windows box: same, using SCM-installed service running as low-priv account. (#16)
- [ ] sshd on every enrolled Agent is configured to trust our CA (`sshd -T | grep TrustedUserCAKeys` shows our pubkey path). (#5, #16)
- [ ] Re-running `agent install` on an already-enrolled host is idempotent / self-healing. (#5)
- [ ] `uncluster agent doctor` returns 0 on a healthy host, 1 with warnings, 2 with failures. (#5)

## Heartbeat + Policy

- [ ] Agent heartbeats every 10s with V2 typed envelope (`policy_state`, `health`, `metrics`). (#6)
- [ ] `agents.last_seen_at` updates on every beat. (#6)
- [ ] Subnets and endpoints auto-detected (Tailscale IP for `*-tailnet`, default route for `*-lan`). (#6)
- [ ] `--subnet=home-lan@<explicit-ip>` overrides detection. (#6)

## ACL + cert flow

- [ ] `uncluster acl grant <caller> <agent> --as <user>` creates a row; `uncluster acl ls` shows it. (#9)
- [ ] ACL change reflects on Agent's principals file within ≤10s. (#10)
- [ ] Removing all ACL rows for a user → that user's principals file is deleted. (#10)
- [ ] `uncluster ssh <agent> -- echo hello` returns 0 with `hello` on stdout end-to-end. (#11)
- [ ] `uncluster ssh <agent> -- exit 7` exits 7 (exit code propagated). (#11)
- [ ] Cert TTL > 900s rejected with 400. (#11)
- [ ] Cert request with a cert as pubkey input (not raw pubkey) rejected with 400. (#11)
- [ ] `POST /v1/certs` with no ACL row → 403; `uncluster ssh` errors clearly. (#11)
- [ ] Two callers with valid ACL rows can each SSH independently. (#11)

## Auth state machine (safe revocation)

- [ ] Revoke an agent token mid-flight → next heartbeat 401 → Agent stops, principals NOT wiped. (#12)
- [ ] `uncluster agents rm <name>` → next heartbeat 410 → Agent wipes principals, marks `.deprovisioned`, exits, supervisor doesn't restart. (#12)
- [ ] `--fail-closed-after=1h` → Agent disconnected for >1h wipes principals; reconnect re-applies. (#12)
- [ ] Default (no fail-closed) → disconnected Agent retains principals; existing certs work until TTL. (#12)

## Audit

- [ ] Every cert issuance writes a row to `cert_issuance_events` (success and denial). (#13)
- [ ] `uncluster audit certs --caller=X --since=1h` returns recent events. (#13)
- [ ] `uncluster audit certs --tail` follows new rows. (#13)
- [ ] `--json` output is parseable. (#13)

## Onboarding UX

- [ ] `uncluster config init` walks through prompts; resulting config supports `uncluster agents ls` and `uncluster ssh` without further setup. (#14)
- [ ] Token input read from stdin only; `--token=<value>` arg rejected. (#14)
- [ ] `uncluster agents ls --subnet=home-tailnet` filters correctly. (#14)
- [ ] `last_seen_at` rendered relatively ("just now", "12s ago", "3m ago", ISO beyond). (#14)

## Self-update

- [ ] Operator publishes a new version via `uncluster server update set --version=...`. (#7)
- [ ] Each Agent self-updates within one heartbeat on Linux/macOS. (#7)
- [ ] Failing new binary reverts within 30s; Agent reports old version. (#7)
- [ ] `uncluster agent update --pin=vX.Y.Z` blocks updates until unpinned. (#7)
- [ ] Windows: same self-update flow validated on real Windows box (`.new`/`.old` swap). (#17, #18)
- [ ] Checksum mismatch aborts swap, logs error, does not corrupt installed binary. (#7)

## Cross-platform completeness

- [ ] CI matrix includes `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`. (#2)
- [ ] `scripts/build.sh` produces cross-compiled artifacts for all five targets. (#2)
- [ ] Real Windows box: install + heartbeat + SSH from another Caller works. (#16)
- [ ] Real Windows box: self-update + rollback works. (#18)

## V1 archive

- [ ] V1 task-execution code (`handlers_tasks.go`, `dispatcher.go`, `sse.go`, `reaper.go`, `execute.go`, `cancel.go`, `run_cmd.go`, `tasks_cmd.go`, `sse_client.go`) deleted. (#15)
- [ ] `tasks` + `task_chunks` tables dropped. (#15)
- [ ] `nodes` → `agents` rename complete (no remaining `nodes` table or struct names). (#15)
- [ ] `go test ./... -race -count=1` is green. (#15)
- [ ] `openapi.yaml` carries V2 endpoints only; description no longer references V1 spec. (#1)
- [ ] V1 spec exists in `docs/superpowers/specs/archive/` with SUPERSEDED header. (#1)

## Documentation

- [ ] All 7 ADRs exist in `docs/adr/0001-…0007.md`. (#1)
- [ ] `docs/architecture.md` exists, ≤ 4 pages, covers system purpose / components / cert flow / ACL flow / lifecycle / threat model / invariants. (#1)
- [ ] `docs/adr/README.md` index lists all ADRs with status. (#1)
- [ ] `ACCEPTANCE.md` (this file) maps each acceptance criterion to its slice issue number. (#1)
- [ ] `CONTEXT.md` vocabulary consistent with the above. (#1)
- [ ] `CLAUDE.md` points readers at the V2 doc topology. (#1)

## Smoke test

End-to-end smoke after all slices land:

1. Fresh control plane host. `uncluster server bootstrap` → `uncluster server start`.
2. Three enrolled agents: one Linux box, one macOS, one Windows. All show `online` in `uncluster agents ls` within 30s of starting their service.
3. From operator workstation, `uncluster acl grant claude-mbp <each-agent> --as <user>`.
4. `uncluster ssh <each-agent> -- hostname` returns each box's hostname; exit code 0.
5. `uncluster acl revoke claude-mbp linux-box --as derek` → next `uncluster ssh linux-box -- whoami` fails within 15s of waiting for cert.
6. `uncluster agents rm macos-box` → agent on macos-box exits cleanly; principals files wiped.
7. `uncluster audit certs --since=1h` shows the issued + denied events.
8. `uncluster server update set --version=v2.0.1 …` → all remaining agents update + restart within one heartbeat each.
