# Uncluster V1 — Session Handoff

**Last session ended:** 2026-04-25
**Branch:** `main`
**HEAD:** `cadad5a` (fix: final review amendments — Dispatcher interface, ?node= param, goroutine safety)
**Status:** V1 implementation complete; all 43 plan tasks done; all tests green under `-race`. Ready for real-hardware smoke test and follow-on work.

---

## What's already in the repo

- **Spec:** `docs/superpowers/specs/2026-04-23-uncluster-v1-design.md`
- **Plan:** `docs/superpowers/plans/2026-04-23-uncluster-v1.md`
- **Code:** see plan §"File structure" — full implementation matches.
- **Tests:** `go test ./... -race -count=1` is green across `internal/{token,store,server,agent}`.
- **Acceptance:** spec §11 #1–#13 all satisfied (concurrency / silent-cancel / output-cap tests in `internal/server/integration_test.go`).
- **Build:** `scripts/build.sh` cross-compiles to `darwin/{amd64,arm64}` + `linux/{amd64,arm64}`. CI in `.github/workflows/ci.yml`.

## Known gaps (deliberately deferred from V1)

1. **`/v1/tasks/{id}/chunks` ignores `?since_stdout=` / `?since_stderr=` query params** — handler passes `sinceSeq=0`; the store layer supports it. Spec §5.1 gap, non-blocking for V1.
2. **`TestOpenAPIDrift` uses `strings.Contains`**, not parsed YAML route-matching. Works in practice but a comment in a YAML could mask a missing route.
3. **Real-hardware smoke test never run** — only in-process integration tests.
4. **`uncluster agent install` smoke** never exercised on a real launchd/systemd unit.
5. **`?node=` filter on `tasks ls`** accepts only an ID, not a name. Users have to `nodes show <name>` first to get the ID. Easy to extend.
6. **No retention/prune yet** — tasks and chunks accumulate forever (acceptable for personal scale; spec §10 lists `tasks prune` as later work).
7. **No MCP server, no fan-out (`--all-nodes`), no TUI** — all explicitly V1.5+ in spec §10.

## Other notes

- The `UPDATE … RETURNING` atomic-claim logic and the agent's three-goroutine model (heartbeat / poll / cancelDispatcher) are the load-bearing correctness pieces. Tests cover both. Don't refactor without keeping `TestAcceptance_NoDoubleClaim` and `TestAcceptance_SilentCommandCancel` green.
- The `Dispatcher` is now an interface (post final-review fix). A queue-backed variant for Lambda/Workers can be a drop-in replacement.
- Go directive is `1.25.0` (required by `modernc.org/sqlite@latest`). CI pins `go-version: "1.25"`.
- Token format is `uct_<kind>_<id>_<secret>` — the public `<id>` segment is the indexed lookup key, only the `<secret>` is argon2id-hashed. Don't change this without re-auditing middleware and the store.

## How to bring it up locally

```bash
# server side
./uncluster server bootstrap --db /tmp/uncluster.db   # prints first CLI token
./uncluster server start --addr :17777 --db /tmp/uncluster.db &

# client side
./uncluster config set server=http://localhost:17777
echo "<cli-token>" | ./uncluster config set token --stdin

# add a node
./uncluster server token create --kind=join --label=lappy
echo "<join-token>" | ./uncluster agent join \
    --server=http://localhost:17777 --name=lappy --token-stdin
./uncluster agent run &
sleep 12
./uncluster nodes ls

# run something
./uncluster run lappy -- 'echo hello && uname -a'
```

---

## Prompt to paste into the next session

```
We're picking up Uncluster V1 from the previous session. Working dir is
/Users/derekxwang/Development/incubator/Uncluster/uncluster on branch
main at HEAD cadad5a.

V1 implementation is complete and all tests pass:
  go test ./... -race -count=1

Read these for context (do NOT re-do brainstorming or planning):
  - docs/superpowers/HANDOFF.md     (current state + known gaps)
  - docs/superpowers/specs/2026-04-23-uncluster-v1-design.md
  - docs/superpowers/plans/2026-04-23-uncluster-v1.md

What I'd like to do next is one of:

  1. Real-hardware smoke test — bring up the server on my home box, join
     one of my MacBooks as a node, run real commands, exercise revoke +
     rejoin. Surface any cross-machine bugs the in-process integration
     tests didn't catch.

  2. Close the spec-gap items in HANDOFF.md "Known gaps" — specifically
     the `?since_stdout=` / `?since_stderr=` chunk pagination params and
     the `tasks ls --node=NAME` resolution.

  3. Start V1.5 work: pick one of [tasks prune, MCP server, --all-nodes
     fan-out, TUI dashboard]. Brainstorm the choice first if multiple
     are tempting.

  4. Something else — tell you what.

Confirm you've read the handoff and the spec/plan headers, then ask me
which path to take. Don't start writing code until I pick.
```
