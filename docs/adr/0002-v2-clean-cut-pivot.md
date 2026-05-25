# 0002: V2 clean cut over incremental pivot

**Status:** accepted

V1's task-execution model (long-poll dispatcher, exec.Command on the agent, chunked stdout/stderr, SSE tail) is deleted wholesale in V2. The agent becomes a gatekeeper for SSH access; "running a command on a remote" is delegated to SSH (which already handles process lifetime, streaming, cancel, cross-platform). No transitional period; no V1/V2 coexistence.

## Considered options

- **Incremental pivot (V1.5).** Add V2 endpoints + CLI alongside V1. Keep `uncluster run` (exec) and add `uncluster ssh` (cert). Delete V1 paths once new paths are proven. Rejected: nothing of V1 has shipped to users, so the "always-shippable" benefit of incremental is moot; carrying ~50% dead code during the build slows every change.
- **Clean cut (chosen).** Delete V1 task code in a single late slice (S11) after V2 MVP works. Earlier slices carry "no V1 compatibility required" acceptance criteria so agents don't waste effort preserving V1 behavior.

## Consequences

- ~50% of V1 code dies: `handlers_tasks.go`, `dispatcher.go`, `sse.go`, `reaper.go`, `internal/agent/execute.go`, `internal/agent/cancel.go`, `internal/cli/run_cmd.go`, `internal/cli/tasks_cmd.go`, `internal/cli/sse_client.go`, plus `tasks` + `task_chunks` tables.
- The V1 design spec is archived (not deleted) with a SUPERSEDED header pointing to `docs/architecture.md` + the ADR index.
- No migration tooling for operators who installed V1 — recommendation is "uninstall V1, fresh install V2." Acceptable because no real V1 deployments exist.
