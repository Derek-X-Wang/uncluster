# Dev-loop validation hook (ADR-0009)

`validate-inspect-hook.sh` is the ADR-0009 auto-invocation: when your working
changes touch install / daemon / self-update code, it runs the **read-only**
`inspect` validation automatically and surfaces the verdict. It is read-only by
construction — it hardcodes `--safety inspect` and never passes
`--allow-mutate` / `--allow-reboot`, so it can fire on every commit without any
risk of auto-`sudo` or auto-reboot. (Only `inspect` may auto-invoke per
ADR-0009; `privileged`/`disruptive` stay explicit manual runs.)

It fires only on relevant paths (gatekeeper, agent daemon/self-update, the
agent CLI command, the `validate` command/package/skill). A docs-only change
does not trigger it.

## Enable (Claude Code)

The hook is a repo-owned script; wire it into **your own**
`.claude/settings.json` (or `~/.claude/settings.json`) as a `Stop` hook so it
runs after each turn. This file is operator-owned and is intentionally not
committed.

```jsonc
{
  "hooks": {
    "Stop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "bash scripts/hooks/validate-inspect-hook.sh"
          }
        ]
      }
    ]
  }
}
```

It also works as a **git pre-push** hook:

```bash
ln -sf ../../scripts/hooks/validate-inspect-hook.sh .git/hooks/pre-push
```

For the hook to actually run the checks, `uncluster` must be on `PATH`
(`go build -o "$(go env GOPATH)/bin/uncluster" ./cmd/uncluster`). If it is not,
the hook detects the relevant change, prints a one-line skip notice, and exits
0 — it never blocks you.

## Disable

One step: remove the `Stop` hook entry from `.claude/settings.json` (or delete
the `.git/hooks/pre-push` symlink). Nothing else is installed.

## What counts as "relevant"

The trigger paths are the single list in `validate_paths_match` inside the
script:

- `internal/gatekeeper/**` (install / sshd / principals / doctor)
- `internal/agent/selfupdate*`, `internal/agent/updatehost*`,
  `internal/agent/service*`, `internal/agent/install*`
- `internal/cli/agent_cmd.go`, `internal/cli/validate_cmd.go`
- `internal/validate/**`, `scripts/validate/**`
- `scripts/hooks/validate-inspect-hook*`, `.claude/skills/validate/**`

## Tests

`test-validate-inspect-hook.sh` asserts the path-sensitivity (relevant paths
trigger, docs-only does not) and the inspect-only guarantee (the invoked
command always hardcodes `--safety inspect` and never contains a mutating
class or an authorizing flag — so even a privileged-triggering change can only
ever run `inspect`). It runs as a normal CI step.
