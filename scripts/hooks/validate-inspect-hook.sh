#!/usr/bin/env bash
# validate-inspect-hook.sh — ADR-0009 dev-loop auto-invocation (#107).
#
# A Claude Code Stop / pre-push hook that runs the read-only `inspect`
# validation WHEN the working changes touch install / daemon / self-update code
# paths. It is read-only BY CONSTRUCTION: it hardcodes `--safety inspect` and
# never passes --allow-mutate / --allow-reboot, so it can fire automatically
# without any risk of auto-sudo or auto-reboot bricking the dev machine
# (ADR-0009 decision 1: only `inspect` may auto-invoke).
#
# Path-sensitivity (ADR-0009): a docs-only change does NOT trigger it; only
# changes under the install/daemon/self-update/validation surfaces do. The
# match list is a function (validate_paths_match) so it is unit-testable.
#
# Modes:
#   (default)         Determine changed files via git, decide, and — if
#                     relevant — invoke `uncluster validate ... --safety inspect`.
#   --match-only      Read newline-separated paths on stdin (or as args) and
#                     exit 0 if any is validation-relevant, 1 otherwise. No
#                     validate invocation. Used by the self-tests and by callers
#                     that supply their own changed-file list.
#   --print-cmd       Print the exact validate command the hook would run and
#                     exit 0 (for docs / assertion that it is inspect-only).
set -euo pipefail

# The hardcoded, read-only invocation. NEVER add --allow-mutate / --allow-reboot
# here, and NEVER make --safety configurable — the whole safety argument for
# auto-invocation is that this can only ever run inspect.
VALIDATE_CMD=(uncluster validate --tier local --target this-machine --checks doctor --safety inspect)

# validate_paths_match reads newline-separated paths on stdin and exits 0 if any
# touches a validation-relevant code path, 1 otherwise. The relevant surfaces
# are the gatekeeper (install/sshd/principals/doctor), the agent's daemon/
# service + self-update code, the agent CLI command, the validate package/
# command, and the validate hook/scripts themselves. Everything else (docs,
# unrelated server/store/ca code, READMEs) is intentionally NOT a trigger.
validate_paths_match() {
    local f matched=1
    while IFS= read -r f; do
        [[ -z "${f}" ]] && continue
        case "${f}" in
            internal/gatekeeper/*) matched=0 ;;
            internal/agent/selfupdate*) matched=0 ;;
            internal/agent/updatehost*) matched=0 ;;
            internal/agent/service*) matched=0 ;;
            internal/agent/install*) matched=0 ;;
            internal/cli/agent_cmd.go) matched=0 ;;
            internal/cli/validate_cmd.go) matched=0 ;;
            internal/validate/*) matched=0 ;;
            scripts/validate/*) matched=0 ;;
            scripts/hooks/validate-inspect-hook*) matched=0 ;;
            .claude/skills/validate/*) matched=0 ;;
        esac
    done
    return "${matched}"
}

# changed_files prints the set of files changed in the working tree: tracked
# modifications/staged changes (vs HEAD) plus untracked files. Best-effort —
# prints nothing if not in a git repo (then the hook simply does not fire).
changed_files() {
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        return 0
    fi
    {
        git diff --name-only HEAD 2>/dev/null || true
        git ls-files --others --exclude-standard 2>/dev/null || true
    } | sort -u
}

main() {
    case "${1:-}" in
        --match-only)
            shift
            if [[ $# -gt 0 ]]; then
                printf '%s\n' "$@" | validate_paths_match
            else
                validate_paths_match
            fi
            exit $?
            ;;
        --print-cmd)
            printf '%s ' "${VALIDATE_CMD[@]}"
            printf '\n'
            exit 0
            ;;
    esac

    local files
    files="$(changed_files)"
    if [[ -z "${files//[[:space:]]/}" ]]; then
        # No changes (or not a repo) — nothing to validate.
        exit 0
    fi
    if ! printf '%s\n' "${files}" | validate_paths_match; then
        # Changes are not install/daemon/self-update-relevant (e.g. docs only).
        exit 0
    fi

    echo "[validate-hook] changes touch install/daemon/self-update code — running read-only inspect validation"
    if ! command -v uncluster >/dev/null 2>&1; then
        echo "[validate-hook] 'uncluster' not on PATH; skipping (build/install it to enable auto-validation)" >&2
        exit 0
    fi
    # Read-only by construction. A non-zero exit surfaces the unhealthy verdict.
    "${VALIDATE_CMD[@]}"
}

main "$@"
