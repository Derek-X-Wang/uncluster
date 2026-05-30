#!/usr/bin/env bash
# Tests for validate-inspect-hook.sh (#107). Runs as a normal (docker-free) CI
# step so a regression in the path-sensitivity or the inspect-only guarantee is
# caught before the hook ever fires on a dev machine.
set -euo pipefail

THIS_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK="${THIS_DIR}/validate-inspect-hook.sh"

fail=0

# expect_match <label> <want-rc> <path...>
# want-rc: 0 = should trigger validation, 1 = should NOT trigger.
expect_match() {
    local label="$1"; shift
    local want="$1"; shift
    local got=0
    "${HOOK}" --match-only "$@" >/dev/null 2>&1 || got=$?
    if [[ "${got}" != "${want}" ]]; then
        echo "FAIL [${label}]: want rc=${want}, got rc=${got}  (paths: $*)"
        fail=1
    else
        echo "ok   [${label}]: rc=${want}"
    fi
}

# --- Path-sensitivity: relevant code paths TRIGGER (rc 0) ---
expect_match "gatekeeper doctor change triggers"      0 internal/gatekeeper/doctor_unix.go
expect_match "gatekeeper install change triggers"     0 internal/gatekeeper/install_windows.go
expect_match "agent selfupdate change triggers"       0 internal/agent/selfupdate.go
expect_match "agent service/daemon change triggers"   0 internal/agent/service.go
expect_match "agent updatehost change triggers"       0 internal/agent/updatehost.go
expect_match "agent CLI command change triggers"      0 internal/cli/agent_cmd.go
expect_match "validate package change triggers"       0 internal/validate/run.go
expect_match "validate command change triggers"       0 internal/cli/validate_cmd.go
expect_match "validate skill change triggers"         0 .claude/skills/validate/SKILL.md
expect_match "relevant among several files triggers"  0 README.md internal/gatekeeper/doctor_unix.go docs/foo.md

# --- Path-sensitivity: irrelevant changes do NOT trigger (rc 1) ---
expect_match "docs-only does not trigger"             1 docs/architecture.md
expect_match "README-only does not trigger"           1 README.md
expect_match "ADR-only does not trigger"              1 docs/adr/0009-ai-agent-driven-validation.md
expect_match "unrelated server code does not trigger" 1 internal/server/handlers_certs.go
expect_match "unrelated store code does not trigger"  1 internal/store/sqlite.go
expect_match "empty change set does not trigger"      1

# --- Inspect-only by construction ---
# The printed command must hardcode --safety inspect and must NEVER contain a
# mutating safety class or an authorizing flag. This is the load-bearing
# guarantee: even a privileged-triggering change can only ever run inspect.
cmd="$("${HOOK}" --print-cmd)"
echo "hook command: ${cmd}"
if ! grep -q -- "--safety inspect" <<<"${cmd}"; then
    echo "FAIL [inspect-only]: hook command does not hardcode --safety inspect: ${cmd}"
    fail=1
else
    echo "ok   [inspect-only]: command hardcodes --safety inspect"
fi
for forbidden in "--allow-mutate" "--allow-reboot" "--safety privileged" "--safety disruptive" "--safety bounded"; do
    if grep -q -- "${forbidden}" <<<"${cmd}"; then
        echo "FAIL [inspect-only]: hook command contains forbidden '${forbidden}': ${cmd}"
        fail=1
    fi
done
echo "ok   [inspect-only]: command contains no mutating class or authorizing flag"

# Belt-and-suspenders: the script source must not reference allow-mutate/reboot
# in a way that could be passed to validate (only the comments warning against
# it are allowed). Assert no UNCOMMENTED occurrence.
if grep -vE '^\s*#' "${HOOK}" | grep -qE -- "--allow-mutate|--allow-reboot"; then
    echo "FAIL [inspect-only]: hook SOURCE has an uncommented --allow-* token"
    fail=1
else
    echo "ok   [inspect-only]: hook source never passes --allow-* (only comments warn about it)"
fi

if [[ "${fail}" -ne 0 ]]; then
    echo "validate-inspect-hook self-tests FAILED"
    exit 1
fi
echo "validate-inspect-hook self-tests passed"
