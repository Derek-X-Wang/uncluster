#!/usr/bin/env bash
# assert-doctor-json.sh — assert health from `uncluster agent doctor --json`.
#
# Single source of truth for "healthy install" (#104, ADR-0009): CI, the
# validate skill, and dogfood all parse the SAME `doctor --json` shape via this
# script instead of re-implementing owner/group/mode/ACL checks in bash. A
# health-check regression then shows up identically in CI and in `doctor`.
#
# Reads the doctor JSON from stdin. Two assertion modes, combinable:
#
#   --no-fails
#       Assert the run has zero `state == "fail"` checks (exit_code != 2).
#       `warn` is tolerated (e.g. `sshd -T` flakiness, pre-install warns).
#
#   --ok <component>/<check> [--ok <component>/<check> ...]
#       Assert the named check exists AND is `state == "ok"`. Use for the
#       specific properties a job cares about (e.g. principals/dir_writable,
#       config/ownership) so a downgrade to warn/fail/absent fails the job.
#
# The `doctor --json` schema (see internal/cli/agent_cmd.go doctorJSON):
#   { "checks": [ {component, check, state, message?}, ... ],
#     "exit_code": 0|1|2,
#     "summary": {ok, warn, fail} }
#
# Usage:
#   uncluster agent doctor --json | scripts/ci/assert-doctor-json.sh \
#       --no-fails --ok principals/dir_writable --ok config/ownership
set -euo pipefail

require_no_fails=false
selectors=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-fails)
            require_no_fails=true
            shift
            ;;
        --ok)
            if [[ $# -lt 2 ]]; then
                echo "assert-doctor-json: --ok requires a <component>/<check> argument" >&2
                exit 2
            fi
            selectors+=("$2")
            shift 2
            ;;
        *)
            echo "assert-doctor-json: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

if ! command -v jq >/dev/null 2>&1; then
    echo "assert-doctor-json: jq is required but not found in PATH" >&2
    exit 2
fi

doc="$(cat)"
if [[ -z "${doc//[[:space:]]/}" ]]; then
    echo "assert-doctor-json: empty input (did 'doctor --json' produce output?)" >&2
    exit 1
fi

# Validate it parses and looks like the doctor schema.
if ! echo "${doc}" | jq -e 'has("checks") and has("exit_code")' >/dev/null 2>&1; then
    echo "assert-doctor-json: input is not the doctor --json schema:" >&2
    echo "${doc}" >&2
    exit 1
fi

# Always echo a compact human-readable summary for the CI log + artifacts.
echo "doctor summary: $(echo "${doc}" | jq -c '.summary')  exit_code=$(echo "${doc}" | jq '.exit_code')"

rc=0

if [[ "${require_no_fails}" == true ]]; then
    fails="$(echo "${doc}" | jq -r '[.checks[] | select(.state=="fail")] | length')"
    if [[ "${fails}" != "0" ]]; then
        echo "::error::doctor reports ${fails} failing check(s):" >&2
        echo "${doc}" | jq -r '.checks[] | select(.state=="fail") | "  FAIL \(.component)/\(.check): \(.message // "")"' >&2
        rc=1
    fi
fi

for sel in ${selectors[@]+"${selectors[@]}"}; do
    comp="${sel%%/*}"
    chk="${sel##*/}"
    state="$(echo "${doc}" | jq -r --arg c "${comp}" --arg k "${chk}" \
        'first(.checks[] | select(.component==$c and .check==$k) | .state) // "absent"')"
    if [[ "${state}" != "ok" ]]; then
        msg="$(echo "${doc}" | jq -r --arg c "${comp}" --arg k "${chk}" \
            'first(.checks[] | select(.component==$c and .check==$k) | .message) // ""')"
        echo "::error::doctor check ${comp}/${chk} is '${state}', want 'ok'${msg:+ — ${msg}}" >&2
        rc=1
    else
        echo "  ok ${comp}/${chk}"
    fi
done

exit "${rc}"
