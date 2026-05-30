#!/usr/bin/env bash
# Intentional-fail tests for assert-doctor-json.sh (#104).
#
# assert-doctor-json.sh is the repo-owned check surface that CI, the validate
# skill, and dogfood all use to assert health from `uncluster agent doctor
# --json`. A regression in its parsing logic would let a broken install pass
# CI silently — exactly the drift #104 exists to kill — so its logic is
# unit-tested here with fixture JSON, run as a normal (docker-free) CI step.
set -euo pipefail

THIS_DIR="$(cd "$(dirname "$0")" && pwd)"
ASSERT="${THIS_DIR}/assert-doctor-json.sh"

fail=0

# expect_rc <label> <want-rc> <json> <args...>
expect_rc() {
    local label="$1"; shift
    local want="$1"; shift
    local json="$1"; shift
    local got=0
    echo "${json}" | "${ASSERT}" "$@" >/dev/null 2>&1 || got=$?
    if [[ "${got}" != "${want}" ]]; then
        echo "FAIL [${label}]: want rc=${want}, got rc=${got}  (args: $*)"
        fail=1
    else
        echo "ok   [${label}]: rc=${want}"
    fi
}

HEALTHY='{"checks":[
  {"component":"sshd","check":"installed","state":"ok"},
  {"component":"principals","check":"dir_writable","state":"ok"},
  {"component":"config","check":"ownership","state":"ok"}
],"exit_code":0,"summary":{"ok":3,"warn":0,"fail":0}}'

WITH_FAIL='{"checks":[
  {"component":"sshd","check":"installed","state":"ok"},
  {"component":"principals","check":"dir_writable","state":"fail","message":"owner derek (want root)"}
],"exit_code":2,"summary":{"ok":1,"warn":0,"fail":1}}'

WITH_WARN='{"checks":[
  {"component":"sshd","check":"installed","state":"ok"},
  {"component":"config","check":"ownership","state":"warn","message":"absent"}
],"exit_code":1,"summary":{"ok":1,"warn":1,"fail":0}}'

# --no-fails passes on a clean run, fails when any check is fail, tolerates warn.
expect_rc "no-fails on healthy"        0 "${HEALTHY}"  --no-fails
expect_rc "no-fails catches a fail"    1 "${WITH_FAIL}" --no-fails
expect_rc "no-fails tolerates warn"    0 "${WITH_WARN}" --no-fails

# --ok asserts a specific check is ok.
expect_rc "ok selector matches ok"     0 "${HEALTHY}"  --ok principals/dir_writable
expect_rc "ok selector catches fail"   1 "${WITH_FAIL}" --ok principals/dir_writable
expect_rc "ok selector catches warn"   1 "${WITH_WARN}" --ok config/ownership
expect_rc "ok selector absent check"   1 "${HEALTHY}"  --ok nonexistent/check

# combined flags both enforced.
expect_rc "combined healthy passes"    0 "${HEALTHY}"  --no-fails --ok principals/dir_writable --ok config/ownership
expect_rc "combined fail fails"        1 "${WITH_FAIL}" --no-fails --ok principals/dir_writable

# malformed / empty input rejected.
expect_rc "empty input rejected"       1 ""            --no-fails
expect_rc "non-doctor json rejected"   1 '{"foo":1}'   --no-fails

if [[ "${fail}" -ne 0 ]]; then
    echo "assert-doctor-json self-tests FAILED"
    exit 1
fi
echo "assert-doctor-json self-tests passed"
