#!/usr/bin/env bash
# Intentional-fail tests for classify-step.sh per the T3a acceptance
# ("Step-name convention implemented and the final classifier-job correctly
# distinguishes the three classes, verified by an intentional-fail test").
#
# This runs as a normal CI step (no docker required), so a regression in
# the classifier logic is caught before any tailnet workflow executes.
set -euo pipefail

THIS_DIR="$(cd "$(dirname "$0")" && pwd)"
CLASSIFY="${THIS_DIR}/classify-step.sh"

fail=0
check() {
    local label="$1"; shift
    local want="$1"; shift
    local got
    got="$("${CLASSIFY}" "$@")"
    if [[ "${got}" != "class=${want}" ]]; then
        echo "FAIL [${label}]: want class=${want}, got ${got}"
        echo "  args: $*"
        fail=1
    else
        echo "ok   [${label}]: class=${want}"
    fi
}

# all-success → success
check "all-success" "success" \
    "bootstrap:tailscale-up=success" \
    "rendezvous:wait=success" \
    "product:cert-flow=success"

# all-skipped → success
check "all-skipped" "success" \
    "bootstrap:install=skipped" \
    "rendezvous:wait=skipped"

# empty outcomes (step never ran) → success
check "all-empty" "success" \
    "bootstrap:foo=" \
    "rendezvous:bar="

# bootstrap failure → advisory
check "bootstrap-fail" "advisory" \
    "bootstrap:tailscale-up=failure" \
    "rendezvous:wait=success" \
    "product:something=success"

# rendezvous failure → advisory
check "rendezvous-fail" "advisory" \
    "bootstrap:tailscale-up=success" \
    "rendezvous:wait=failure"

# product failure → required (wins over advisory)
check "product-fail" "required" \
    "bootstrap:tailscale-up=success" \
    "rendezvous:wait=success" \
    "product:cert-flow=failure"

# product failure dominates bootstrap failure
check "product-dominates" "required" \
    "bootstrap:tailscale-up=failure" \
    "product:cert-flow=failure"

# collect:* failure ignored
check "collect-ignored" "success" \
    "collect:logs=failure"

# unknown prefix fails safe → required
check "unknown-prefix-fail" "required" \
    "untagged-step=failure"

# cancelled treated like failure
check "cancelled-bootstrap" "advisory" \
    "bootstrap:foo=cancelled"

if [[ "${fail}" -ne 0 ]]; then
    echo "classify-step.sh tests FAILED"
    exit 1
fi
echo "all classify-step.sh tests passed"
