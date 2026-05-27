#!/usr/bin/env bash
# Per-job step classifier per ADR-0008.
#
# Reads a list of step-name/outcome pairs from arguments and emits a single
# class word: success | advisory | required.
#
# Convention:
#   * Steps named bootstrap:* and rendezvous:* failing → advisory.
#   * Steps named product:* failing → required (blocks the gate).
#   * Steps named collect:* failing → ignored (diagnostic only).
#   * Unknown-prefix steps default to required (fail-safe).
#
# Usage:
#   classify-step.sh "<step-name>=<outcome>" "<step-name>=<outcome>" ...
#
# In yaml:
#     - name: bootstrap:tailscale-up
#       id: ts-up
#       continue-on-error: true
#     ...
#     - name: classify
#       run: ./scripts/ci/classify-step.sh \
#               "bootstrap:tailscale-up=${{ steps.ts-up.outcome }}" \
#               "rendezvous:wait-for-peers=${{ steps.rdv-wait.outcome }}" \
#               ... >> "$GITHUB_OUTPUT"
set -euo pipefail

class="success"

for pair in "$@"; do
    name="${pair%%=*}"
    outcome="${pair#*=}"
    case "${outcome}" in
        success|skipped|"")
            continue
            ;;
    esac
    # outcome is failure or cancelled — classify by name prefix.
    case "${name}" in
        bootstrap:*|rendezvous:*)
            if [[ "${class}" == "success" ]]; then
                class="advisory"
            fi
            ;;
        collect:*)
            : # diagnostic only — ignored
            ;;
        product:*)
            class="required"
            ;;
        *)
            # Unknown prefix is fail-safe: treat as required so an
            # unannotated step that fails does not silently pass.
            class="required"
            ;;
    esac
done

echo "class=${class}"
