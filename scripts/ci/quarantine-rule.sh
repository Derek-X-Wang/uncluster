#!/usr/bin/env bash
# Quarantine rule per ADR-0008.
#
# Reads recent runs of a workflow from `gh run list --json` and, if the most
# recent N runs are all classified as advisory-failure (rendezvous/bootstrap
# failure rather than product failure), opens a `needs-triage` issue.
#
# A run is "advisory failure" when:
#   * conclusion == failure
#   * AND its run page contains a log line "[ADVISORY] ..." somewhere
#     (we approximate by checking annotations + the first matching step).
# A run is "required failure" when:
#   * conclusion == failure AND no [ADVISORY] marker appears.
#
# Default policy: 3 consecutive advisory failures open a triage issue.
# Crucially, this is the OPPOSITE of papering over flakes — its existence is
# what allows the workflow author to say "advisory until proven stable" with
# a defined escalation path.
#
# Usage (in a workflow):
#   ./scripts/ci/quarantine-rule.sh --workflow ci.yml --threshold 3
#
# Idempotent: if an open `needs-triage` issue exists with the same title,
# this script appends a comment instead of creating a duplicate.
set -euo pipefail

THRESHOLD=3
WORKFLOW=""
REPO="${GITHUB_REPOSITORY:-Derek-X-Wang/uncluster}"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workflow) WORKFLOW="$2"; shift 2 ;;
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 64 ;;
    esac
done

if [[ -z "${WORKFLOW}" ]]; then
    echo "--workflow <name.yml> is required" >&2
    exit 64
fi

log() { echo "[quarantine] $*"; }

# Get the last THRESHOLD * 2 runs (over-fetch to tolerate workflow_dispatch
# noise and successful runs interleaved). Only consider scheduled/push runs
# on main — quarantine on PR runs would be noisy.
runs_json="$(gh run list \
    --repo "${REPO}" \
    --workflow "${WORKFLOW}" \
    --branch main \
    --limit $((THRESHOLD * 2)) \
    --json databaseId,conclusion,displayTitle,status,createdAt,event \
    --jq '[.[] | select(.event == "schedule" or .event == "push" or .event == "workflow_dispatch")]')"

# We need the most recent THRESHOLD runs (excluding still-in-progress ones).
recent="$(echo "${runs_json}" | jq --argjson n "${THRESHOLD}" \
    '[.[] | select(.status == "completed")] | .[:$n]')"
got_count="$(echo "${recent}" | jq 'length')"
if [[ "${got_count}" -lt "${THRESHOLD}" ]]; then
    log "only ${got_count} completed runs available; need ${THRESHOLD} — no action"
    exit 0
fi

# Classify each run: download its first failed log and grep for [ADVISORY].
# Failed run with no [ADVISORY] marker => required failure (the gate
# already turned the workflow red; not our job to escalate further).
classify_run() {
    local run_id="$1"
    local concl="$2"
    if [[ "${concl}" == "success" ]]; then
        echo "success"
        return
    fi
    if [[ "${concl}" != "failure" ]]; then
        echo "${concl}"
        return
    fi
    # Cheap classifier: look at the failed-log dump for [ADVISORY].
    if gh run view "${run_id}" --repo "${REPO}" --log-failed 2>/dev/null | \
            grep -q '\[ADVISORY\]'; then
        echo "advisory-failure"
    else
        echo "required-failure"
    fi
}

all_advisory=1
classifications=()
while IFS= read -r row; do
    rid="$(echo "${row}" | jq -r '.databaseId')"
    concl="$(echo "${row}" | jq -r '.conclusion')"
    class="$(classify_run "${rid}" "${concl}")"
    classifications+=("${rid}:${class}")
    if [[ "${class}" != "advisory-failure" ]]; then
        all_advisory=0
    fi
done < <(echo "${recent}" | jq -c '.[]')

log "recent classifications: ${classifications[*]}"

if [[ "${all_advisory}" -ne 1 ]]; then
    log "not all of the last ${THRESHOLD} runs are advisory-failure — no action"
    exit 0
fi

# All N most recent runs are advisory failures. Open a triage issue if one
# doesn't already exist.
title="CI quarantine: ${WORKFLOW} has ${THRESHOLD} consecutive advisory failures"
existing="$(gh issue list --repo "${REPO}" --state open --label needs-triage \
    --search "${title} in:title" --json number --jq '.[0].number // empty')"

body="$(cat <<EOF
The quarantine rule (per [ADR-0008](https://github.com/Derek-X-Wang/uncluster/blob/main/docs/adr/0008-tiered-e2e-ci.md))
detected ${THRESHOLD} consecutive advisory-classified failures on \`${WORKFLOW}\`
on \`main\`.

Recent runs (most-recent first):

$(for c in "${classifications[@]}"; do
  rid="${c%%:*}"; cls="${c##*:}"
  echo "- run #${rid} — ${cls} — https://github.com/${REPO}/actions/runs/${rid}"
done)

Per ADR-0008's failure-taxonomy guardrail, an AI agent should NOT respond by
adding retries or marking more things advisory. Required actions:

1. Investigate the rendezvous/bootstrap failure mode that is recurring.
2. Either fix root cause (often: stack timing, image build cache, network
   plumbing) or, if the rendezvous mechanism itself is unreliable in this
   environment, decide whether to disable the workflow's schedule until
   resolved.
3. Close this issue with a reference to the fix PR or the decision.
EOF
)"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "[dry-run] would open issue:"
    echo "${title}"
    echo "${body}"
    exit 0
fi

if [[ -n "${existing}" ]]; then
    log "appending comment to existing issue #${existing}"
    gh issue comment "${existing}" --repo "${REPO}" --body "Detected again at $(date -u +%FT%TZ). See run list above."
else
    log "creating new triage issue"
    gh issue create --repo "${REPO}" \
        --title "${title}" \
        --label "needs-triage" \
        --body "${body}"
fi
