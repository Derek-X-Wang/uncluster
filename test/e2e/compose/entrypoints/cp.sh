#!/usr/bin/env bash
# Control plane entrypoint.
#
# Boot order:
#   1. Bootstrap CA + DB + caller token (offline; writes CA pubkey to /shared).
#   2. Start the control plane in the background.
#   3. Wait for /healthz, then mint a join token via the API and persist it
#      to /shared/join-token. This is the file the Agent polls for.
#   4. Hand off to the foreground server (replace with exec so signals work).
#
# All shared state lives in /shared (a named volume mounted by every role).
# Failure-taxonomy: any step here is bootstrap, not product. The harness
# classifies an early exit from this script as [ADVISORY] (rendezvous).
set -euo pipefail

UNCLUSTER_ADDR="${UNCLUSTER_ADDR:-:7777}"
SHARED_DIR="${SHARED_DIR:-/shared}"
mkdir -p "${SHARED_DIR}"
mkdir -p "$(dirname "${UNCLUSTER_DB}")"

log() { echo "[cp] $(date -u +%FT%TZ) $*"; }

log "bootstrap (CA + DB + caller token) ..."
# Bootstrap prints the caller token on stdout; capture it.
BOOTSTRAP_OUT="$(mktemp)"
uncluster server bootstrap \
    --db "${UNCLUSTER_DB}" \
    --ca "${UNCLUSTER_CA}" \
    --label "e2e-bootstrap" \
    > "${BOOTSTRAP_OUT}"
cat "${BOOTSTRAP_OUT}"

# Extract the caller token: it appears after the "caller token" header.
# Format: "caller token (shown ONCE — copy it now):\n  <token>"
CALLER_TOKEN="$(awk '/caller token \(shown ONCE/{getline; gsub(/^[[:space:]]+/,""); print; exit}' "${BOOTSTRAP_OUT}")"
if [[ -z "${CALLER_TOKEN}" ]]; then
    log "ERROR: failed to parse caller token from bootstrap output"
    exit 2
fi

export CALLER_TOKEN  # needed in the backgrounded subshell below

# Publish CA pubkey + caller token for the Agent/Caller to consume.
cp "${UNCLUSTER_CA}.pub" "${SHARED_DIR}/ca.pub"
echo -n "${CALLER_TOKEN}" > "${SHARED_DIR}/caller-token"
chmod 0644 "${SHARED_DIR}/ca.pub" "${SHARED_DIR}/caller-token"
log "shared CA pubkey + caller token written to ${SHARED_DIR}/"

# Background: wait for healthz then mint a join token.
mint_join_token() {
    local url="http://127.0.0.1${UNCLUSTER_ADDR#*:}"
    if [[ "${UNCLUSTER_ADDR}" != *:* ]]; then
        url="http://127.0.0.1:${UNCLUSTER_ADDR}"
    fi
    for _ in $(seq 1 60); do
        if curl -fsS "${url}/healthz" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    # Mint the join token via the API.
    local resp
    resp="$(curl -fsS -X POST "${url}/v1/tokens" \
        -H "Authorization: Bearer ${CALLER_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"kind":"join","label":"e2e-join"}')"
    local join_tok
    join_tok="$(echo "${resp}" | jq -r '.token')"
    if [[ -z "${join_tok}" || "${join_tok}" == "null" ]]; then
        log "ERROR: failed to mint join token; response: ${resp}"
        return 1
    fi
    echo -n "${join_tok}" > "${SHARED_DIR}/join-token"
    chmod 0644 "${SHARED_DIR}/join-token"
    log "join token published to ${SHARED_DIR}/join-token"
}
mint_join_token &

log "starting control plane on ${UNCLUSTER_ADDR}"
exec uncluster server start \
    --addr "${UNCLUSTER_ADDR}" \
    --db "${UNCLUSTER_DB}" \
    --ca "${UNCLUSTER_CA}"
