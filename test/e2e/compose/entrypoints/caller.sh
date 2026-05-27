#!/usr/bin/env bash
# Caller entrypoint.
#
# Boot order:
#   1. Wait for /shared/caller-token to appear (CP rendezvous).
#   2. Generate a host-local ed25519 keypair the harness can submit to /v1/certs.
#   3. Write a CLI config so `uncluster ssh` works without re-prompting.
#   4. Idle indefinitely (the harness drives this container via `docker exec`).
set -euo pipefail

SHARED_DIR="${SHARED_DIR:-/shared}"
CP_URL="${CP_URL:-http://cp:7777}"
CALLER_DIR="${UNCLUSTER_CALLER_DIR:-/var/lib/uncluster-caller}"

log() { echo "[caller] $(date -u +%FT%TZ) $*"; }
fail_bootstrap() { log "[ADVISORY] bootstrap failure: $*"; exit 64; }

# 1. rendezvous
log "waiting for ${SHARED_DIR}/caller-token"
for _ in $(seq 1 60); do
    if [[ -s "${SHARED_DIR}/caller-token" ]]; then
        break
    fi
    sleep 1
done
if [[ ! -s "${SHARED_DIR}/caller-token" ]]; then
    fail_bootstrap "shared caller-token never appeared"
fi

# 2. keypair
mkdir -p "${CALLER_DIR}/keys"
if [[ ! -f "${CALLER_DIR}/keys/id_ed25519" ]]; then
    ssh-keygen -q -t ed25519 -N "" -C "uncluster-e2e-caller" -f "${CALLER_DIR}/keys/id_ed25519"
fi
chmod 0600 "${CALLER_DIR}/keys/id_ed25519"
chmod 0644 "${CALLER_DIR}/keys/id_ed25519.pub"

# 3. CLI config (best effort; the harness can also drive the API directly)
mkdir -p /root/.config/uncluster
CALLER_TOKEN="$(cat "${SHARED_DIR}/caller-token")"
cat >/root/.config/uncluster/cli.toml <<EOF
server = "${CP_URL}"
token = "${CALLER_TOKEN}"
ssh_key_path = "${CALLER_DIR}/keys/id_ed25519"
EOF
chmod 0600 /root/.config/uncluster/cli.toml

log "caller ready (cp=${CP_URL}, key=${CALLER_DIR}/keys/id_ed25519)"

# 4. idle
exec tail -f /dev/null
