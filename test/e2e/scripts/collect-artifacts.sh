#!/usr/bin/env bash
# Artifact collector for the Compose E2E stack.
#
# Per ADR-0008: on success and on failure, capture from each role: container
# logs, sshd config dump, principals file contents, service status,
# network state. Tar everything for upload via actions/upload-artifact.
#
# Usage:  collect-artifacts.sh <out-dir>
#
# Idempotent: tolerates missing services (older partial stacks) and best-effort
# scrapes whatever is available. Exits 0 even if individual scrapes fail so
# the test step that triggered collection isn't masked.
set -uo pipefail

OUT_DIR="${1:-./_e2e-artifacts}"
COMPOSE_FILE="${COMPOSE_FILE:-$(dirname "$0")/../docker-compose.yml}"

mkdir -p "${OUT_DIR}"

log() { echo "[collect] $*"; }

# Compose-level metadata first.
log "compose ps + config -> ${OUT_DIR}"
docker compose -f "${COMPOSE_FILE}" ps --format json > "${OUT_DIR}/docker.ps.json" 2>/dev/null || true
docker compose -f "${COMPOSE_FILE}" config > "${OUT_DIR}/compose.yml" 2>/dev/null || true

scrape_role() {
    local role="$1"; shift
    local role_dir="${OUT_DIR}/${role}"
    mkdir -p "${role_dir}"

    # Logs.
    docker compose -f "${COMPOSE_FILE}" logs --no-color --tail=2000 "${role}" \
        > "${role_dir}/logs.txt" 2>&1 || true

    # Inspect (container state, IPs, env).
    docker compose -f "${COMPOSE_FILE}" ps --format json "${role}" \
        > "${role_dir}/ps.json" 2>/dev/null || true

    # Per-role probes (best-effort; the container may not be running).
    # Probe format: "<label>:::<shell command>". The ":::" delimiter avoids
    # collisions with shell `|` operators inside probes (e.g. `... || ...`).
    for cmd in "$@"; do
        local probe label
        label="${cmd%%:::*}"
        probe="${cmd#*:::}"
        docker compose -f "${COMPOSE_FILE}" exec -T "${role}" sh -c "${probe}" \
            > "${role_dir}/${label}" 2>&1 || true
    done
}

scrape_role cp \
    "fs-listing.txt:::ls -la /var/lib/uncluster 2>/dev/null" \
    "ca.pub:::cat /var/lib/uncluster/ca.pub 2>/dev/null" \
    "healthz.json:::curl -fsS http://127.0.0.1:7777/healthz"

scrape_role agent \
    "sshd-T.txt:::sshd -T 2>/dev/null" \
    "sshd-drop-in.conf:::cat /etc/ssh/sshd_config.d/uncluster.conf 2>/dev/null" \
    "ca.pub:::cat /etc/ssh/uncluster-ca.pub 2>/dev/null" \
    "auth_principals-listing.txt:::ls -la /etc/ssh/auth_principals 2>/dev/null" \
    "auth_principals-contents.txt:::find /etc/ssh/auth_principals -type f -exec sh -c 'echo === \$1 ===; cat \$1' _ {} \;" \
    "ip-addr.txt:::ip addr 2>/dev/null || ifconfig 2>/dev/null" \
    "listening-ports.txt:::ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"

scrape_role caller \
    "cli.toml:::cat /root/.config/uncluster/cli.toml 2>/dev/null" \
    "fs-listing.txt:::ls -la /var/lib/uncluster-caller 2>/dev/null" \
    "id_ed25519.pub:::cat /var/lib/uncluster-caller/keys/id_ed25519.pub 2>/dev/null"

log "artifacts written under ${OUT_DIR}"
ls -la "${OUT_DIR}" || true
