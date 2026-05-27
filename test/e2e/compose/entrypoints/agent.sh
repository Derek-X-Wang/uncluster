#!/usr/bin/env bash
# Agent entrypoint.
#
# Boot order:
#   1. Wait for /shared/ca.pub and /shared/join-token (CP rendezvous).
#   2. Configure sshd: install the CA pubkey at /etc/ssh/uncluster-ca.pub,
#      write a sshd drop-in with TrustedUserCAKeys and AuthorizedPrincipalsFile.
#      Pre-create the principals file for $TARGET_USER, empty for now — the
#      Agent populates it later when ACLs sync.
#   3. Run `uncluster agent join` (uses join token + CP URL).
#   4. Start sshd in the foreground via tini child, plus `uncluster agent run`.
#      The agent's heartbeat is what `e2e-compose-smoke` waits for.
#
# Failure-taxonomy:
#   - Steps 1-2 are bootstrap; harness classifies their failures as advisory.
#   - Step 3 onwards is product; failures are required-gate red.
set -euo pipefail

SHARED_DIR="${SHARED_DIR:-/shared}"
CP_URL="${CP_URL:-http://cp:7777}"
TARGET_USER="${TARGET_USER:-tester}"
AGENT_NAME="${AGENT_NAME:-agent-1}"

log() { echo "[agent] $(date -u +%FT%TZ) $*"; }
fail_bootstrap() { log "[ADVISORY] bootstrap failure: $*"; exit 64; }
fail_product()   { log "[REQUIRED] product failure: $*"; exit 1; }

# --- 1. rendezvous on the shared volume ---
log "waiting for CP rendezvous files in ${SHARED_DIR}"
for _ in $(seq 1 60); do
    if [[ -s "${SHARED_DIR}/ca.pub" && -s "${SHARED_DIR}/join-token" ]]; then
        break
    fi
    sleep 1
done
if [[ ! -s "${SHARED_DIR}/ca.pub" || ! -s "${SHARED_DIR}/join-token" ]]; then
    fail_bootstrap "shared rendezvous files never appeared (cp.pub or join-token missing)"
fi
log "rendezvous ok"

# --- 2. configure sshd ---
install -m 0644 "${SHARED_DIR}/ca.pub" /etc/ssh/uncluster-ca.pub

mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/uncluster.conf <<'EOF'
# Installed by uncluster e2e agent container.
TrustedUserCAKeys /etc/ssh/uncluster-ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
EOF
chmod 0644 /etc/ssh/sshd_config.d/uncluster.conf

# Some debian:bookworm-slim images ship a sshd_config that does not include
# the conf.d directory. Add the Include directive idempotently.
if ! grep -q '^Include /etc/ssh/sshd_config.d/' /etc/ssh/sshd_config 2>/dev/null; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi

# Pre-create an empty principals file for the test user. ACL sync (S3+) is
# what populates it for real; T1a only needs the file to exist so sshd can
# read it without errors. T1b will exercise the populated path.
install -d -m 0755 /etc/ssh/auth_principals
install -m 0644 /dev/null "/etc/ssh/auth_principals/${TARGET_USER}"

# Sanity check: sshd parses the config.
if ! /usr/sbin/sshd -t 2>/tmp/sshd-config-error; then
    log "sshd config test failed:"
    cat /tmp/sshd-config-error || true
    fail_bootstrap "sshd config validation failed"
fi
log "sshd config validated"

# --- 3. join the control plane (product step) ---
JOIN_TOKEN="$(cat "${SHARED_DIR}/join-token")"
# `agent join` rejects re-enrollment; clear any stale state from a previous run.
rm -rf /root/.config/uncluster
export UNCLUSTER_TOKEN="${JOIN_TOKEN}"
log "joining ${CP_URL} as ${AGENT_NAME}"
if ! uncluster agent join --server "${CP_URL}" --name "${AGENT_NAME}" 2>&1 | tee /tmp/join.log; then
    fail_product "agent join failed (see /tmp/join.log)"
fi
unset UNCLUSTER_TOKEN

# --- 4. supervisor: run sshd + agent run together ---
# Foreground sshd in the background; foreground `uncluster agent run` as PID 1's
# direct child via tini. If either exits non-zero, exit non-zero so the
# orchestrator sees the failure.
log "starting sshd"
/usr/sbin/sshd -D -e &
SSHD_PID=$!
log "sshd pid=${SSHD_PID}"

log "starting uncluster agent run"
uncluster agent run &
AGENT_PID=$!
log "agent pid=${AGENT_PID}"

# Wait for either to exit, then propagate the exit code.
set +e
wait -n "${SSHD_PID}" "${AGENT_PID}"
RC=$?
log "child exited rc=${RC}; tearing down siblings"
kill "${SSHD_PID}" "${AGENT_PID}" 2>/dev/null || true
wait || true
exit "${RC}"
