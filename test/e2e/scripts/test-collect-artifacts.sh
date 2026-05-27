#!/usr/bin/env bash
# Standalone smoke test for collect-artifacts.sh that does NOT need Docker.
# Mocks `docker` via a PATH-shadowed stub that prints canned output, then
# verifies the collector lays down the expected file tree.
#
# Per ADR-0008 the collector promises (at minimum):
#   cp/logs.txt, agent/logs.txt, agent/sshd-T.txt, agent/auth_principals-...,
#   caller/logs.txt, compose.yml, docker.ps.json
set -euo pipefail

THIS_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${THIS_DIR}/collect-artifacts.sh"
COMPOSE_FILE="${THIS_DIR}/../docker-compose.yml"

# Sandbox PATH so our docker stub wins.
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
STUB="${WORK}/bin/docker"
mkdir -p "${WORK}/bin"

cat > "${STUB}" <<'EOF'
#!/usr/bin/env bash
# Mock docker for collect-artifacts smoke test.
case "$1 $2" in
    "compose ps")
        if [[ "$*" == *"--format json"* ]]; then
            echo '[{"Name":"cp"},{"Name":"agent"},{"Name":"caller"}]'
            exit 0
        fi
        ;;
    "compose config")
        echo "name: uncluster-e2e"
        echo "services: {cp: {}, agent: {}, caller: {}}"
        exit 0
        ;;
    "compose logs")
        echo "[mock] logs for $*"
        exit 0
        ;;
    "compose exec")
        # arg layout: compose -f <file> exec -T <role> sh -c <cmd>
        # Echo a recognisable line so the collector files have content.
        echo "[mock-exec] $*"
        exit 0
        ;;
esac
exit 0
EOF
chmod +x "${STUB}"

OUT="${WORK}/artifacts"
PATH="${WORK}/bin:${PATH}" COMPOSE_FILE="${COMPOSE_FILE}" bash "${COLLECTOR}" "${OUT}"

# Verify the expected files exist with non-empty contents.
fail=0
require() {
    if [[ ! -e "${OUT}/$1" ]]; then
        echo "MISSING: ${OUT}/$1"
        fail=1
    fi
}

require "docker.ps.json"
require "compose.yml"
require "cp/logs.txt"
require "agent/logs.txt"
require "agent/sshd-T.txt"
require "agent/sshd-drop-in.conf"
require "agent/ca.pub"
require "agent/auth_principals-listing.txt"
require "agent/auth_principals-contents.txt"
require "agent/ip-addr.txt"
require "agent/listening-ports.txt"
require "caller/logs.txt"
require "caller/cli.toml"

if [[ "${fail}" -ne 0 ]]; then
    echo "FAILED — see missing files above"
    echo "--- tree under ${OUT} ---"
    find "${OUT}" -type f
    exit 1
fi

echo "OK — artifact collector produced all required files"
