#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"

if [[ "${EUID}" -ne 0 ]]; then
    echo "[test_local] root privileges are required. Run via 'sudo make test' or execute this script under sudo." >&2
    exit 1
fi

# Ensure we always run from the repo root for predictable relative paths.
if [[ "${L2SHELL_TEST_ROOT:-0}" != "1" ]]; then
    export L2SHELL_TEST_ROOT=1
    cd "${REPO_ROOT}"
    exec "${SCRIPT_PATH}" "$@"
fi

BR_IF="br_l2shell0"
SERVER_IF="veth_srv0"
SERVER_PEER="veth_srv1"
CLIENT_IF="veth_cli0"
CLIENT_PEER="veth_cli1"
LOG_DIR="test_logs"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
SERVER_PID=""
CLIENT_RC=1

log() {
    echo "[test_local] $*"
}

command -v ip >/dev/null || { echo "iproute2 is required for this test" >&2; exit 1; }

cleanup() {
    set +e
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
        kill "${SERVER_PID}" >/dev/null 2>&1
        wait "${SERVER_PID}" >/dev/null 2>&1
    fi
    ip link set "${SERVER_PEER}" nomaster >/dev/null 2>&1 || true
    ip link set "${CLIENT_PEER}" nomaster >/dev/null 2>&1 || true
    ip link del "${SERVER_IF}" >/dev/null 2>&1 || true
    ip link del "${CLIENT_IF}" >/dev/null 2>&1 || true
    ip link del "${BR_IF}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "${LOG_DIR}" || true
chmod 777 "${LOG_DIR}" || true
chmod 666 "${LOG_DIR}"/*.log || true
: >"${SERVER_LOG}"
: >"${CLIENT_LOG}"

log "Recreating bridge ${BR_IF} with veth pairs"
ip link del "${SERVER_IF}" >/dev/null 2>&1 || true
ip link del "${CLIENT_IF}" >/dev/null 2>&1 || true
ip link del "${BR_IF}" >/dev/null 2>&1 || true

ip link add "${BR_IF}" type bridge
ip link set "${BR_IF}" up

ip link add "${SERVER_IF}" type veth peer name "${SERVER_PEER}"
ip link add "${CLIENT_IF}" type veth peer name "${CLIENT_PEER}"

for dev in "${SERVER_IF}" "${SERVER_PEER}" "${CLIENT_IF}" "${CLIENT_PEER}"; do
    ip link set "${dev}" up
done

ip link set "${SERVER_PEER}" master "${BR_IF}"
ip link set "${CLIENT_PEER}" master "${BR_IF}"

SERVER_MAC="$(cat /sys/class/net/${SERVER_IF}/address)"
log "Server MAC detected: ${SERVER_MAC}"

log "Launching server ./a on ${SERVER_IF}"
./a "${SERVER_IF}" /bin/bash >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 1

log "Running client ./b on ${CLIENT_IF} to send 'echo 123'"
set +e
./b "${CLIENT_IF}" "${SERVER_MAC}" "echo 123" >"${CLIENT_LOG}" 2>&1
CLIENT_RC=$?
set -e

log "Stopping server process"
if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
fi

log "Server log preview:"
tail -n +1 "${SERVER_LOG}" || true
log "Client log preview:"
tail -n +1 "${CLIENT_LOG}" || true

if [[ ${CLIENT_RC} -ne 0 ]]; then
    log "Local test failed: client exited with code ${CLIENT_RC}"
    exit "${CLIENT_RC}"
fi

# поиск 123 целиком во всех строчках выхлопа клиента
found=0
while IFS= read -r line; do
    if [[ "$line" == *"123"* ]]; then
        log "Local bridge test passed: found '123' in output"
        found=1
        break
    fi
done < "${CLIENT_LOG}"

if [[ $found -eq 1 ]]; then
    exit 0
fi

log "Local bridge test failed: expected '123' in client output"
exit 1
