#!/bin/sh

# Helper functions
log() {
    echo "[test_local] $*"
}

run() {
    log "$*"
    "$@"
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "$0")"

if [ "$(id -u)" -ne 0 ]; then
    log "root privileges are required. Run via 'sudo make test' or execute this script under sudo." >&2
    exit 1
fi

# Ensure we always run from the repo root for predictable relative paths
if [ "${L2SHELL_TEST_ROOT:-0}" != "1" ]; then
    export L2SHELL_TEST_ROOT=1
    cd "${REPO_ROOT}" || exit 1
    exec "${SCRIPT_PATH}" "$@"
fi

BR_IF="br_l2shell0"
SERVER_IF="veth_srv0"
SERVER_PEER="veth_srv1" 
CLIENT_IF="veth_cli0"
CLIENT_PEER="veth_cli1"
LOG_DIR="logs"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
SERVER_PID=""
CLIENT_RC=1

cleanup() {
    set +e
    if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null
        wait "${SERVER_PID}" 2>/dev/null
    fi
    ip link set "${SERVER_PEER}" nomaster 2>/dev/null
    ip link set "${CLIENT_PEER}" nomaster 2>/dev/null
    ip link del "${SERVER_IF}" 2>/dev/null
    ip link del "${CLIENT_IF}" 2>/dev/null
    ip link del "${BR_IF}" 2>/dev/null
}
trap cleanup EXIT

# Setup
mkdir -p "${LOG_DIR}" && chmod 777 "${LOG_DIR}"
: >"${SERVER_LOG}"
: >"${CLIENT_LOG}"

log "Recreating bridge ${BR_IF} with veth pairs"
run ip link del "${BR_IF}" 2>/dev/null || true

run ip link add "${BR_IF}" type bridge
run ip link set "${BR_IF}" up

run ip link add "${SERVER_IF}" type veth peer name "${SERVER_PEER}"
run ip link add "${CLIENT_IF}" type veth peer name "${CLIENT_PEER}"

for dev in "${SERVER_IF}" "${SERVER_PEER}" "${CLIENT_IF}" "${CLIENT_PEER}"; do
    run ip link set "${dev}" up
done

run ip link set "${SERVER_PEER}" master "${BR_IF}"
run ip link set "${CLIENT_PEER}" master "${BR_IF}"

SERVER_MAC="$(cat "/sys/class/net/${SERVER_IF}/address")"
log "Server MAC detected: ${SERVER_MAC}"

# Run test
log "Launching server ./a on ${SERVER_IF}"
./a "${SERVER_IF}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 1

log "Running client"
run ./b "${CLIENT_IF}" "${SERVER_MAC}" /bin/sh "echo 123" >"${CLIENT_LOG}" 2>&1
CLIENT_RC=$?

log "Stopping server process"
[ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null && wait "${SERVER_PID}" 2>/dev/null

log "Server log preview:"
tail -n +1 "${SERVER_LOG}" || true
log "Client log preview:" 
tail -n +1 "${CLIENT_LOG}" || true

if [ ${CLIENT_RC} -ne 0 ]; then
    log "Local test failed: client exited with code ${CLIENT_RC}"
    exit ${CLIENT_RC}
fi


FOUND_COUNT=$(grep -c "123" "${CLIENT_LOG}")
if [ "$FOUND_COUNT" -gt 2 ]; then
    log "Local bridge test passed: found '123' in output"
    rm -f "${CLIENT_LOG}" "${SERVER_LOG}"
    exit 0
else
    log "Local bridge test failed: expected '123' in client output"
    exit 1
fi
