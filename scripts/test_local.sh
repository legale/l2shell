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

PS4='+ [${EPOCHREALTIME}] ${BASH_SOURCE##*/}:${LINENO}: '
set -x

SERVER_IF="veth_srv0"
CLIENT_IF="veth_cli0"
LOG_DIR="test_logs"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
TEST_PAYLOAD="ping_over_l2shell"
SLEEP_SHORT=1
SLEEP_LONG=2
SERVER_PID=""
CLIENT_PID=""
CLIENT_STDIN_FD=""

log() {
    echo "[test_local] $*"
}

command -v ip >/dev/null || { echo "iproute2 is required for this test" >&2; exit 1; }

cleanup() {
    set +e
    if [[ -n "${CLIENT_STDIN_FD:-}" ]]; then
        exec {CLIENT_STDIN_FD}>&-
        CLIENT_STDIN_FD=""
    fi
    if [[ -n "${CLIENT_PID:-}" ]] && kill -0 "${CLIENT_PID}" >/dev/null 2>&1; then
        kill "${CLIENT_PID}" >/dev/null 2>&1
        wait "${CLIENT_PID}" >/dev/null 2>&1
    fi
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
        kill "${SERVER_PID}" >/dev/null 2>&1
        wait "${SERVER_PID}" >/dev/null 2>&1
    fi
    ip link del "${SERVER_IF}" >/dev/null 2>&1
}
trap cleanup EXIT

mkdir -p "${LOG_DIR}"
: >"${SERVER_LOG}"
: >"${CLIENT_LOG}"

log "Recreating veth pair ${SERVER_IF}<->${CLIENT_IF}"
ip link del "${SERVER_IF}" >/dev/null 2>&1 || true
ip link add "${SERVER_IF}" type veth peer name "${CLIENT_IF}"
ip link set "${SERVER_IF}" up
ip link set "${CLIENT_IF}" up

SERVER_MAC="$(cat /sys/class/net/${SERVER_IF}/address)"
log "Server MAC detected: ${SERVER_MAC}"

log "Launching server ./a on ${SERVER_IF}"
./a "${SERVER_IF}" /bin/cat >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep "${SLEEP_LONG}"

log "Launching client ./b toward ${SERVER_MAC} on ${CLIENT_IF}"
coproc CLIENT_SESSION { ./b "${CLIENT_IF}" "${SERVER_MAC}" >"${CLIENT_LOG}" 2>&1; }
CLIENT_PID="${CLIENT_SESSION_PID}"
CLIENT_STDIN_FD=${CLIENT_SESSION[1]}
CLIENT_STDOUT_FD=${CLIENT_SESSION[0]}
exec {CLIENT_STDOUT_FD}>&-
sleep "${SLEEP_LONG}"

log "Sending payload '${TEST_PAYLOAD}' through client session"
printf '%s\n' "${TEST_PAYLOAD}" >&${CLIENT_STDIN_FD}
sleep "${SLEEP_LONG}"

log "Stopping client and server processes"
if [[ -n "${CLIENT_PID:-}" ]] && kill -0 "${CLIENT_PID}" >/dev/null 2>&1; then
    kill "${CLIENT_PID}" >/dev/null 2>&1 || true
    wait "${CLIENT_PID}" >/dev/null 2>&1 || true
fi
if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
fi
sleep "${SLEEP_SHORT}"

log "Server log preview:"
tail -n +1 "${SERVER_LOG}" || true
log "Client log preview:"
tail -n +1 "${CLIENT_LOG}" || true

if grep -q "${TEST_PAYLOAD}" "${CLIENT_LOG}"; then
    log "Local veth test passed"
    exit 0
else
    log "Local veth test failed: payload not observed in ${CLIENT_LOG}"
    exit 1
fi
