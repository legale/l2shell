#!/bin/sh

set -e

log() {
    echo "[test_kernel] $*"
}

run() {
    log "$*"
    "$@"
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "$0")"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SRC_DIR="${REPO_ROOT}/src"

echo $SCRIPT_PATH

if [ "$(id -u)" -ne 0 ]; then
    log "root privileges are required. Rerunning via sudo."
    exec sudo "$SCRIPT_PATH" "$@"
fi

if [ "${L2SHELL_TEST_ROOT:-0}" != "1" ]; then
    export L2SHELL_TEST_ROOT=1
    cd "${SRC_DIR}" || exit 1
    exec "$SCRIPT_PATH" "$@"
fi

BR_IF="br-veth"
SERVER_IF="veth0"
SERVER_PEER="veth00"
CLIENT_IF="veth1"
CLIENT_PEER="veth11"
LOG_DIR="${REPO_ROOT}/logs"
CLIENT_LOG="${LOG_DIR}/kernel_client.log"
SERVER_LOG="${LOG_DIR}/kernel_server.log"
KERNEL_LOG="${LOG_DIR}/kernel_module.log"
DMESG_PID=""

cleanup() {
    set +e
    if [ -n "${DMESG_PID}" ] && kill -0 "${DMESG_PID}" 2>/dev/null; then
        kill "${DMESG_PID}" 2>/dev/null
    fi
    dmesg -c >/dev/null 2>&1 || true
    ip link set "${SERVER_PEER}" nomaster 2>/dev/null
    ip link set "${CLIENT_PEER}" nomaster 2>/dev/null
    ip link del "${SERVER_IF}" 2>/dev/null
    ip link del "${CLIENT_IF}" 2>/dev/null
    ip link del "${BR_IF}" 2>/dev/null
    rmmod l2shell_kmod 2>/dev/null || true
}


trap cleanup EXIT

mkdir -p "${LOG_DIR}"
: >"${CLIENT_LOG}"
: >"${SERVER_LOG}"
: >"${KERNEL_LOG}"

log "clearing kernel ring buffer"
dmesg -c >/dev/null || true

log "starting kernel log capture"
stdbuf -oL -eL dmesg -w | stdbuf -oL grep -a "l2sh:" >>"${KERNEL_LOG}" &
DMESG_PID=$!

log "creating bridge ${BR_IF} with veth pairs"
${SCRIPT_DIR}/br-veth.sh "${BR_IF}" "${SERVER_IF}" "${CLIENT_IF}"

SERVER_MAC="$(cat "/sys/class/net/${SERVER_IF}/address")"
log "server mac=${SERVER_MAC}"


log "building kernel module"
run env MAKEFLAGS= make kmod

log "building userland binaries"
run env MAKEFLAGS= make l2shell

log "loading kernel module"
if lsmod | grep -q "^l2shell_kmod"; then
    if ! rmmod l2shell_kmod; then
        log "failed to unload existing l2shell_kmod, aborting"
        exit 1
    fi
fi
run insmod ./l2shell_kmod.ko

CLIENT_BIN="${SRC_DIR}/b"
SERVER_BIN="${SRC_DIR}/a"
ln -sf l2shell "${SERVER_BIN}"
ln -sf l2shell "${CLIENT_BIN}"

cd "${REPO_ROOT}" || exit 1

SPAWN_CMD="${SERVER_BIN} --log-file ${SERVER_LOG} any"
log "spawn command: \"${SPAWN_CMD}\""
log "running client against kernel module"
set +e
"${CLIENT_BIN}" --log-file "${CLIENT_LOG}" --idle-timeout 10 --spawn "${SPAWN_CMD}" "${CLIENT_IF}" "${SERVER_MAC}" /bin/sh "echo 123"
CLIENT_RC=$?
set -e

if [ ${CLIENT_RC} -ne 0 ]; then
    log "client exited with code ${CLIENT_RC}"
    exit ${CLIENT_RC}
fi

if ! grep -q "123" "${CLIENT_LOG}"; then
    log "kernel test failed: expected '123' in client output"
    exit 1
fi

wait_for_log() {
    pattern=$1
    timeout=$2
    start_line=${3:-1}
    start_ts=$(date +%s)
    while [ $(( $(date +%s) - start_ts )) -lt "${timeout}" ]; do
        if tail -n +"${start_line}" "${KERNEL_LOG}" | grep -E -q "${pattern}"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

disabled_pattern="capture disabled|listening stopped"
log "waiting for kernel module to hand off to userspace"
if ! wait_for_log "${disabled_pattern}" 30; then
    log "kernel test failed: did not observe capture disabled log"
    exit 1
fi

disabled_line=$(grep -n -E "${disabled_pattern}" "${KERNEL_LOG}" | tail -n 1 | cut -d: -f1)
next_start=$((disabled_line + 1))

enable_pattern="capture enabled|listening started"
log "waiting for kernel module to resume capture"
if ! wait_for_log "${enable_pattern}" 30 "${next_start}"; then
    log "kernel test failed: module did not resume capture"
    exit 1
fi

if ! grep -q "launching cmd" "${KERNEL_LOG}"; then
    log "kernel test failed: no command launch recorded"
    exit 1
fi

log "kernel bridge test passed"
log "Kernel log preview:"
tail -n +1 "${KERNEL_LOG}" || true
log "Client log:"
tail -n +1 "${CLIENT_LOG}" || true
