#!/bin/sh

log() {
    echo "[test_local] $*"
}


SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "$0")"

echo $SCRIPT_PATH

if [ "$(id -u)" -ne 0 ]; then
    log "root privileges are required. Rerunning via sudo."
    exec sudo "$SCRIPT_PATH" "$@"
fi


BR_IF=br-veth
SERVER_IF=veth0
SERVER_PEER=${SERVER_IF}1
CLIENT_IF=veth1
CLIENT_PEER=${CLIENT_IF}1
LOG_DIR=logs
SERVER_LOG=$LOG_DIR/server.log
CLIENT_LOG=$LOG_DIR/client.log
SERVER_PID=
CLIENT_RC=1

cleanup() {
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
}
trap cleanup EXIT

mkdir -p "$LOG_DIR"
echo >"$SERVER_LOG"
echo >"$CLIENT_LOG"

log "recreate bridge $BR_IF"
${SCRIPT_DIR}/br-veth.sh ${BR_IF} ${SERVER_IF} ${CLIENT_IF} || {
    log "failed to create bridge"
    exit 1
}

SERVER_MAC=$(cat "/sys/class/net/$SERVER_IF/address")
log "server mac=$SERVER_MAC"

WDIR=.
SERVER_BIN=${WDIR}/a
CLIENT_BIN=${WDIR}/b
[ -x "$SERVER_BIN" ] || SERVER_BIN=${WDIR}/l2shell
[ -x "$CLIENT_BIN" ] || CLIENT_BIN=${WDIR}/l2shell

log "start server $SERVER_BIN any"
"$SERVER_BIN" any >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 1

log "run client"
"$CLIENT_BIN" "$CLIENT_IF" "$SERVER_MAC" /bin/sh "echo 123" >"$CLIENT_LOG" 2>&1
CLIENT_RC=$?

log "stop server"
kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null

log "server log:"
cat "$SERVER_LOG"
log "client log:"
cat "$CLIENT_LOG"

[ "$CLIENT_RC" -ne 0 ] && log "client rc=$CLIENT_RC" && exit "$CLIENT_RC"

if grep -q "123" "$CLIENT_LOG"; then
    log "ok: 123 found"
    exit 0
fi

log "fail: 123 not found"
exit 1