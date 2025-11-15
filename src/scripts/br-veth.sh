#!/bin/sh

usage() {
	cat << EOF
Usage: $0 [-h] BRIDGE SERVER_IF CLIENT_IF

Arguments:
	BRIDGE          Bridge interface name
	SERVER_IF       Server interface name
	CLIENT_IF       Client interface name

Options:
	-h              Show this help message

Example:
	$0 br-veth veth0 veth00
EOF
}

if [ "$1" = "-h" ]; then
	usage
	exit 0
fi

if [ $# -gt 3 ]; then
	usage
	exit 1
fi

BR_IF="$1"
SERVER_IF="$2"
CLIENT_IF="$3"

[ -z "$BR_IF" ] && BR_IF="br-veth"
[ -z "$SERVER_IF" ] && SERVER_IF="veth0"
[ -z "$CLIENT_IF" ] && CLIENT_IF="veth1"

ip link add "$BR_IF" type bridge
ip link add "$SERVER_IF" type veth peer name "${SERVER_IF}1"
ip link add "$CLIENT_IF" type veth peer name "${CLIENT_IF}1"
ip link set "${SERVER_IF}1" master "${BR_IF}"
ip link set "${CLIENT_IF}1" master "${BR_IF}"
ip link set "$BR_IF" up
ip link set "$SERVER_IF" up
ip link set "${SERVER_IF}1" up
ip link set "$CLIENT_IF" up
ip link set "${CLIENT_IF}1" up

