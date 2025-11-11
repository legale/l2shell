#!/bin/sh

ip link add br-veth type bridge
ip link add veth0 type veth peer name veth1
ip link add veth00 type veth peer name veth11
ip link set veth0 master br-veth
ip link set veth00 master br-veth
ip link set br-veth up
ip link set veth0 up
ip link set veth1 up
ip link set veth00 up
ip link set veth11 up

