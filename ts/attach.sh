#!/bin/bash

if [ -z "${1}" ]; then
    echo "Please specify an IP to time one-way latency towards"
    exit 1
fi

IP="${1}"
IF="ts"

ip link add ${IF} type dummy 2>/dev/null
ip link set ${IF} up

ip route replace "${IP}" dev ts

# Attach BPF program to interface.
/sbin/tc qdisc del dev ${IF} clsact 2>/dev/null
/sbin/tc qdisc add dev ${IF} clsact
/sbin/tc filter add dev ${IF} egress bpf direct-action obj ts.bpf.o sec tc

