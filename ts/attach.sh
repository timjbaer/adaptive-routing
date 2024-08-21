#!/bin/bash

if [ -z "${1}" ]; then
    echo "Please specify an IP to time one-way latency towards"
    exit 1
fi

IP="${1}"

ip link add adapt type dummy 2>/dev/null
ip link set adapt up

ip route del "${IP}"
ip route add "${IP}" dev adapt

# Attach BPF program to interface.
/sbin/tc qdisc del dev adapt clsact 2>/dev/null
/sbin/tc qdisc add dev adapt clsact
/sbin/tc filter add dev adapt egress bpf direct-action obj ts.bpf.o sec ts

