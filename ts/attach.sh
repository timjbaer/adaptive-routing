#!/bin/bash

if [ -z "${1}" ]; then
    echo "Please specify an IP to time one-way latency towards"
    exit 1
fi

IP="${1}"

ip link add ts type dummy 2>/dev/null
ip link set ts up

ip route del "${IP}"
ip route add "${IP}" dev ts

# Attach BPF program to interface.
/sbin/tc qdisc del dev ts clsact 2>/dev/null
/sbin/tc qdisc add dev ts clsact
/sbin/tc filter add dev ts egress bpf direct-action obj ts.bpf.o sec ts

