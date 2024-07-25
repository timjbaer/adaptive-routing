#!/bin/bash

if [ -z "${1}" ]; then
    echo "Please specify a subnet to adaptively route traffic towards"
    exit 1
fi

ROUTE_SUBNET="${1}"

# Create dummy virtual interface to attach BPF program.
ip link add adapt type dummy
ip link set adapt up

/sbin/tc qdisc del dev adapt clsact
/sbin/tc qdisc add dev adapt clsact
# TODO: move to C program.
# TODO: change to tc
/sbin/tc filter add dev adapt egress bpf direct-action obj redir.bpf.o sec avx_lb_redir

/sbin/tc qdisc show dev adapt
/sbin/tc filter show dev adapt egress

# TODO: clean up change vs add
ip route change "${ROUTE_SUBNET}" metric 100 proto 102 nexthop dev adapt

