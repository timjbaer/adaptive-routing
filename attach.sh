#!/bin/bash

if [ -z "${1}" ]; then
    echo "Please specify a subnet to adaptively route traffic towards"
    exit 1
fi

IP="${1}"

ip link add adapt type dummy 2>/dev/null
ip link set adapt up

ip route replace ${IP} dev adapt

# Attach BPF program to dummy interface.
/sbin/tc qdisc del dev adapt clsact 2>/dev/null
/sbin/tc qdisc add dev adapt clsact
/sbin/tc filter add dev adapt egress bpf direct-action obj redir.bpf.o sec adapt_redir

# Pin BPF maps.
SCORES_DIR="/sys/fs/bpf/adapt"
mkdir -p ${SCORES_DIR}

SCORES_MAP="${SCORES_DIR}/intf_scores"
rm ${SCORES_MAP} 2>/dev/null

bpftool map pin name intf_scores ${SCORES_MAP}

