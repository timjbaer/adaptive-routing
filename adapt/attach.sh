#!/bin/bash

if [ -z "${1}" ]; then
    echo "Please specify an IP to adaptively route traffic towards"
    exit 1
fi

IF="adapt"

# Attach BPF program to dummy interface.
/sbin/tc qdisc del dev ${IF} clsact 2>/dev/null
/sbin/tc qdisc add dev ${IF} clsact
/sbin/tc filter add dev ${IF} egress bpf direct-action obj redir.bpf.o sec tc

