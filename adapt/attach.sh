#!/bin/bash

IF="adapt"

# Attach BPF program to dummy interface.
/sbin/tc qdisc del dev ${IF} clsact 2>/dev/null
/sbin/tc qdisc add dev ${IF} clsact
/sbin/tc filter add dev ${IF} egress bpf direct-action obj redir.bpf.o sec tc

