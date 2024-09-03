# Adaptive Routing with eBPF

## Setup

### AWS Console

#### Security Groups
Open security groups on all VMs to local subnet and tunnel traffic.

#### Source/Destination Check
Stop source/destination check on all VMs.

```
Select EC2 instance: Actions → Networking → Change source/destination check → select Stop.
```

### Dependencies
- llvm
- clang
- libbpf-dev

### Scripts
Setup scripts are provided under `/setup`.

