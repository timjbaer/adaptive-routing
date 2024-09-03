. ./var.sh

# Enable kernel modules.
lsmod | grep gre
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/fib_multipath_hash_policy

# Add GRE tunnels.
ip tunnel add gre1 mode gre remote ${VM3_IP} local ${VM2_IP} ttl 225
ip addr add ${TUN1_SRC_CIDR} dev gre1
ip link set dev gre1 up

ip tunnel add gre2 mode gre remote ${VM3_IP2} local ${VM2_IP} ttl 225
ip addr add ${TUN2_SRC_CIDR} dev gre2
ip link set dev gre2 up

# Add ECMP over tunnels.
ip route add ${VM4_IP} \
	nexthop via ${TUN1_DST_IP} dev gre1 \
	nexthop via ${TUN2_DST_IP} dev gre2

# Route packets toward VM4 through adapt interface.
echo 100 custom >> /etc/iproute2/rt_tables
ip route add ${VM4_IP} dev adapt table 100

ip rule add fwmark 0x1 lookup 100
iptables -t mangle -A PREROUTING -j MARK --set-mark 0x1
iptables -t mangle -A OUTPUT -j MARK --set-mark 0x0

