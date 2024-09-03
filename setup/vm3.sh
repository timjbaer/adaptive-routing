. ./var.sh

lsmod | grep gre
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/fib_multipath_hash_policy

ip tunnel add gre1 mode gre remote ${VM2_IP} local ${VM3_IP} ttl 225
ip addr add ${TUN1_DST_CIDR} dev gre1
ip link set dev gre1 up

ip tunnel add gre2 mode gre remote ${VM2_IP} local ${VM3_IP2} ttl 225
ip addr add ${TUN2_DST_CIDR} dev gre2
ip link set dev gre2 up

