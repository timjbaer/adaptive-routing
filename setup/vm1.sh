. ./var.sh

# Route traffic toward VM4 via VM2.
ip route add ${VM4_IP} via ${VM2_IP}

