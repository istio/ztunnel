#! /bin/bash

set -eux

ip netns delete pod1 || true
ip netns delete z || true
ip link delete pod1 || true
ip link delete z || true

ip netns add pod1
ip -n pod1 link set lo up
# veth device
ip link add pod1 type veth peer name pod1-eth0
# move one end to the pod
ip link set pod1-eth0 netns pod1
# configure the veth devices
ip link set pod1 up
ip -n pod1 link set pod1-eth0 up
ip addr add dev pod1 10.0.0.1/24
ip -n pod1 addr add dev pod1-eth0 10.0.0.2/24
ip netns exec pod1 ip route add default dev pod1-eth0

ip netns add z
ip -n z link set lo up
# veth device
ip link add z type veth peer name z-eth0
# move one end to the pod
ip link set z-eth0 netns z
# configure the veth devices
ip link set z up
ip -n z link set z-eth0 up
ip addr add dev z 10.0.1.1/24
ip -n z addr add dev z-eth0 10.0.1.2/24
ip netns exec z ip route add default dev z-eth0



cat <<EOF | ip netns exec pod1 bash
source ./scripts/local.sh
export ZTUNNEL_REDIRECT_USER="iptables1"
redirect-user-setup
redirect-to 15001
EOF
