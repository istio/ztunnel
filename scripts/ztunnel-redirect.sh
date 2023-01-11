#!/bin/bash

# This script sets up redirection in the ztunnel network namespace for namespaced tests (tests/README.md)
set -ex

INSTANCE_IP="${1:?INSTANCE_IP}"
shift


# START https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L198-L205
PROXY_OUTBOUND_MARK=0x401/0xfff
PROXY_INBOUND_MARK=0x402/0xfff
PROXY_ORG_SRC_MARK=0x4d2/0xfff
# tproxy mark, it's only used here.
MARK=0x400/0xfff
ORG_SRC_RET_MARK=0x4d3/0xfff
# END https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L198-L205

# Below is from config.sh but used in redirect-worker.sh as well
POD_OUTBOUND=15001
POD_INBOUND=15008
POD_INBOUND_PLAINTEXT=15006

# socket mark setup
OUTBOUND_MASK="0x100"
OUTBOUND_MARK="0x100/$OUTBOUND_MASK"

SKIP_MASK="0x200"
SKIP_MARK="0x200/$SKIP_MASK"

# note!! this includes the skip mark bit, so match on skip mark will match this as well.
CONNSKIP_MASK="0x220"
CONNSKIP_MARK="0x220/$CONNSKIP_MASK"

# note!! this includes the skip mark bit, so match on skip mark will match this as well.
PROXY_MASK="0x210"
PROXY_MARK="0x210/$PROXY_MASK"

PROXY_RET_MASK="0x040"
PROXY_RET_MARK="0x040/$PROXY_RET_MASK"

INBOUND_TUN=istioin
OUTBOUND_TUN=istioout

# TODO: look into why link local (169.254.x.x) address didn't work
# they don't respond to ARP.
INBOUND_TUN_IP=192.168.126.1
ZTUNNEL_INBOUND_TUN_IP=192.168.126.2
OUTBOUND_TUN_IP=192.168.127.1
ZTUNNEL_OUTBOUND_TUN_IP=192.168.127.2
TUN_PREFIX=30

# a route table number number we can use to send traffic to envoy (should be unused).
INBOUND_ROUTE_TABLE=100
INBOUND_ROUTE_TABLE2=103
OUTBOUND_ROUTE_TABLE=101
# needed for original src.
PROXY_ROUTE_TABLE=102

HOST_IP=$(ip route | grep default | awk '{print $3}')

ip link add name p$INBOUND_TUN type geneve id 1000 remote $HOST_IP
ip addr add $ZTUNNEL_INBOUND_TUN_IP/$TUN_PREFIX dev p$INBOUND_TUN

ip link add name p$OUTBOUND_TUN type geneve id 1001 remote $HOST_IP
ip addr add $ZTUNNEL_OUTBOUND_TUN_IP/$TUN_PREFIX dev p$OUTBOUND_TUN

ip link set p$INBOUND_TUN up
ip link set p$OUTBOUND_TUN up

echo 0 > /proc/sys/net/ipv4/conf/p$INBOUND_TUN/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/p$OUTBOUND_TUN/rp_filter

ip rule add priority 20000 fwmark $MARK lookup 100
ip rule add priority 20001 fwmark $PROXY_OUTBOUND_MARK lookup 101
ip rule add priority 20002 fwmark $PROXY_INBOUND_MARK lookup 102
ip rule add priority 20003 fwmark $ORG_SRC_RET_MARK lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

ip route add table 101 $HOST_IP dev eth0 scope link
ip route add table 101 0.0.0.0/0 via $OUTBOUND_TUN_IP dev p$OUTBOUND_TUN

ip route add table 102 $HOST_IP dev eth0 scope link
ip route add table 102 0.0.0.0/0 via $INBOUND_TUN_IP dev p$INBOUND_TUN

set +e
num_legacy_lines=$( (iptables-legacy-save || true; ip6tables-legacy-save || true) 2>/dev/null | grep '^-' | wc -l)
if [ "${num_legacy_lines}" -ge 10 ]; then
  mode=legacy
else
  num_nft_lines=$( (timeout 5 sh -c "iptables-nft-save; ip6tables-nft-save" || true) 2>/dev/null | grep '^-' | wc -l)
  if [ "${num_legacy_lines}" -ge "${num_nft_lines}" ]; then
    mode=legacy
  else
    mode=nft
  fi
fi
IPTABLES=iptables-legacy
if [ "${mode}" = "nft" ]; then
  IPTABLES=iptables-nft
fi
set -e

$IPTABLES -w -t mangle -F PREROUTING
$IPTABLES -w -t nat -F OUTPUT

$IPTABLES -w -t mangle -A PREROUTING -p tcp -i p$INBOUND_TUN -m tcp --dport=$POD_INBOUND -j TPROXY --tproxy-mark $MARK --on-port $POD_INBOUND --on-ip 127.0.0.1
$IPTABLES -w -t mangle -A PREROUTING -p tcp -i p$OUTBOUND_TUN -j TPROXY --tproxy-mark $MARK --on-port $POD_OUTBOUND --on-ip 127.0.0.1
$IPTABLES -w -t mangle -A PREROUTING -p tcp -i p$INBOUND_TUN -j TPROXY --tproxy-mark $MARK --on-port $POD_INBOUND_PLAINTEXT --on-ip 127.0.0.1

$IPTABLES -w -t mangle -A PREROUTING -p tcp -i eth0 ! --dst $INSTANCE_IP -j MARK --set-mark $ORG_SRC_RET_MARK

# Huge hack. Currently, we only support single "node" test setup. This means we cannot test
# Cross-ztunnel requests. Instead, loop these back to ourselves.
# TODO: setup multiple ztunnels and actually communicate between them; then this can be removed.
# We send HBONE to waypoints, so let those through...
ipset create waypoint-pods-ips hash:ip
for waypoint in $@; do
  ipset add waypoint-pods-ips "${waypoint}"
done
$IPTABLES -w -t nat -A OUTPUT -p tcp --dport 15008 -m set '!' --match-set waypoint-pods-ips dst -j REDIRECT --to-port $POD_INBOUND

# With normal linux routing we need to disable the rp_filter
# as we get packets from a tunnel that doesn't have default routes.
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/eth0/rp_filter

#$IPTABLES -t mangle -I PREROUTING -j LOG --log-prefix "mangle pre [zt] "
#$IPTABLES -t mangle -I POSTROUTING -j LOG --log-prefix "mangle post [zt] "
#$IPTABLES -t mangle -I INPUT -j LOG --log-prefix "mangle inp [zt] "
#$IPTABLES -t mangle -I OUTPUT -j LOG --log-prefix "mangle out [zt] "
#$IPTABLES -t mangle -I FORWARD -j LOG --log-prefix "mangle fw [zt] "
#$IPTABLES -t nat -I POSTROUTING -j LOG --log-prefix "nat post [zt] "
#$IPTABLES -t nat -I INPUT -j LOG --log-prefix "nat inp [zt] "
#$IPTABLES -t nat -I OUTPUT -j LOG --log-prefix "nat out [zt] "
#$IPTABLES -t nat -I PREROUTING -j LOG --log-prefix "nat pre [zt] "
#$IPTABLES -t raw -I PREROUTING -j LOG --log-prefix "raw pre [zt] "
#$IPTABLES -t raw -I OUTPUT -j LOG --log-prefix "raw out [zt] "
#$IPTABLES -t filter -I FORWARD -j LOG --log-prefix "filt fw [zt] "
#$IPTABLES -t filter -I OUTPUT -j LOG --log-prefix "filt out [zt] "
#$IPTABLES -t filter -I INPUT -j LOG --log-prefix "filt inp [zt] "
