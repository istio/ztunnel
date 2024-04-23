#!/bin/bash

# This script sets up redirection in the host network namespace for namespaced tests (tests/README.md)
set -ex

HOST_IP="$(ip -j addr | jq '.[] | select(.ifname == "eth0").addr_info[0].local' -r)"
ZTUNNEL_IP="${1:?ztunnel IP}"
ZTUNNEL_INTERFACE="${2:?ztunnel interface}"
shift; shift;
set +e
ipset -L ztunnel-pods-ips >/dev/null 2>&1
if [ $? -eq 0 ]; then
  # ipset already exists, we must be a later iteration..
  for ip in "$@"; do
    ipset add ztunnel-pods-ips "${ip}"
  done
  exit 0
fi
set -e
ipset create ztunnel-pods-ips hash:ip || :
for ip in "$@"; do
  ipset add ztunnel-pods-ips "${ip}"
done

# Setup interfaces
ip link add name istioin type geneve id 1000 remote "${ZTUNNEL_IP}"
ip addr add 192.168.126.1/30 dev istioin
ip link set istioin up

ip link add name istioout type geneve id 1001 remote "${ZTUNNEL_IP}"
ip addr add 192.168.127.1/30 dev istioout
ip link set istioout up

cat <<EOF | iptables-restore -w
*mangle
:PREROUTING ACCEPT
:INPUT ACCEPT
:FORWARD ACCEPT
:OUTPUT ACCEPT
:POSTROUTING ACCEPT
:ztunnel-FORWARD -
:ztunnel-INPUT -
:ztunnel-OUTPUT -
:ztunnel-POSTROUTING -
:ztunnel-PREROUTING -
-A PREROUTING -j ztunnel-PREROUTING
-A INPUT -j ztunnel-INPUT
-A FORWARD -j ztunnel-FORWARD
-A OUTPUT -j ztunnel-OUTPUT
-A POSTROUTING -j ztunnel-POSTROUTING
-A ztunnel-FORWARD -m mark --mark 0x220/0x220 -j CONNMARK --save-mark --nfmask 0x220 --ctmask 0x220
-A ztunnel-FORWARD -m mark --mark 0x210/0x210 -j CONNMARK --save-mark --nfmask 0x210 --ctmask 0x210
-A ztunnel-INPUT -m mark --mark 0x220/0x220 -j CONNMARK --save-mark --nfmask 0x220 --ctmask 0x220
-A ztunnel-INPUT -m mark --mark 0x210/0x210 -j CONNMARK --save-mark --nfmask 0x210 --ctmask 0x210
-A ztunnel-OUTPUT -s ${HOST_IP}/32 -j MARK --set-xmark 0x220/0xffffffff
-A ztunnel-PREROUTING -i istioin -j MARK --set-xmark 0x200/0x200
-A ztunnel-PREROUTING -i istioin -j RETURN
-A ztunnel-PREROUTING -i istioout -j MARK --set-xmark 0x200/0x200
-A ztunnel-PREROUTING -i istioout -j RETURN
-A ztunnel-PREROUTING -p udp -m udp --dport 6081 -j RETURN
-A ztunnel-PREROUTING -m connmark --mark 0x220/0x220 -j MARK --set-xmark 0x200/0x200
-A ztunnel-PREROUTING -m mark --mark 0x200/0x200 -j RETURN
-A ztunnel-PREROUTING ! -i ${ZTUNNEL_INTERFACE} -m connmark --mark 0x210/0x210 -j MARK --set-xmark 0x40/0x40
-A ztunnel-PREROUTING -m mark --mark 0x40/0x40 -j RETURN
-A ztunnel-PREROUTING ! -s ${ZTUNNEL_IP}/32 -i ${ZTUNNEL_INTERFACE} -j MARK --set-xmark 0x210/0x210
-A ztunnel-PREROUTING -m mark --mark 0x200/0x200 -j RETURN
-A ztunnel-PREROUTING -i ${ZTUNNEL_INTERFACE} -j MARK --set-xmark 0x220/0x220
-A ztunnel-PREROUTING -p udp -j MARK --set-xmark 0x220/0x220
-A ztunnel-PREROUTING -m mark --mark 0x200/0x200 -j RETURN
-A ztunnel-PREROUTING -p tcp -m set --match-set ztunnel-pods-ips src -j MARK --set-xmark 0x100/0x100
COMMIT
*nat
:PREROUTING ACCEPT
:INPUT ACCEPT
:OUTPUT ACCEPT
:POSTROUTING ACCEPT
:ztunnel-POSTROUTING -
:ztunnel-PREROUTING -
-A PREROUTING -j ztunnel-PREROUTING
-A POSTROUTING -j ztunnel-POSTROUTING
-A ztunnel-POSTROUTING -m mark --mark 0x100/0x100 -j ACCEPT
-A ztunnel-PREROUTING -m mark --mark 0x100/0x100 -j ACCEPT
COMMIT
EOF

ip route add table 101 "${ZTUNNEL_IP}" dev "${ZTUNNEL_INTERFACE}" scope link
ip route add table 101 0.0.0.0/0 via 192.168.127.2 dev istioout
ip route add table 102 "${ZTUNNEL_IP}" dev "${ZTUNNEL_INTERFACE}" scope link
ip route add table 102 0.0.0.0/0 via "${ZTUNNEL_IP}" dev "${ZTUNNEL_INTERFACE}" onlink
ip route add table 100 "${ZTUNNEL_IP}" dev "${ZTUNNEL_INTERFACE}" scope link
for ip in "$@"; do
  ip route add table 100 "${ip}/32" via 192.168.126.2 dev istioin src "$HOST_IP"
done

ip rule add priority 100 fwmark 0x200/0x200 goto 32766
ip rule add priority 101 fwmark 0x100/0x100 lookup 101
ip rule add priority 102 fwmark 0x040/0x040 lookup 102
ip rule add priority 103 table 100

#IPTABLES=iptables-legacy
#$IPTABLES -t mangle -I PREROUTING -j LOG --log-prefix "mangle pre [node] "
#$IPTABLES -t mangle -I POSTROUTING -j LOG --log-prefix "mangle post [node] "
#$IPTABLES -t mangle -I INPUT -j LOG --log-prefix "mangle inp [node] "
#$IPTABLES -t mangle -I OUTPUT -j LOG --log-prefix "mangle out [node] "
#$IPTABLES -t mangle -I FORWARD -j LOG --log-prefix "mangle fw [node] "
#$IPTABLES -t nat -I POSTROUTING -j LOG --log-prefix "nat post [node] "
#$IPTABLES -t nat -I INPUT -j LOG --log-prefix "nat inp [node] "
#$IPTABLES -t nat -I OUTPUT -j LOG --log-prefix "nat out [node] "
#$IPTABLES -t nat -I PREROUTING -j LOG --log-prefix "nat pre [node] "
#$IPTABLES -t raw -I PREROUTING -j LOG --log-prefix "raw pre [node] "
#$IPTABLES -t raw -I OUTPUT -j LOG --log-prefix "raw out [node] "
#$IPTABLES -t filter -I FORWARD -j LOG --log-prefix "filt fw [node] "
#$IPTABLES -t filter -I OUTPUT -j LOG --log-prefix "filt out [node] "
#$IPTABLES -t filter -I INPUT -j LOG --log-prefix "filt inp [node] "
