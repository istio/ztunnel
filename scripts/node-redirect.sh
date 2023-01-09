#!/bin/bash

set -ex

# TODO: use a loop instead of ipset maybe
ipset create ztunnel-pods-ips hash:ip
ipset add ztunnel-pods-ips 10.0.1.1
ipset add ztunnel-pods-ips 10.0.2.1
ipset add ztunnel-pods-ips 10.0.3.1


HOST_IP="10.0.0.1"
ZTUNNEL_INTERFACE=veth3
ZTUNNEL_IP="10.0.3.1"

# Setup interfaces
ip link add name istioin type geneve id 1000 remote "${ZTUNNEL_IP}"
ip addr add 192.168.126.1/30 dev istioin
ip link set istioin up

ip link add name istioout type geneve id 1001 remote "${ZTUNNEL_IP}"
ip addr add 192.168.127.1/30 dev istioout
ip link set istioout up



iptables-legacy -t nat -N ztunnel-PREROUTING
iptables-legacy -t nat -I PREROUTING -j ztunnel-PREROUTING
iptables-legacy -t nat -N ztunnel-POSTROUTING
iptables-legacy -t nat -I POSTROUTING -j ztunnel-POSTROUTING
iptables-legacy -t mangle -N ztunnel-PREROUTING
iptables-legacy -t mangle -I PREROUTING -j ztunnel-PREROUTING
iptables-legacy -t mangle -N ztunnel-POSTROUTING
iptables-legacy -t mangle -I POSTROUTING -j ztunnel-POSTROUTING
iptables-legacy -t mangle -N ztunnel-OUTPUT
iptables-legacy -t mangle -I OUTPUT -j ztunnel-OUTPUT
iptables-legacy -t mangle -N ztunnel-INPUT
iptables-legacy -t mangle -I INPUT -j ztunnel-INPUT
iptables-legacy -t mangle -N ztunnel-FORWARD
iptables-legacy -t mangle -I FORWARD -j ztunnel-FORWARD
iptables-legacy -t mangle -A ztunnel-PREROUTING -i istioin -j MARK --set-mark 0x200/0x200
iptables-legacy -t mangle -A ztunnel-PREROUTING -i istioin -j RETURN
iptables-legacy -t mangle -A ztunnel-PREROUTING -i istioout -j MARK --set-mark 0x200/0x200
iptables-legacy -t mangle -A ztunnel-PREROUTING -i istioout -j RETURN
iptables-legacy -t mangle -A ztunnel-FORWARD -m mark --mark 0x220/0x220 -j CONNMARK --save-mark --nfmask 0x220 --ctmask 0x220
iptables-legacy -t mangle -A ztunnel-INPUT -m mark --mark 0x220/0x220 -j CONNMARK --save-mark --nfmask 0x220 --ctmask 0x220
iptables-legacy -t mangle -A ztunnel-FORWARD -m mark --mark 0x210/0x210 -j CONNMARK --save-mark --nfmask 0x210 --ctmask 0x210
iptables-legacy -t mangle -A ztunnel-INPUT -m mark --mark 0x210/0x210 -j CONNMARK --save-mark --nfmask 0x210 --ctmask 0x210
iptables-legacy -t mangle -A ztunnel-OUTPUT --source "${HOST_IP}" -j MARK --set-mark 0x220
iptables-legacy -t nat -A ztunnel-PREROUTING -m mark --mark 0x100/0x100 -j ACCEPT
iptables-legacy -t nat -A ztunnel-POSTROUTING -m mark --mark 0x100/0x100 -j ACCEPT
iptables-legacy -t mangle -A ztunnel-PREROUTING -p tcp -j LOG --log-prefix "zt pre!"
iptables-legacy -t mangle -A ztunnel-PREROUTING -p udp -m udp --dport 6081 -j RETURN
iptables-legacy -t mangle -A ztunnel-PREROUTING -m connmark --mark 0x220/0x220 -j MARK --set-mark 0x200/0x200
iptables-legacy -t mangle -A ztunnel-PREROUTING -p tcp -j LOG --log-prefix "zt mark 1!"
iptables-legacy -t mangle -A ztunnel-PREROUTING -m mark --mark 0x200/0x200 -j RETURN
iptables-legacy -t mangle -A ztunnel-PREROUTING ! -i "${ZTUNNEL_INTERFACE}" -m connmark --mark 0x210/0x210 -j MARK --set-mark 0x040/0x040
iptables-legacy -t mangle -A ztunnel-PREROUTING -p tcp -j LOG --log-prefix "zt mark 2!"
iptables-legacy -t mangle -A ztunnel-PREROUTING -m mark --mark 0x040/0x040 -j RETURN
iptables-legacy -t mangle -A ztunnel-PREROUTING -i "${ZTUNNEL_INTERFACE}" ! --source "${ZTUNNEL_IP}" -j MARK --set-mark 0x210/0x210
iptables-legacy -t mangle -A ztunnel-PREROUTING -p tcp -j LOG --log-prefix "zt mark 3!"
iptables-legacy -t mangle -A ztunnel-PREROUTING -m mark --mark 0x200/0x200 -j RETURN
iptables-legacy -t mangle -A ztunnel-PREROUTING -p tcp -j LOG --log-prefix "zt mark 3.5!"
iptables-legacy -t mangle -A ztunnel-PREROUTING -i "${ZTUNNEL_INTERFACE}" -j MARK --set-mark 0x220/0x220
iptables-legacy -t mangle -A ztunnel-PREROUTING -p udp -j MARK --set-mark 0x220/0x220
iptables-legacy -t mangle -A ztunnel-PREROUTING -p tcp -j LOG --log-prefix "zt mark 4!"
iptables-legacy -t mangle -A ztunnel-PREROUTING -m mark --mark 0x200/0x200 -j RETURN
iptables-legacy -t mangle -A ztunnel-PREROUTING -p tcp -j LOG --log-prefix "check set!"
iptables-legacy -t mangle -A ztunnel-PREROUTING -p tcp -m set --match-set ztunnel-pods-ips src -j MARK --set-mark 0x100/0x100
ip route add table 101 "${ZTUNNEL_IP}" dev "${ZTUNNEL_INTERFACE}" scope link
ip route add table 101 0.0.0.0/0 via 192.168.127.2 dev istioout
ip route add table 102 "${ZTUNNEL_IP}" dev "${ZTUNNEL_INTERFACE}" scope link
ip route add table 102 0.0.0.0/0 via "${ZTUNNEL_IP}" dev "${ZTUNNEL_INTERFACE}" onlink
ip route add table 100 "${ZTUNNEL_IP}" dev "${ZTUNNEL_INTERFACE}" scope link
ip rule add priority 100 fwmark 0x200/0x200 goto 32766
ip rule add priority 101 fwmark 0x100/0x100 lookup 101
ip rule add priority 102 fwmark 0x040/0x040 lookup 102
ip rule add priority 103 table 100

# TODO: remove
#iptables-legacy -t mangle -I PREROUTING -j LOG --log-prefix "mangle pre [$POD_NAME] "
#iptables-legacy -t mangle -I POSTROUTING -j LOG --log-prefix "mangle post [$POD_NAME] "
#iptables-legacy -t mangle -I INPUT -j LOG --log-prefix "mangle inp [$POD_NAME] "
#iptables-legacy -t mangle -I OUTPUT -j LOG --log-prefix "mangle out [$POD_NAME] "
#iptables-legacy -t mangle -I FORWARD -j LOG --log-prefix "mangle fw [$POD_NAME] "
#iptables-legacy -t nat -I POSTROUTING -j LOG --log-prefix "nat post [$POD_NAME] "
#iptables-legacy -t nat -I INPUT -j LOG --log-prefix "nat inp [$POD_NAME] "
#iptables-legacy -t nat -I OUTPUT -j LOG --log-prefix "nat out [$POD_NAME] "
#iptables-legacy -t nat -I PREROUTING -j LOG --log-prefix "nat pre [$POD_NAME] "
#iptables-legacy -t raw -I PREROUTING -j LOG --log-prefix "raw pre [$POD_NAME] "
#iptables-legacy -t raw -I OUTPUT -j LOG --log-prefix "raw out [$POD_NAME] "
#iptables-legacy -t filter -I FORWARD -j LOG --log-prefix "filt fw [$POD_NAME] "
#iptables-legacy -t filter -I OUTPUT -j LOG --log-prefix "filt out [$POD_NAME] "
#iptables-legacy -t filter -I INPUT -j LOG --log-prefix "filt inp [$POD_NAME] "
