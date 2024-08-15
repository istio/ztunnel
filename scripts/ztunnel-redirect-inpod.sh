#!/bin/bash
# shellcheck disable=SC2086
# This script sets up redirection in the ztunnel network namespace for namespaced tests (tests/README.md)

set -ex

# CONNMARK is needed to make original src work. we set conn mark on prerouting. this is will not effect connections
# from ztunnel to outside the pod, which will go on OUTPUT chain.
# as we are in the pod ns, we can use whatever iptables is default.
iptables-restore --wait 10 <<EOF
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ISTIO_OUTPUT - [0:0]
:ISTIO_PRERT - [0:0]
-A PREROUTING -j ISTIO_PRERT
-A OUTPUT -j ISTIO_OUTPUT
-A ISTIO_OUTPUT -m connmark --mark 0x111/0xfff -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
-A ISTIO_PRERT -m mark --mark 0x539/0xfff -j CONNMARK --set-xmark 0x111/0xfff
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ISTIO_OUTPUT - [0:0]
:ISTIO_PRERT - [0:0]
-A OUTPUT -j ISTIO_OUTPUT
-A PREROUTING -j ISTIO_PRERT
-A ISTIO_OUTPUT -d 169.254.7.127/32 -p tcp -m tcp -j ACCEPT
-A ISTIO_OUTPUT -p tcp -m mark --mark 0x111/0xfff -j ACCEPT
-A ISTIO_OUTPUT ! -d 127.0.0.1/32 -o lo -j ACCEPT
-A ISTIO_OUTPUT ! -d 127.0.0.1/32 -p tcp -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports 15001
-A ISTIO_PRERT -s 169.254.7.127/32 -p tcp -m tcp -j ACCEPT
-A ISTIO_PRERT ! -d 127.0.0.1/32 -p tcp ! --dport 15008 -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports 15006
COMMIT
EOF

ip route add local 0.0.0.0/0 dev lo table 100 || :

# tproxy and original src
ip rule add fwmark 0x111/0xfff pref 32764 lookup 100 || :
