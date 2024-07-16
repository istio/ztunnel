#!/bin/bash
# shellcheck disable=SC2086
# This script sets up redirection in the ztunnel network namespace for namespaced tests (tests/README.md)
set -ex

# tproxy mark, it's only used here.
MARK=0x539/0xfff

# Below is from config.sh but used in redirect-worker.sh as well
POD_OUTBOUND=15001

set +e
num_legacy_lines=$( (iptables-legacy-save || true; ip6tables-legacy-save || true) 2>/dev/null | grep -c '^-')
if [ "${num_legacy_lines}" -ge 10 ]; then
  mode=legacy
else
  num_nft_lines=$( (timeout 5 sh -c "iptables-nft-save; ip6tables-nft-save" || true) 2>/dev/null | grep -c '^-')
  if [ "${num_legacy_lines}" -gt "${num_nft_lines}" ]; then
    mode=legacy
  else
    if [ "${num_nft_lines}" -eq "0" ]; then
      mode=none
    else
      mode=nft
    fi
  fi
fi
IPTABLES=iptables-legacy
if [ "${mode}" = "nft" ]; then
  IPTABLES=iptables-nft
fi
if [ "${mode}" = "none" ]; then
  IPTABLES=iptables
fi
set -e

$IPTABLES -w -t mangle -F PREROUTING
$IPTABLES -w -t nat -F OUTPUT
# Redirect outbound traffic that is NOT from ztunnel (identified by mark)
# We do not currently bother redirecting inbound traffic since we don't test it, but a more complete solution would.
# Note: in real world, this would be a UID/GID match like sidecars. Setting mark is enabled only for testing (for now?)
$IPTABLES -w -t nat -A OUTPUT -p tcp ! -o lo -m mark ! --mark $MARK -j REDIRECT --to-ports "${POD_OUTBOUND}"

# With normal linux routing we need to disable the rp_filter
# as we get packets from a tunnel that doesn't have default routes.
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/eth0/rp_filter
#
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
