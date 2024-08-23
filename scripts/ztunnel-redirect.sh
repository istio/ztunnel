#!/bin/bash
# shellcheck disable=SC2086
# This script sets up redirection in the ztunnel network namespace for namespaced tests for dedicated mode (tests/README.md)
# See ztunnel-redirect-inpod.sh for inpod mode.
set -ex

# Mark ztunnel will set
MARK=0x539/0xfff
# Port used for outbound traffic
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
