#!/usr/bin/env bash

# Init the base set of tables and routes
init() {
  # Anything with the mark 15001 will be sent to loopback
  ip -4 rule add fwmark 15001 lookup 15001
  ip -4 route add local default dev lo table 15001

  iptables -t mangle -N ZT_CAPTURE_EGRESS
  iptables -t mangle -A ZT_CAPTURE_EGRESS -j MARK --set-mark 15001

  # PREROUTING on loopback - anything routed by the route table 15001, based on OUTPUT mark
  # Ignore local source or dst - it's not egress
  iptables -t mangle -N ZT_TPROXY
  iptables -t mangle -A ZT_TPROXY -d 127.0.0.0/8 -j RETURN
  iptables -t mangle -A ZT_TPROXY --match mark --mark 15001 -p tcp  -j TPROXY --tproxy-mark 15001/0xffffffff --on-port 15001
  iptables -t mangle -A PREROUTING -i lo -j ZT_TPROXY


  # Table that determines who gets redirected
  iptables -t mangle -N ZT_EGRESS
  iptables -t mangle -A OUTPUT  -j ZT_EGRESS
}

init6() {
  # Anything with the mark 15001 will be sent to loopback
  ip -6 rule add fwmark 15001 lookup 15001
  ip -6 route add local default dev lo table 15001

  ip6tables -t mangle -N ZT_CAPTURE_EGRESS
  ip6tables -t mangle -A ZT_CAPTURE_EGRESS -j MARK --set-mark 15001

  # PREROUTING on loopback - anything routed by the route table 15001, based on OUTPUT mark
  # Ignore local source or dst - it's not egress
  ip6tables -t mangle -N ZT_TPROXY
  ip6tables -t mangle -A ZT_TPROXY -d ::1/128 -j RETURN
  ip6tables -t mangle -A ZT_TPROXY --match mark --mark 15001 -p tcp  -j TPROXY --tproxy-mark 15001/0xffffffff --on-port 15001
  ip6tables -t mangle -A PREROUTING -i lo -j ZT_TPROXY


  # Table that determines who gets redirected
  ip6tables -t mangle -N ZT_EGRESS
  ip6tables -t mangle -A OUTPUT  -j ZT_EGRESS
}


# Clean the configurable table for outbound capture
clean() {
  iptables -t mangle -F ZT_EGRESS
  ip6tables -t mangle -F ZT_EGRESS
}

# Setup outbound capture
setup() {
  iptables -t mangle -A ZT_EGRESS  -p tcp --dport 15001 -j RETURN
  iptables -t mangle -A ZT_EGRESS  -p tcp --dport 15009 -j RETURN
  iptables -t mangle -A ZT_EGRESS  -p tcp --dport 15008 -j RETURN

  iptables -t mangle -A ZT_EGRESS -m owner --uid-owner 0 -j RETURN

  # For now capture only 10, to avoid breaking internet requests.
  # Will need to be expanded
  iptables -t mangle -A ZT_EGRESS -d 10.0.0.0/8 -j ZT_CAPTURE_EGRESS
  iptables -t mangle -A ZT_EGRESS -d 142.251.46.228/32 -j ZT_CAPTURE_EGRESS
}

setup6() {
  ip6tables -t mangle -A ZT_EGRESS  -p tcp --dport 15001 -j RETURN
  ip6tables -t mangle -A ZT_EGRESS  -p tcp --dport 15009 -j RETURN
  ip6tables -t mangle -A ZT_EGRESS  -p tcp --dport 15008 -j RETURN

  ip6tables -t mangle -A ZT_EGRESS -m owner --uid-owner 0 -j RETURN

  # For now capture only 10, to avoid breaking internet requests.
  # Will need to be expanded
  ip6tables -t mangle -A ZT_EGRESS -d fc::/7 -j ZT_CAPTURE_EGRESS
  ip6tables -t mangle -A ZT_EGRESS -d fe:c0::/10 -j ZT_CAPTURE_EGRESS
}

if [[ "$1" != "" ]]; then
  $1
fi
