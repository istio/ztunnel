#!/usr/bin/env bash

ZTUNNEL_REDIRECT_USER="${ZTUNNEL_REDIRECT_USER:-iptables1}"

ztunnel-local-bootstrap () {
  pod="$(kubectl get pods -lapp=ztunnel -n istio-system -ojson | jq '.items[0]')"
  sa="$(<<<"${pod}"  jq -r '.spec.serviceAccountName')"
  uid="$(<<<"${pod}"  jq -r '.metadata.uid')"
  name="$(<<<"${pod}"  jq -r '.metadata.name')"
  mkdir -p ./var/run/secrets/tokens ./var/run/secrets/istio
  kubectl create token "$sa" -n istio-system --audience=istio-ca --duration=240h --bound-object-kind Pod --bound-object-name="${name}" --bound-object-uid="${uid}" > ./var/run/secrets/tokens/istio-token
  kubectl -n istio-system get secret istio-ca-secret -ojsonpath='{.data.ca-cert\.pem}' | base64 -d > ./var/run/secrets/istio/root-cert.pem
}

redirect-to () {
  redirect-to-clean
  uid=$(id -u "${ZTUNNEL_REDIRECT_USER}")
  sudo iptables -t nat -I OUTPUT 1 -p tcp -m owner --uid-owner "$uid" -j REDIRECT --to-ports "${1:?port}" -m comment --comment "local-redirect-to"
  sudo ip6tables -t nat -I OUTPUT 1 -p tcp -m owner --uid-owner "$uid" -j REDIRECT --to-ports "${1:?port}" -m comment --comment "local-redirect-to"
  echo "Redirecting calls from UID $uid to ${1}"
  echo "Try: sudo -u ${ZTUNNEL_REDIRECT_USER} curl"
}

redirect-to-clean () {
  sudo iptables-save | grep '^\-A' | grep "local-redirect-to" | cut -c 4- | xargs -r -L 1 echo sudo iptables -t nat -D
  sudo iptables-save | grep '^\-A' | grep "local-redirect-to" | cut -c 4- | xargs -r -L 1 sudo iptables -t nat -D
  sudo ip6tables-save | grep '^\-A' | grep "local-redirect-to" | cut -c 4- | xargs -r -L 1 echo sudo ip6tables -t nat -D
  sudo ip6tables-save | grep '^\-A' | grep "local-redirect-to" | cut -c 4- | xargs -r -L 1 sudo ip6tables -t nat -D
}

redirect-user-setup() {
  # shellcheck disable=SC2046,SC2139,SC2006
  alias redirect-run="sudo -u \"${ZTUNNEL_REDIRECT_USER}\""
  sudo useradd "${ZTUNNEL_REDIRECT_USER}"
}

