#!/usr/bin/env bash
# Copyright Istio Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Asserts that ztunnel in CA_PROVIDER=spiffe_broker mode minted a *distinct*
# SVID per test pod. The two probe pods share one ServiceAccount, so any
# Istio-CA-style identity-keyed cache would collapse them into one SVID;
# only per-pod attestation produces two different serials.
#
# Strategy:
#   1. Force ztunnel to mint a cert for each probe pod by exercising an
#      outbound connection from inside the pod. ztunnel only fetches an
#      SVID lazily (on first connection through it).
#   2. Identify the ztunnel pod on each worker node that hosts a probe.
#   3. Curl that ztunnel's admin /config_dump and extract the leaf
#      serial number for each probe pod's SPIFFE identity.
#   4. Fail if any two serials are equal.

set -euo pipefail

NS="ztunnel-broker-test"
ZTUNNEL_NS="istio-system"

log() {
  printf '\033[1;34m[verify]\033[0m %s\n' "$*" >&2
}

die() {
  printf '\033[1;31m[verify]\033[0m %s\n' "$*" >&2
  exit 1
}

PROBES=(probe-a probe-b)
SPIFFE_ID="spiffe://cluster.local/ns/${NS}/sa/probe"

# Trigger ztunnel to actually fetch each pod's SVID. ztunnel only mints an
# SVID lazily, on the first connection it proxies *for* a given pod, so we
# drive real pod-to-pod traffic (localhost traffic is not proxied, and the
# fortio image is distroless so it has neither `sh` nor `curl` — only the
# `fortio` binary). Each probe curls every other probe so every pod shows up
# as a *source* workload and thus gets its own SVID minted.
warm_pods() {
  local from to ip
  for from in "${PROBES[@]}"; do
    for to in "${PROBES[@]}"; do
      [[ "${from}" == "${to}" ]] && continue
      ip=$(kubectl -n "${NS}" get pod "${to}" -o jsonpath='{.status.podIP}')
      log "warming SVID for ${from} -> ${to} (${ip}:8080)"
      kubectl -n "${NS}" exec "${from}" -- \
        fortio curl -quiet "http://${ip}:8080/echo" >/dev/null 2>&1 || true
    done
  done
  # Give ztunnel a moment to update its cache after the connections.
  sleep 2
}

# Print the distinct set of ztunnel pods that serve the probe pods (one per
# node that hosts a probe).
ztunnel_pods() {
  local probe node
  for probe in "${PROBES[@]}"; do
    node=$(kubectl -n "${NS}" get pod "${probe}" -o jsonpath='{.spec.nodeName}')
    kubectl -n "${ZTUNNEL_NS}" get pod \
      -l app=ztunnel \
      --field-selector "spec.nodeName=${node}" \
      -o jsonpath='{.items[0].metadata.name}{"\n"}'
  done | sort -u
}

# Dump the leaf serial(s) a given ztunnel pod has cached for the probe
# identity. The ztunnel container is distroless (no curl), so we reach its
# admin server (localhost:15000) via `kubectl port-forward`.
serials_from_ztunnel() {
  local ztunnel="$1"
  local pf_pid rc=0
  kubectl -n "${ZTUNNEL_NS}" port-forward "${ztunnel}" 15000:15000 >/dev/null 2>&1 &
  pf_pid=$!
  # Wait for the forwarder to come up.
  local i
  for i in $(seq 1 20); do
    curl -s --max-time 1 http://localhost:15000/config_dump >/dev/null 2>&1 && break
    sleep 0.25
  done
  curl -s --max-time 5 http://localhost:15000/config_dump \
    | jq -r --arg id "${SPIFFE_ID}" \
        '.certificates[]? | select(.identity==$id) | .certChain[0].serialNumber' \
    | grep -vi '^null$' || rc=$?
  kill "${pf_pid}" 2>/dev/null || true
  wait "${pf_pid}" 2>/dev/null || true
  return 0
}

# Collect the distinct set of leaf serials cached across the ztunnel pods that
# serve the probe pods. Prints one serial per line (deduplicated).
collect_serials() {
  local serials zt
  serials=""
  while read -r zt; do
    [[ -z "${zt}" ]] && continue
    log "collecting serials from ztunnel ${zt}"
    serials+=$'\n'"$(serials_from_ztunnel "${zt}")"
  done < <(ztunnel_pods)

  printf '%s\n' "${serials}" | sed '/^$/d' | sort -u
}

main() {
  local want serials count
  want=${#PROBES[@]}

  # SVIDs are minted lazily, AND the broker only returns one once SPIRE has
  # propagated the pod's registration entry (created by the ClusterSPIFFEID
  # controller). For a freshly created pod that can take a few dozen seconds,
  # during which the broker legitimately returns an empty SVID list and ztunnel
  # retries with backoff. Poll until the SVIDs converge rather than sampling a
  # single moment, otherwise we race the propagation window.
  local deadline=$((SECONDS + 90))
  while :; do
    warm_pods
    serials=$(collect_serials)
    count=$(printf '%s\n' "${serials}" | grep -c . || true)
    if [[ "${count}" -ge "${want}" ]]; then
      break
    fi
    if (( SECONDS >= deadline )); then
      break
    fi
    log "have ${count}/${want} distinct SVIDs so far; waiting for broker/SPIRE to converge..."
    sleep 3
  done

  [[ -n "${serials}" ]] || die "ztunnel reported no SVIDs for ${SPIFFE_ID}; broker call probably failed"

  log "distinct leaf serials cached for ${SPIFFE_ID}:"
  printf '  %s\n' "${serials}"

  # The probe pods all share one ServiceAccount, hence one SPIFFE identity.
  # An Istio-CA-style identity-keyed cache would mint a single shared SVID
  # (one serial). Only per-pod attestation produces a distinct serial per
  # pod, so we must see exactly as many serials as there are probe pods.
  if [[ "${count}" -lt "${want}" ]]; then
    die "expected ${want} distinct SVID serials (one per probe pod) but found ${count}; per-pod attestation is NOT working"
  fi

  log "OK: ${count} distinct SVIDs for ${want} probe pods sharing one ServiceAccount; SPIFFE Broker per-pod attestation works."
}

main "$@"
