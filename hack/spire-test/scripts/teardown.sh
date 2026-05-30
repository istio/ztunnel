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
# Deletes the kind cluster. Also force-removes any stale kind node
# containers that kind's state tracking may have lost (e.g. when the
# cluster was created from inside a container with its own kind state dir).

set -euo pipefail

: "${KIND_CLUSTER_NAME:=ztunnel-spiffe-broker}"

log() {
  printf '\033[1;34m[teardown]\033[0m %s\n' "$*" >&2
}

if kind get clusters 2>/dev/null | grep -qx "${KIND_CLUSTER_NAME}"; then
  log "deleting kind cluster ${KIND_CLUSTER_NAME}"
  kind delete cluster --name "${KIND_CLUSTER_NAME}"
else
  log "no kind cluster named ${KIND_CLUSTER_NAME} in kind state; checking for stragglers"
fi

# Force-remove any node containers kind didn't clean up.
stragglers=$(docker ps -aq --filter "name=^${KIND_CLUSTER_NAME}-(control-plane|worker)" 2>/dev/null || true)
if [[ -n "${stragglers}" ]]; then
  log "removing stray kind node containers"
  # shellcheck disable=SC2086
  docker rm -f ${stragglers} >/dev/null
fi
