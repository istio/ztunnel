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
# Builds local docker images for SPIRE server + agent from the broker-api
# branch of matheuscscp/spire (companion to spiffe/spire#6915) and tags them
# with the names setup.sh expects.
#
# Knobs:
#   SPIRE_FORK / SPIRE_BRANCH  — git source (defaults below)
#   SPIRE_SERVER_IMAGE         — final tag for spire-server image
#   SPIRE_AGENT_IMAGE          — final tag for spire-agent image
#   SPIRE_CACHE_DIR            — where to clone the SPIRE source
#   REBUILD=1                  — force a fresh `git fetch` + image rebuild

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HACK_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

: "${SPIRE_FORK:=https://github.com/matheuscscp/spire.git}"
: "${SPIRE_BRANCH:=broker-api}"
: "${SPIRE_SERVER_IMAGE:=ghcr.io/matheuscscp/spire-server:broker-api}"
: "${SPIRE_AGENT_IMAGE:=ghcr.io/matheuscscp/spire-agent:broker-api}"
: "${SPIRE_CACHE_DIR:=${HACK_DIR}/.cache/spire}"
: "${REBUILD:=0}"

log() {
  printf '\033[1;34m[build-spire]\033[0m %s\n' "$*" >&2
}

require() {
  for cmd in "$@"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      printf 'error: required command not found: %s\n' "${cmd}" >&2
      exit 1
    fi
  done
}

clone_or_update() {
  if [[ -d "${SPIRE_CACHE_DIR}/.git" ]]; then
    log "updating existing SPIRE checkout in ${SPIRE_CACHE_DIR}"
    git -C "${SPIRE_CACHE_DIR}" fetch --depth=1 origin "${SPIRE_BRANCH}"
    git -C "${SPIRE_CACHE_DIR}" reset --hard "origin/${SPIRE_BRANCH}"
  else
    log "cloning ${SPIRE_FORK} (branch ${SPIRE_BRANCH}) into ${SPIRE_CACHE_DIR}"
    mkdir -p "$(dirname "${SPIRE_CACHE_DIR}")"
    git clone --depth=1 --branch "${SPIRE_BRANCH}" "${SPIRE_FORK}" "${SPIRE_CACHE_DIR}"
  fi
}

# image_exists <tag>
image_exists() {
  docker image inspect "$1" >/dev/null 2>&1
}

build_target() {
  local target="$1" tag="$2"
  if [[ "${REBUILD}" != "1" ]] && image_exists "${tag}"; then
    log "image ${tag} already present; skipping build (REBUILD=1 to force)"
    return
  fi
  local goversion=""
  if [[ -f "${SPIRE_CACHE_DIR}/.go-version" ]]; then
    goversion=$(tr -d '[:space:]' < "${SPIRE_CACHE_DIR}/.go-version")
  fi
  if [[ -z "${goversion}" ]]; then
    printf 'error: cannot determine SPIRE go version from %s/.go-version\n' "${SPIRE_CACHE_DIR}" >&2
    exit 1
  fi
  log "building --target ${target} → ${tag} (goversion=${goversion})"
  DOCKER_BUILDKIT=1 docker build \
    --target "${target}" \
    --build-arg "goversion=${goversion}" \
    --tag "${tag}" \
    "${SPIRE_CACHE_DIR}"
}

main() {
  require git docker
  clone_or_update
  build_target spire-server "${SPIRE_SERVER_IMAGE}"
  build_target spire-agent  "${SPIRE_AGENT_IMAGE}"
  log "done."
  log "next: ./hack/spire-test/scripts/setup.sh"
}

main "$@"
