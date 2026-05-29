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
# End-to-end provisioning for the ztunnel SPIFFE Broker testbed.
#
# Idempotent: re-running picks up where it left off rather than failing
# loudly. See ../README.md for the full layout and prerequisites.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HACK_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
CACHE_DIR="${HACK_DIR}/.cache"

: "${KIND_CLUSTER_NAME:=ztunnel-spiffe-broker}"
: "${TRUST_DOMAIN:=cluster.local}"
: "${SPIRE_SERVER_IMAGE:=ghcr.io/matheuscscp/spire-server:broker-api}"
: "${SPIRE_AGENT_IMAGE:=ghcr.io/matheuscscp/spire-agent:broker-api}"
: "${ZTUNNEL_IMAGE:=localhost/ztunnel:spiffe-broker-dev}"
: "${ISTIO_VERSION:=1.24.0}"

log() {
  printf '\033[1;34m[setup]\033[0m %s\n' "$*" >&2
}

require() {
  for cmd in "$@"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      printf 'error: required command not found: %s\n' "${cmd}" >&2
      exit 1
    fi
  done
}

# Download istioctl into ${CACHE_DIR}/istio-${ISTIO_VERSION} and prepend it
# to PATH. Skipped if a system istioctl is already on PATH.
ensure_istioctl() {
  if command -v istioctl >/dev/null 2>&1; then
    return
  fi
  local arch os istio_dir
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$(uname -m)" in
    x86_64)  arch=amd64  ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l)  arch=armv7  ;;
    *) printf 'error: unsupported arch for istioctl auto-install: %s\n' "$(uname -m)" >&2; exit 1 ;;
  esac
  istio_dir="${CACHE_DIR}/istio-${ISTIO_VERSION}"
  if [[ ! -x "${istio_dir}/bin/istioctl" ]]; then
    log "istioctl not found on PATH; downloading ${ISTIO_VERSION} (${os}-${arch}) into ${istio_dir}"
    mkdir -p "${CACHE_DIR}"
    local url="https://github.com/istio/istio/releases/download/${ISTIO_VERSION}/istio-${ISTIO_VERSION}-${os}-${arch}.tar.gz"
    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "${tmp}"' RETURN
    curl -fsSL "${url}" -o "${tmp}/istio.tar.gz"
    tar -xzf "${tmp}/istio.tar.gz" -C "${tmp}"
    rm -rf "${istio_dir}"
    mv "${tmp}/istio-${ISTIO_VERSION}" "${istio_dir}"
  fi
  export PATH="${istio_dir}/bin:${PATH}"
  log "using istioctl: $(command -v istioctl) ($(istioctl version --remote=false 2>/dev/null | head -n1))"
}

split_image() {
  # Splits "registry/repo:tag" into REPO and TAG. Repo includes the registry.
  local image="$1"
  IMAGE_REPO="${image%:*}"
  if [[ "${image}" == "${IMAGE_REPO}" ]]; then
    IMAGE_TAG="latest"
  else
    IMAGE_TAG="${image##*:}"
  fi
}

ensure_kind_cluster() {
  if kind get clusters | grep -qx "${KIND_CLUSTER_NAME}"; then
    log "kind cluster ${KIND_CLUSTER_NAME} already exists, skipping create"
    return
  fi
  log "creating kind cluster ${KIND_CLUSTER_NAME}"
  kind create cluster --config "${HACK_DIR}/kind.yaml"
}

# True when running inside a container (devcontainer, docker-in-docker, etc.).
in_container() {
  [[ -f /.dockerenv ]] || grep -qE 'docker|containerd|kubepods' /proc/1/cgroup 2>/dev/null
}

# When kind is invoked from inside a container, the kubeconfig it writes
# points at 127.0.0.1:<random_port> on the *host* loopback, which is not
# reachable from our container. Patch the kubeconfig to use the kind
# control-plane's docker-network endpoint instead, and join the kind
# network ourselves so DNS-by-container-name works.
fix_kubeconfig_for_in_container() {
  in_container || return 0
  local control_plane="${KIND_CLUSTER_NAME}-control-plane"
  if ! docker inspect "${control_plane}" >/dev/null 2>&1; then
    log "warn: ${control_plane} not found via docker; skipping kubeconfig rewrite"
    return 0
  fi

  local self_id
  self_id=$(awk -F/ 'BEGIN{cid=""} /\/docker\/containers\// {n=split($0,a,"/"); for(i=1;i<=n;i++) if(a[i]=="containers"){cid=a[i+1]; exit}} END{print cid}' /proc/self/mountinfo)
  if [[ -z "${self_id}" ]]; then
    self_id="$(hostname)"
  fi

  if ! docker network inspect kind --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null \
      | tr ' ' '\n' | grep -qx "$(docker inspect -f '{{.Name}}' "${self_id}" 2>/dev/null | sed 's|^/||')"; then
    log "attaching this container to the 'kind' docker network"
    docker network connect kind "${self_id}" 2>/dev/null \
      || log "warn: failed to connect to kind network (already attached or permission denied?)"
  fi

  local server="https://${control_plane}:6443"
  log "rewriting kubeconfig server URL to ${server} (in-container fixup)"
  # Drop the CA paired with the old localhost endpoint and skip TLS verification.
  # This is a local dev cluster — acceptable.
  kubectl config set-cluster "kind-${KIND_CLUSTER_NAME}" --server="${server}" >/dev/null
  kubectl config unset "clusters.kind-${KIND_CLUSTER_NAME}.certificate-authority-data" >/dev/null 2>&1 || true
  kubectl config set-cluster "kind-${KIND_CLUSTER_NAME}" --insecure-skip-tls-verify=true >/dev/null

  # Sanity check: must be able to talk to the API server before we proceed.
  if ! kubectl --request-timeout=10s get --raw=/readyz >/dev/null 2>&1; then
    printf 'error: cannot reach kind API server at %s after in-container fixup\n' "${server}" >&2
    printf '  hints:\n' >&2
    printf '    - is the devcontainer on the same docker daemon as the kind nodes?\n' >&2
    printf '    - try: docker network connect kind <this-container>\n' >&2
    exit 1
  fi
  log "kubeconfig fixup OK; API server reachable"
}

load_image() {
  local image="$1"
  log "loading image into kind: ${image}"
  kind load docker-image --name "${KIND_CLUSTER_NAME}" "${image}"
}

install_spire() {
  log "installing SPIRE (umbrella chart + CRDs)"
  helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ >/dev/null 2>&1 || true
  helm repo update spiffe >/dev/null

  # Pre-create namespaces; the umbrella chart is configured with
  # `global.spire.namespaces.create: false` so it won't try to import
  # them and won't fail if they pre-existed from a prior run.
  for ns in spire-server spire-system; do
    kubectl create namespace "${ns}" --dry-run=client -o yaml | kubectl apply -f -
  done

  # CRDs must be installed first so the controller-manager + ClusterSPIFFEID
  # objects can be applied.
  helm upgrade --install spire-crds spiffe/spire-crds \
    --namespace spire-server \
    --wait --timeout=2m

  split_image "${SPIRE_SERVER_IMAGE}"
  local server_repo="${IMAGE_REPO}" server_tag="${IMAGE_TAG}"
  split_image "${SPIRE_AGENT_IMAGE}"
  local agent_repo="${IMAGE_REPO}" agent_tag="${IMAGE_TAG}"

  helm upgrade --install spire spiffe/spire \
    --namespace spire-server \
    --values "${HACK_DIR}/spire/spire-values.yaml" \
    --set "spire-server.image.registry=" \
    --set "spire-server.image.repository=${server_repo}" \
    --set "spire-server.image.tag=${server_tag}" \
    --set "spire-agent.image.registry=" \
    --set "spire-agent.image.repository=${agent_repo}" \
    --set "spire-agent.image.tag=${agent_tag}" \
    --wait --timeout=5m \
    || {
      printf 'error: helm install spire timed out or failed.\n' >&2
      printf '  pod status:\n' >&2
      kubectl -n spire-server get pods 2>&1 | sed 's/^/    /' >&2
      kubectl -n spire-system get pods 2>&1 | sed 's/^/    /' >&2
      printf '  if you see ImagePullBackOff, build the broker-api images locally and\n' >&2
      printf '  load them via:\n' >&2
      printf '    kind load docker-image %s --name %s\n' "${SPIRE_SERVER_IMAGE}" "${KIND_CLUSTER_NAME}" >&2
      printf '    kind load docker-image %s --name %s\n' "${SPIRE_AGENT_IMAGE}" "${KIND_CLUSTER_NAME}" >&2
      exit 1
    }

  log "applying SPIFFE registration entries"
  kubectl apply -f "${HACK_DIR}/spire/clusterspiffeids.yaml"
}

# enable_broker_endpoint enables the experimental SPIFFE Broker API on
# the agent. The upstream helm-charts-hardened chart has no escape hatch
# for `experimental.broker`, AND its rendered ConfigMap is JSON which
# trips the HCLv1 parser's well-known single-element-list-of-objects bug
# (`brokers[1]: not an object type for struct (*ast.ListType)`). So we
# rewrite the ConfigMap from scratch as native HCL.
#
# We also add a SECOND hostPath volume for the broker socket because
# SPIRE refuses to listen on a broker socket that lives in the same
# directory as the Workload API socket.
#
# After this runs the agent listens on TWO UDSes:
#
#   /run/spire/agent-sockets/api.sock      (Workload API — used by ztunnel
#                                           to bootstrap its own SVID, no
#                                           mTLS)
#   /run/spire/broker-sockets/broker.sock  (SPIFFE Broker API — mTLS-gated,
#                                           used by ztunnel to mint
#                                           per-pod SVIDs)
enable_broker_endpoint() {
  log "enabling SPIFFE Broker endpoint (HCL rewrite + extra hostPath volume)"

  local broker_id="spiffe://${TRUST_DOMAIN:-cluster.local}/ns/istio-system/sa/ztunnel"
  # In-container path inside the agent. The matching hostPath on the
  # node is /run/spire/broker-sockets, mounted into ztunnel below.
  local broker_socket_in_container="/tmp/spire-agent-broker/broker.sock"

  # 1) Patch the DaemonSet to add the broker hostPath volume + the
  #    chown init container. Idempotent: kubectl patch with strategic
  #    merge is a no-op if the volume already exists.
  local ds_patch
  ds_patch=$(cat <<'EOF'
spec:
  template:
    spec:
      initContainers:
      - name: broker-dir-chown
        image: cgr.dev/chainguard/bash:latest@sha256:ef209fd7d231ead12bf24287db24991bdd979669f4df2e037698f94545816d3e
        command: ["bash", "-c"]
        args:
        - |
          mkdir -p /tmp/spire-agent-broker
          chown -R "1000:1000" /tmp/spire-agent-broker
          chmod 0755 /tmp/spire-agent-broker
        securityContext:
          runAsUser: 0
          runAsGroup: 0
        volumeMounts:
        - name: spire-agent-broker-dir
          mountPath: /tmp/spire-agent-broker
      containers:
      - name: spire-agent
        volumeMounts:
        - name: spire-agent-broker-dir
          mountPath: /tmp/spire-agent-broker
      volumes:
      - name: spire-agent-broker-dir
        hostPath:
          path: /run/spire/broker-sockets
          type: DirectoryOrCreate
EOF
  )
  echo "${ds_patch}" | kubectl -n spire-system patch ds spire-agent --patch-file /dev/stdin

  # 2) Re-emit agent.conf as native HCL. The values mirror the chart's
  #    defaults; if you change spire-values.yaml in a way that affects
  #    these, update this block too.
  local agent_conf
  agent_conf=$(cat <<EOF
agent {
  data_dir = "/var/lib/spire"
  log_format = "text"
  log_level = "info"
  rebootstrap_delay = "10m"
  rebootstrap_mode = "always"
  server_address = "spire-server.spire-server"
  server_port = "443"
  socket_path = "/tmp/spire-agent/public/api.sock"
  trust_bundle_format = "spiffe"
  trust_bundle_path = "/run/spire/bundle/bundle.spiffe"
  trust_domain = "${TRUST_DOMAIN:-cluster.local}"

  experimental {
    broker {
      socket_path = "${broker_socket_in_container}"
      brokers = [
        {
          id = "${broker_id}"
          allowed_reference_types = ["*"]
        },
      ]
    }
  }
}

health_checks {
  bind_address = "0.0.0.0"
  bind_port = "9982"
  listener_enabled = true
  live_path = "/live"
  ready_path = "/ready"
}

plugins {
  KeyManager "memory" {
    plugin_data {}
  }

  NodeAttestor "k8s_psat" {
    plugin_data {
      cluster = "${KIND_CLUSTER_NAME}"
    }
  }

  WorkloadAttestor "k8s" {
    plugin_data {
      disable_container_selectors = false
      skip_kubelet_verification = true
      use_new_container_locator = true
      verbose_container_locator_logs = false
    }
  }

  WorkloadAttestor "unix" {
    plugin_data {}
  }
}

telemetry {
  Prometheus {
    host = "0.0.0.0"
    port = 9988
  }
}
EOF
  )

  kubectl -n spire-system create configmap spire-agent \
    --from-literal=agent.conf="${agent_conf}" \
    --dry-run=client -o yaml \
    | kubectl -n spire-system apply -f -

  # 3) Bounce the agents. Use `delete pod` rather than `rollout restart`
  #    because the DS patch already triggered a rollout; this avoids a
  #    second redundant cycle.
  kubectl -n spire-system delete pod -l app.kubernetes.io/name=agent --wait=false >/dev/null
  kubectl -n spire-system rollout status ds/spire-agent --timeout=2m

  # 4) Confirm the broker endpoint actually came up. Fail loudly so
  #    downstream failures don't look mysterious.
  local deadline=$(( $(date +%s) + 30 ))
  while (( $(date +%s) < deadline )); do
    if kubectl -n spire-system logs ds/spire-agent --tail=200 2>/dev/null \
        | grep -q "Starting SPIFFE Broker Endpoint"; then
      log "broker endpoint is live at /run/spire/broker-sockets/broker.sock"
      return
    fi
    sleep 2
  done
  printf 'error: SPIRE agent did not log "Starting SPIFFE Broker Endpoint" within 30s.\n' >&2
  kubectl -n spire-system logs ds/spire-agent --tail=80 >&2 || true
  exit 1
}

install_istio_ambient() {
  if kubectl -n istio-system get ds ztunnel >/dev/null 2>&1; then
    log "istio ambient already installed, skipping"
    return
  fi
  log "installing istio ambient (version ${ISTIO_VERSION})"
  split_image "${ZTUNNEL_IMAGE}"
  istioctl install -y \
    --set "profile=ambient" \
    --set "values.ztunnel.image=${ZTUNNEL_IMAGE}" \
    --set "values.ztunnel.imagePullPolicy=IfNotPresent" \
    --set "tag=${ISTIO_VERSION}"
}

patch_ztunnel_for_broker() {
  log "patching ztunnel daemonset for the SPIFFE Broker provider"
  kubectl -n istio-system patch ds ztunnel \
    --patch-file "${HACK_DIR}/istio/ztunnel-patch.yaml"
  # Force a rollout so the new env vars and volume take effect on already-running pods.
  kubectl -n istio-system rollout restart ds/ztunnel
  kubectl -n istio-system rollout status ds/ztunnel --timeout=2m
}

deploy_test_workloads() {
  log "deploying test workloads"
  kubectl apply -f "${HACK_DIR}/workloads/test-pods.yaml"
  kubectl -n ztunnel-broker-test wait pod -l app=ztunnel-broker-test --for=condition=Ready --timeout=2m
}

main() {
  require kind kubectl helm docker jq curl tar
  ensure_istioctl
  require istioctl
  ensure_kind_cluster
  fix_kubeconfig_for_in_container
  # Loading is best-effort — if the image isn't local (e.g. the user pushed
  # to a registry the kind nodes can pull from), the helm/istioctl steps
  # will surface the failure themselves.
  load_image "${SPIRE_SERVER_IMAGE}" 2>/dev/null || log "warn: ${SPIRE_SERVER_IMAGE} not local; expecting pull"
  load_image "${SPIRE_AGENT_IMAGE}" 2>/dev/null || log "warn: ${SPIRE_AGENT_IMAGE} not local; expecting pull"
  load_image "${ZTUNNEL_IMAGE}" 2>/dev/null || log "warn: ${ZTUNNEL_IMAGE} not local; expecting pull"
  install_spire
  enable_broker_endpoint
  install_istio_ambient
  patch_ztunnel_for_broker
  deploy_test_workloads
  log "setup complete. Run scripts/verify.sh to confirm per-pod SVIDs differ."
}

main "$@"
