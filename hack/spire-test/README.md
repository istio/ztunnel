# SPIFFE Broker testbed for ztunnel

A reproducible local environment that exercises ztunnel's `CA_PROVIDER=spiffe_broker`
mode end-to-end against the [SPIFFE Broker API][broker-api] using the SPIRE
reference implementation from PR [spiffe/spire#6915][spire-pr] (`matheuscscp:broker-api`).

The end goal is to assert that **two pods sharing one Kubernetes
ServiceAccount get distinct SVIDs**, which is the whole point of per-pod
attestation through the broker.

## Layout

```
hack/spire-test/
├── README.md                       This file.
├── kind.yaml                       kind cluster with the agent-socket extra mount.
├── spire/
│   ├── spire-values.yaml           Values overrides for the SPIFFE umbrella chart (spiffe/spire).
│   └── clusterspiffeids.yaml       SPIFFE registration entries (ztunnel + test pods).
├── istio/
│   ├── ambient-values.yaml         istioctl/Helm overrides for the ambient profile.
│   └── ztunnel-patch.yaml          Strategic-merge patch that wires the broker env vars
│                                   and mounts the broker socket.
├── workloads/
│   └── test-pods.yaml              Two pods sharing one ServiceAccount.
└── scripts/
    ├── build-spire-images.sh        Clone + build the broker-api SPIRE images.
    ├── build-ztunnel-image.sh       Compile ztunnel and package the docker image.
    ├── setup.sh                     End-to-end provisioning.
    ├── verify.sh                    Asserts the two pods received different SVIDs.
    ├── teardown.sh                  Tears the cluster down.
    └── up.sh                        Convenience wrapper: build → setup → verify.
```

## Prerequisites

- `docker` (with buildx; SPIRE's Dockerfile uses `--target` multi-stage builds)
- `kind` ≥ 0.22
- `kubectl`
- `helm` ≥ 3.14
- `git`, `jq`, `curl`, `tar`
- A Rust toolchain (only needed for `build-ztunnel-image.sh`).

Neither `istioctl` nor the SPIRE source need to be installed manually —
`setup.sh` auto-downloads `istioctl` and `build-spire-images.sh` clones
the SPIRE source into `hack/spire-test/.cache/` (gitignored).

The SPIRE branch under test (`matheuscscp:broker-api`) is not yet
released — you must build the server/agent images yourself and either
push them to a registry reachable by the kind cluster or load them with
`kind load docker-image`. `scripts/build-spire-images.sh` does this in
one shot (clones into `.cache/spire/` and builds with `docker build
--target spire-{server,agent}`). The image tags it produces match the
env var defaults below.

| Variable                  | Default                                       |
|---------------------------|-----------------------------------------------|
| `SPIRE_SERVER_IMAGE`      | `ghcr.io/matheuscscp/spire-server:broker-api` |
| `SPIRE_AGENT_IMAGE`       | `ghcr.io/matheuscscp/spire-agent:broker-api`  |
| `ZTUNNEL_IMAGE`           | `localhost/ztunnel:spiffe-broker-dev`         |
| `KIND_CLUSTER_NAME`       | `ztunnel-spiffe-broker`                       |
| `TRUST_DOMAIN`            | `cluster.local`                               |
| `SPIRE_FORK`              | `https://github.com/matheuscscp/spire.git`    |
| `SPIRE_BRANCH`            | `broker-api`                                  |

## End-to-end run

Fastest path — one command builds everything, brings the cluster up,
and runs verification:

```shell
./hack/spire-test/scripts/up.sh
```

Or step-by-step (each script is independently idempotent):

```shell
# 1. Build the SPIRE broker-api images (clones the branch, builds, tags).
./hack/spire-test/scripts/build-spire-images.sh

# 2. Build the ztunnel image.
./hack/spire-test/scripts/build-ztunnel-image.sh

# 3. Provision kind + SPIRE + istio ambient + ztunnel + test workloads.
./hack/spire-test/scripts/setup.sh

# 4. Assert per-pod SVIDs differ.
./hack/spire-test/scripts/verify.sh

# 5. Tear down when done.
./hack/spire-test/scripts/teardown.sh
```

## How the verification works

`verify.sh` exec's into the ztunnel pod for the worker node hosting the
test workloads and hits its admin endpoint (`/config_dump`). With the
broker provider, ztunnel keys SVIDs by `(Identity, WorkloadUid)`
([`CacheKey::Workload`][cache-key]), so each test pod has its own entry
even though they share a ServiceAccount. The script extracts the leaf
serial number for each pod and fails if any two are equal.

[broker-api]: https://github.com/arndt-s/spiffe/blob/main/standards/brokerapi.proto
[spire-pr]: https://github.com/spiffe/spire/pull/6915
[cache-key]: ../../src/identity/manager.rs

## Troubleshooting

- **`broker stream errored; reconnecting after backoff`** in ztunnel logs:
  confirm the SPIRE agent socket path matches `SPIFFE_BROKER_SOCKET`
  and that the agent is healthy (`kubectl logs -n spire-system ds/spire-agent`).
- **`BrokerMissingWorkload` / `BrokerMissingUid`**: the workload's pod
  metadata (namespace/name/uid) wasn't available to ztunnel, so the
  KubernetesObject attestor couldn't build a reference. Confirm the pod
  is managed in inpod mode and that ztunnel received its metadata.
- **All SVIDs share one serial**: verify ztunnel is actually built with the
  broker provider — `kubectl exec ... -- ztunnel --version` should match
  the locally built image, and the ds spec must show
  `CA_PROVIDER=spiffe_broker`.
