# Local Testing

Along with running in a Kubernetes, ztunnel can be run locally for development purposes.

This doc covers ztunnel specifically, for general Istio local development see
[Local Istio Development](https://github.com/howardjohn/local-istio-development).

## Local overrides

There are a variety of config options that can be used to replace components with mocked ones:

* `FAKE_CA="true"` - this will use self-signed fake certificates, eliminating a dependency on a CA
* `XDS_ADDRESS=""` - disables XDS client completely
* `LOCAL_XDS_PATH=./examples/localhost.yaml` - read XDS config from a file.
  This example adds a workload for `127.0.0.1`, allowing us to send requests to/from localhost.
* `NODE_NAME=local` - configures which node the ztunnel is running as.
  This impacts the networking path of requests. In the `localhost.yaml` example, `NODE_NAME=local` would make localhost use the in-memory fast path; without it HBONE would be used.

Together, `FAKE_CA="true" XDS_ADDRESS="" LOCAL_XDS_PATH=./examples/localhost.yaml cargo run` (with `--no-default-features` if you have FIPS disabled) can be used to run entirely locally, without a Kubernetes or Istiod dependency.

## Local in-pod testing

Create a netns for your "pod" (in this case, just a network namespace):

```shell
ip netns add pod1
ip -n pod1 link set lo up

# veth device
ip link add pod1 type veth peer name pod1-eth0
# move one end to the pod
ip link set pod1-eth0 netns pod1
# configure the veth devices
ip link set pod1 up
ip -n pod1 link set pod1-eth0 up
ip addr add dev pod1 10.0.0.1/24
ip -n pod1 addr add dev pod1-eth0 10.0.0.2/24
```

run fake server with:

```shell
INPOD_UDS=/tmp/ztunnel cargo run --example inpodserver -- pod1
```

run ztunnel with:

```shell
RUST_LOG=debug INPOD_ENABLED=true INPOD_UDS=/tmp/ztunnel FAKE_CA="true" XDS_ADDRESS="" LOCAL_XDS_PATH=./examples/localhost.yaml cargo run
```

see the ztunnel sockets:

```shell
ip netns exec pod1 ss -ntlp | grep ztunnel
```

```shell
# redirect traffic to ztunnel
ip netns exec pod1 ./scripts/ztunnel-redirect-inpod.sh
```

To get traffic to work you may need to adjust the IPs in localhost.yaml and start processes in the pod netns.

## In-pod mode with istiod on kind - local testing

Run ztunnel on from your terminal. With istiod and workloads running in KinD. This works on Linux only.
This approach will have traffic running through your local ztunnel - running outside of k8s as a regular, non-containerized userspace process. This can make certain kinds of debugging and local development flows faster/simpler.

In this setup we will replace ztunnel in one of the nodes. In this example we replace the node named `ambient-worker`.

Created cluster with and add an extraMount to the worker node. This will allow the ztunnel on your laptop
to connect to the cni-socket of the worker node.

```shell
kind create cluster --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ambient
nodes:
- role: control-plane
- role: worker
  extraMounts:
  - hostPath: /tmp/worker1-ztunnel/
    containerPath: /var/run/ztunnel/
- role: worker
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:5000"]
    endpoint = ["http://${KIND_REGISTRY_NAME}:5000"]
EOF
```

Now you can install istio ambient and your workloads.
Note that once installed you should see the cni socket appear in `/tmp/worker1-ztunnel/ztunnel.sock`.

Remove ztunnel from the desired node:

```shell
kubectl label node ambient-worker ztunnel=no
kubectl patch daemonset -n istio-system ztunnel --type=merge -p='{"spec":{"template":{"spec":{"affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"ztunnel","operator":"NotIn","values":["no"]}]}]}}}}}}}'
```

Get certs and the ztunnel service account token. We do this using a pod with the same service account to the same node.

```shell
kubectl get cm -n istio-system istio-ca-root-cert -o jsonpath='{.data.root-cert\.pem}' > /tmp/istio-root.pem
kubectl create -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: fake-tunnel-worker1
  namespace: istio-system
spec:
  nodeName: ambient-worker
  terminationGracePeriodSeconds: 1
  serviceAccountName: ztunnel
  containers:
  - name: cat-token
    image: ubuntu:22.04
    command:
    - bash
    - -c
    args:
    - "sleep 10000"
    ports:
    - containerPort: 80
    volumeMounts:
    - mountPath: /var/run/secrets/tokens
      name: istio-token
  volumes:
  - name: istio-token
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          audience: istio-ca
          expirationSeconds: 43200
          path: istio-token
EOF
```

Now, port forward istiod, copy over the token and run ztunnel (under sudo):

```shell
kubectl port-forward -n istio-system svc/istiod 15012:15012 &
mkdir -p ./var/run/secrets/tokens/
kubectl exec -n istio-system fake-tunnel-worker1 -- cat /var/run/secrets/tokens/istio-token > ./var/run/secrets/tokens/istio-token
xargs env <<EOF
INPOD_UDS=/tmp/worker1-ztunnel/ztunnel.sock
CLUSTER_ID=Kubernetes
RUST_LOG=debug
INPOD_ENABLED="true"
ISTIO_META_DNS_CAPTURE="true"
ISTIO_META_DNS_PROXY_ADDR="127.0.0.1:15053"
SERVICE_ACCOUNT=ztunnel
NODE_NAME=ambient-worker
POD_NAMESPACE=istio-system
POD_NAME=ztunnel-worker1
CA_ROOT_CA=/tmp/istio-root.pem
XDS_ROOT_CA=/tmp/istio-root.pem
CARGO_TARGET_$(rustc -vV | sed -n 's|host: ||p' | tr '[:lower:]' '[:upper:]'| tr - _)_RUNNER="sudo -E"
cargo run proxy ztunnel
EOF
```

## Real Istiod

`ztunnel` can also be run locally but connected to a real Istiod instance.

### Authentication

Ztunnel authentication for CA requires a pod-bound Service Account token.
This makes local running a bit more complex than normally.

First, you must have at least 1 ztunnel pod running.
See the [instructions](https://github.com/istio/istio/blob/experimental-ambient/CONTRIBUTING.md)
for deploying a ztunnel.

Then the below command will fetch a token:

```shell
source ./scripts/local.sh
ztunnel-local-bootstrap
```

### XDS and CA

While XDS is not a hard requirement due to the static config file, the CA is.
When running locally, ztunnel will automatically connect to an Istiod running on localhost.

Istiod can be run locally as simply as `go run ./pilot/cmd/pilot-discovery discovery`.

## Sending requests

Ztunnel expects requests to be redirected with iptables. The following functions can help do this:

* `redirect-user-setup` sets up a new user specified by `$ZTUNNEL_REDIRECT_USER`
* `redirect-to <port>` redirects all traffic from `$ZTUNNEL_REDIRECT_USER` to the given port.
* `redirect-to-clean` removes any iptables rules setup by `redirect-to`
* `redirect-run <cmd>` runs the command as `$ZTUNNEL_REDIRECT_USER`.

To setup redirection logic for all requests from the `iptables1` user to 15001:

```shell
source ./scripts/local.sh
export ZTUNNEL_REDIRECT_USER="iptables1"
redirect-user-setup
redirect-to 15001
```

Finally, requests can be sent through the ztunnel:

```shell
redirect-run curl localhost:8080
```

In the example request above, the request will go from `curl -> ztunnel (15001) --HBONE--> ztunnel (15008) -> localhost:8080`.

If you wanted the same request to not go over HBONE, you could connect to/from another unknown IP like `127.0.0.2`.

## Configuration

Ztunnel behaves differently for requests to workloads on the same node vs other nodes.
This can be utilized to test different things. For example:

* `LOCAL_XDS_PATH=./examples/localhost.yaml cargo run` - request to localhost will use HBONE
* `LOCAL_XDS_PATH=./examples/localhost.yaml NODE_NAME=local cargo run` - request to localhost will use in-memory fast path
