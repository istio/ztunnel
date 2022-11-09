# Local Testing

Along with running in a Kubernetes, ztunnel can be run locally for development purposes.

This doc covers ztunnel specifically, for general Istio local development see [Local Istio Development](https://github.com/howardjohn/local-istio-development).

## Workloads

A local file can configure workloads: `LOCAL_XDS_PATH=./examples/localhost.yaml cargo run`.

This example adds a workload for `127.0.0.1`, allowing us to send requests to/from localhost.

## Authentication

Ztunnel authentication for CA requires a pod-bound Service Account token. This makes local running a
bit more complex than normally.

First, you must have at least 1 ztunnel pod running. Then the below command will fetch a token:

```shell
ztunnel-local-bootstrap () {
  pod="$(kubectl get pods -lapp=ztunnel -n istio-system -ojson | jq '.items[0]')"
  sa="$(<<<"${pod}"  jq -r '.spec.serviceAccountName')"
  uid="$(<<<"${pod}"  jq -r '.metadata.uid')"
  name="$(<<<"${pod}"  jq -r '.metadata.name')"
  mkdir -p ./var/run/secrets/tokens ./var/run/secrets/istio
  kubectl create token $sa -n istio-system --audience=istio-ca --duration=240h --bound-object-kind Pod --bound-object-name="${name}" --bound-object-uid="${uid}" > ./var/run/secrets/tokens/istio-token
  kubectl -n istio-system get secret istio-ca-secret -ojsonpath='{.data.ca-cert\.pem}' | base64 -d > ./var/run/secrets/istio/root-cert.pem
}
```

## XDS and CA

While XDS is not a hard requirement due to the static config file, the CA is.

Istiod can be run locally as simply as `go run ./pilot/cmd/pilot-discovery discovery`.

When running locally, ztunnel will automatically connect to an Istiod running on localhost.

## Sending requests

Ztunnel expects requests to be redirected with iptables. The following scripts can help do this:

Initial setup:

```shell
sudo useradd iptables1
function redirect-to () {
  redirect-to-clean
  uid=$(id -u iptables1)
  sudo iptables -t nat -I OUTPUT 1 -p tcp -m owner --uid-owner "$uid" -j REDIRECT --to-ports "${1:?port}" -m comment --comment "local-redirect-to"
  sudo ip6tables -t nat -I OUTPUT 1 -p tcp -m owner --uid-owner "$uid" -j REDIRECT --to-ports "${1:?port}" -m comment --comment "local-redirect-to"
  echo "Redirecting calls from UID $uid to ${1}"
  echo "Try: sudo -u iptables1 curl"
}
function redirect-to-clean () {
  sudo iptables-save | grep '^\-A' | grep "local-redirect-to" | cut -c 4- | xargs -r -L 1 echo sudo iptables -t nat -D
  sudo iptables-save | grep '^\-A' | grep "local-redirect-to" | cut -c 4- | xargs -r -L 1 sudo iptables -t nat -D
  sudo ip6tables-save | grep '^\-A' | grep "local-redirect-to" | cut -c 4- | xargs -r -L 1 echo sudo ip6tables -t nat -D
  sudo ip6tables-save | grep '^\-A' | grep "local-redirect-to" | cut -c 4- | xargs -r -L 1 sudo ip6tables -t nat -D
}
alias redirect-run=`sudo -u iptables1`
```

Then, setup redirection logic for all requests from the `iptables1` user to 15001:

```shell
redirect-to 15001
```

Finally, requests can be sent through the ztunnel:

```shell
redirect-run curl localhost:8080
```

In the example request above, the request will go from `curl -> ztunnel (15001) --HBONE--> ztunnel (15008) -> localhost:8080`.

If you wanted the same request to not go over HBONE, you could connect to/from another unknown IP like `127.0.0.2`.
