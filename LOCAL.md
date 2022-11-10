# Local Testing

Along with running in a Kubernetes, ztunnel can be run locally for development purposes.

This doc covers ztunnel specifically, for general Istio local development see
[Local Istio Development](https://github.com/howardjohn/local-istio-development).

## Workloads

A local file can configure workloads: `LOCAL_XDS_PATH=./examples/localhost.yaml cargo run`.

This example adds a workload for `127.0.0.1`, allowing us to send requests to/from localhost.

## Authentication

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

## XDS and CA

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
