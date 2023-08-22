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


## Remote debugging

Deploy ztunnel in docker, and use CLion on mac for remote debugging:

- Create a remote debug configuration, please refer to [here](https://www.jetbrains.com/help/clion/remote-debug.html#remote-config).
- For the docker image and how to use it, please refer to [here](./docker/remote-env/Dockerfile).

In docker, launch ztunnel under gdbserver:

```shell
cargo build
# This port 1234 was specified when executing "docker run".
FAKE_CA="true" XDS_ADDRESS="" LOCAL_XDS_PATH=./examples/localhost.yaml gdbserver :1234 ./out/rust/debug/ztunnel
```

Next, please refer to [here](#sending-requests) to see how to send the request.