# Integration tests

This folder contains integration tests for ztunnel.

## Direct tests

These are tests in `direct.rs`, which simply run a ztunnel in process and make assertions.
This is the preferred option for most tests, if possible.

Helpers are available to use a fake CA and local XDS config, to avoid reliance on components outside of `ztunnel`.

For more advanced testing, see [Namespaced](#namespaced).

## Namespaced

Many scenarios in ztunnel are reliant on being deployed in an environment with redirection in place.
In order to support these, the tests in `namespaced.rs` come with a framework to run components in different network namespaces.
This simulates a single node in Kubernetes.

Tests can run "workloads" in a namespace, such as:

```rust
manager
    .workload_builder("client")
    .on_local_node()
    .register()?
    .run(|| { ... commands run here are in a network namespace ...})
```

For more information, see the docs under `WorkloadManager`.

Running these tests requires root. To run tests under sudo, `make test-root` can be used.
When not running as root, the tests are skipped. 
Warning: rust doesn't allow reporting a test was skipped, so it just appears to pass; in CI we enforce it always runs as root to avoid missing tests.

If namespaces get in a broken state, they can be cleaned up with:

```shell
ip -j netns ls | jq -r '.[].name' | grep '^test_' | xargs -n1 sudo ip netns del
```

## Kubernetes

Tests run in a full Kubernetes environment are handled in [`istio/istio`](https://github.com/istio/istio).
This repo only runs a standalone `ztunnel` tests.