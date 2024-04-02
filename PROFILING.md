# Profiling ztunnel


# CPU

1. Port-forward admin port (15000):

```
k port-forward -n istio-system ztunnel-qkvdj 15000:15000
```

1. Either open `localhost:15000` in a browser for help, or just `curl` the CPU profile:

```
curl localhost:15000/debug/pprof/profile > profile.prof
```

1. Observe in your tooling of choice, such as https://flamegraph.com/

# Memory

1. Build `ztunnel` with the `jemalloc` feature (disabled by default, see `Cargo.toml`)

1. Port-forward admin port (15000):

```
k port-forward -n istio-system ztunnel-qkvdj 15000:15000
```

1. Either open `localhost:15000` in a browser for help, or just `curl` the memory profile:

```
curl localhost:15000/debug/pprof/heap > mem.pb.gz
```

1. If working remotely, copy container binaries to local path for symbol resolution:
```
# ztunnel main binary
kubectl cp kube-system/ztunnel-qkvdj:/usr/local/bin/ztunnel ../../ztunnel-libs-pprof/ztunnel
# stdlibs (optional)
kubectl cp kube-system/ztunnel-qkvdj:/usr/lib/$BINARY_COMPILED_ARCH/ ../../ztunnel-libs-pprof/
```
1. Observe in your tooling of choice, such as golang's `pprof`:

```
PPROF_BINARY_PATH=../../ztunnel-libs-pprof pprof -http=:8080 mem.pb.gz
```
