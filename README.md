# Ztunnel

Ztunnel provides an experimental implementation of the ztunnel component of
[ambient mesh](https://istio.io/latest/blog/2022/introducing-ambient-mesh/).

Note: `istio/ztunnel` is currently intended for experimental usage only.

## Feature Scope

Ztunnel is intended to be a purpose built implementation of the node proxy in [ambient mesh](https://istio.io/latest/blog/2022/introducing-ambient-mesh/).
Part of the goals of this included keeping a narrow feature set, implementing only the bare minimum requirements for ambient.
This ensures the project remains simple and high performance.

Explicitly out of scope for ztunnel include:
* Terminating user HTTP traffic
* Terminating user HTTP traffic (its worth repeating)
* Generic extensibility such as `ext_authz`, WASM, linked-in extensions, Lua, etc.

In general, ztunnel does not aim to be a generic extensible proxy; Envoy is better suited for that task.
If a feature is not directly used to implement the node proxy component in ambient mesh, it is unlikely to be accepted.

## Building

### TLS/Crypto provider

Ztunnel's TLS is built on [rustls](https://github.com/rustls/rustls).

Rustls has support for plugging in various crypto providers to meet various needs (compliance, performance, etc).

| Name                                          | How To Enable                                  |
|-----------------------------------------------|------------------------------------------------|
| [ring](https://github.com/briansmith/ring/)   | Default (or `--features tls-ring`)             |
| [boring](https://github.com/cloudflare/boring) | `--features tls-boring --no-default-features`) |

In all options, only TLS 1.3 with cipher suites `TLS13_AES_256_GCM_SHA384` and `TLS13_AES_128_GCM_SHA256` is used.

#### `boring` FIPS

With the `boring` option, the FIPS version is used.
Please note this only implies the specific version of the library is used; FIPS compliance requires more than *just* using a specific library.

FIPS has
[strict requirements](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4407.pdf)
to ensure that compliance is granted only to the exact binary tested.
FIPS compliance was [granted](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4407)
to an old version of BoringSSL that was tested with `Clang 12.0.0`.

Given that FIPS support will always have special environmental build requirements, we currently we work around this by vendoring OS/arch specific FIPS-compliant binary builds of `boringssl` in [](vendor/boringssl-fips/)

We vendor FIPS boringssl binaries for

- `linux/x86_64`
- `linux/arm64`

To use these vendored libraries and build ztunnel for either of these OS/arch combos, for the moment you must manually edit
[.cargo/config.toml](.cargo/config.toml) and change the values of BORING_BSSL_PATH and BORING_BSSL_INCLUDE_PATH under the `[env]` key to match the path to the vendored libraries for your platform, e.g:

##### For linux/x86_64

``` toml
BORING_BSSL_PATH = { value = "vendor/boringssl-fips/linux_x86_64", force = true, relative = true }
BORING_BSSL_INCLUDE_PATH = { value = "vendor/boringssl-fips/include/", force = true, relative = true }
```

##### For linux/arm64

``` toml
BORING_BSSL_PATH = { value = "vendor/boringssl-fips/linux_arm64", force = true, relative = true }
BORING_BSSL_INCLUDE_PATH = { value = "vendor/boringssl-fips/include/", force = true, relative = true }
```

Once that's done, you should be able to build:

``` shell
cargo build
```

This manual twiddling of environment vars is not ideal but given that the alternative is prefixing `cargo build` with these envs on every `cargo build/run`, for now we have chosen to hardcode these in `config.toml` - that may be revisited in the future depending on local pain and/or evolving `boring` upstream build flows.

Note that the Dockerfiles used to build these vendored `boringssl` builds may be found in the respective vendor directories, and can serve as a reference for the build environment needed to generate FIPS-compliant ztunnel builds.

## Metrics

Ztunnel exposes a variety of metrics, at varying levels of stability.

**Core** metrics are considered stable APIs
**Unstable** metrics may be changed. This includes removal, semantic changes, and label changes.

### Core metrics

#### Traffic metrics

- Tcp Bytes Sent (`istio_tcp_sent_bytes_total`): This is a `COUNTER` which measures the size of total bytes sent during response in case of a TCP connection.
- Tcp Bytes Received (`istio_tcp_received_bytes_total`): This is a `COUNTER` which measures the size of total bytes received during request in case of a TCP connection.
- Tcp Connections Opened (`istio_tcp_connections_opened_total`): This is a `COUNTER` incremented for every opened connection.
- Tcp Connections Closed (`istio_tcp_connections_closed_total`): This is a `COUNTER` incremented for every closed connection.

#### Meta metrics

-Istio build information (`istio_build`)

### Unstable metrics

#### DNS metrics

- DNS Requests (`istio_dns_requests_total`)
- DNS Upstream Requests (`istio_dns_upstream_requests_total`)
- DNS Upstream Failures (`istio_dns_upstream_failures_total`)
- DNS Upstream Request Duration (`istio_dns_upstream_request_duration_seconds`)
- On Demand DNS Requests (`istio_on_demand_dns_total`)
- On Demand DNS Cache Misses (`istio_on_demand_dns_cache_misses_total`)

#### In-Pod metrics

- Active proxy count (`istio_active_proxy_count_total`)
- Pending proxy count (`istio_pending_proxy_count_total`)
- Proxies started (`istio_proxies_started_total`)
- Proxies stopped (`istio_proxies_stopped_total`)

#### XDS metrics

- XDS Connection terminations (`istio_xds_connection_terminations_total`)
