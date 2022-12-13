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

## Building on Non-linux/x86_64

The Ztunnel build enables the `fips` feature by default, which in turn enables the `fips` feature
on [BoringSSL](https://github.com/cloudflare/boring).

FIPS has
[strict requirements](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf)
to ensure that compliance is granted only to the exact binary tested.
FIPS compliance was [granted](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3678)
to an old version of BoringSSL that was tested with `Clang 7.0.1`.

Installing `Clang 7.0.1` on modern environments is at best difficult. For `linux` `x86_64`, we work around
this problem by shipping the pre-built binaries under `vendor/boringssl-fips/linux_x86_64`. We then tell the BoringSSL libraries
to use this path by setting the `BORING_BSSL_PATH` environment variable in `.cargo/config.toml`.

For non-linux/x86_64 platforms, you can disable FIPS by doing the following:

1. Run cargo with the `--no-default-features` flag (e.g. `cargo build --no-default-features`).
1. Comment out the `BORING_BSSL_*` environment variables in `.cargo/config.toml`. We're actively looking into ways
to avoid this step, so it should not be needed in the future.

Some IDEs (such as the [Intellij-series](https://github.com/intellij-rust/intellij-rust/issues/9757)) do not support
globally applying arguments to cargo. In this case, it is probably easier to remove `fips` as a default feature in
`Cargo.toml`.

```toml
# ...
[features]
default = []
# ...
```
