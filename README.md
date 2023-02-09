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


### FIPS

Ztunnel enables the `fips` feature by default, which in turn enables the `fips` feature
on [BoringSSL](https://github.com/cloudflare/boring).

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

#### For linux/x86_64
``` toml
BORING_BSSL_PATH = { value = "vendor/boringssl-fips/linux_x86_64", force = true, relative = true }
BORING_BSSL_INCLUDE_PATH = { value = "vendor/boringssl-fips/linux_x86_64/include/", force = true, relative = true }
```

#### For linux/arm64
``` toml
BORING_BSSL_PATH = { value = "vendor/boringssl-fips/linux_arm64", force = true, relative = true }
BORING_BSSL_INCLUDE_PATH = { value = "vendor/boringssl-fips/linux_arm64/include/", force = true, relative = true }
```

Once that's done, you should be able to build:

``` shell
cargo build
```

This manual twiddling of environment vars is not ideal but given that the alternative is prefixing `cargo build` with these envs on every `cargo build/run`, for now we have chosen to hardcode these in `config.toml` - that may be revisited in the future depending on local pain and/or evolving `boring` upstream build flows.

Note that the Dockerfiles use to build these vendored `boringssl` builds may be found in the respective vendor directories, and can serve as a reference for the build environment needed to generate FIPS-compliant ztunnel builds.


### Non-FIPS

If you are building for a platform we don't include vendored FIPS `boringssl` binaries for, or you don't want or need FIPS compliance, note that currently non-FIPS builds are **not supported** by us. However you may build `ztunnel` with a FIPS-less `boringssl` by doing the following:


1. Comment out the `BORING_BSSL_*` environment variables in `.cargo/config.toml` entirely.
2. Run `cargo build --no-default-features`

Some IDEs (such as the [Intellij-series](https://github.com/intellij-rust/intellij-rust/issues/9757)) do not support
globally applying arguments to cargo. In this case, it is probably easier to remove `fips` as a default feature in
`Cargo.toml`.

```toml
# ...
[features]
default = []
# ...
```
