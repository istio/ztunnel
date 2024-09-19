# WIP: Windows Support

Easiest way is probably to cross-compile? On Debian-based distros, install mingw:

```bash
sudo apt-get install mingw-w64
```

Then, add Rust cross-compile support with rustup:

```bash
rustup target add x86_64-pc-windows-gnu
```

Test a build with:

```bash
cargo build --target x86_64-pc-windows-gnu
```

## DNS

HostProcess pods in Windows can't resolve cluster local DNS names. This is a known issue and is being worked on. In the meantime, you can set the ISTIOD_CUSTOM_HOST environment variable (on the istiod deployment) to the IP address of the Istiod service (do this post-installation). This will allow the tls connections to work.
