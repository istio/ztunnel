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

Docker does support cross-building for Windows, but it is a bit of a pain. You can use the `docker buildx` command to build images for Windows. First, you need to create a new builder instance:

```bash
docker buildx create --name windows-builder --platform=windows/amd64 # change to windows/arm64 if you want to build for arm64
```

Then, build a docker image with:

```bash
docker buildx build . -f Dockerfile.ztunnel-windows --platform=windows/amd64 --output type=registry -t localhost:5000/ztunnel-windows --builder windows-builder
```

## DNS

HostProcess pods in Windows can't resolve cluster local DNS names. This is a known issue. In the meantime, you can use ALT_XDS_HOSTNAME and ALT_CA_HOSTNAME environment variables to set the expected certificate dns names for both XDS and CA clients.

UPDATE: looks like there are some powershell commands we can run (perhaps as an init container?) to set the nameserver for a certain DNS namespace:

```powershell
Add-DnsClientNrptRule -Namespace ".cluster.local" -NameServers "$env:KUBE_DNS_IP"
Clear-DnsClientCache # Clears the DNS client cache. Equivalent to `ipconfig /flushdns`
```

## REUSE_PORT

Socket reuse is effectively not supported on Windows (despite the options existing, they're either insecure or ineffective for our purposes)
