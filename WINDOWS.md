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

HostProcess pods in Windows can't resolve cluster local DNS names. This is a known issue. In the meantime, you can use ALT_XDS_HOSTNAME and ALT_CA_HOSTNAME environment variables to set the expected certificate dns names for both XDS and CA clients.

UPDATE: looks like there are some powershell commands we can run (perhaps as an init container?) to set the nameserver for a certain DNS namespace:

```powershell
Add-DnsClientNrptRule -Namespace ".cluster.local" -NameServers "$env:KUBE_DNS_IP"
Clear-DnsClientCache # Clears the DNS client cache. Equivalent to `ipconfig /flushdns`
```

## REUSE_PORT

Socket reuse is effectively not supported on Windows (despite the options existing, they're either insecure or ineffective for our purposes)
