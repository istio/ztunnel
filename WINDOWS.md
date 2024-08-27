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
