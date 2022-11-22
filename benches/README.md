# Benchmarks

This folder provides Rust benchmarks.

## Running

```shell
$ cargo bench # Just run benchmarks
$ cargo bench -- --quick # Just run benchmarks, with less samples
$ cargo bench -- --profile-time 10s # run benchmarks with cpu profile; results will be in out/rust/criterion/<group>/<test>/profile/profile.pb
$ # Compare to a baseline
$ cargo bench -- --save-baseline <name> # save baseline
$ # ...change something...
$ cargo bench -- --baseline <name> # compare against it
```
