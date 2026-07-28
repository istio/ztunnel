#! /bin/bash
set -eux

REPORT_PATH="out/rust/criterion/"

git checkout "$PULL_BASE_SHA"
cargo bench -- --save-baseline master

git checkout "$PULL_PULL_SHA"
cargo bench -- --baseline-lenient master

# Capture profiles for the same-destination cases that expose pool contention.
cargo bench --bench pool -- hbone_pool_same_destination_spawned/production/32 --profile-time 10
cargo bench --bench pool -- hbone_pool_same_destination_spawned/production/512 --profile-time 10

cp -r "$REPORT_PATH" "$ARTIFACTS"
