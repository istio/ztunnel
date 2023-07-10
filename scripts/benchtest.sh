#! /bin/bash
set -eux

REPORT_PATH="out/rust/criterion/"

git checkout "$PULL_BASE_SHA"
cargo bench -- --save-baseline master

git checkout "$PULL_PULL_SHA"
cargo bench -- --baseline-lenient master

cp -r "$REPORT_PATH" "$ARTIFACTS"
