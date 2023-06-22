#! /bin/bash
set -eux

REPORT_PATH="out/rust/criterion/"

git checkout $PULL_BASE_SHA
cargo bench --profile dev -- --quick # FIXME: dev for faster compilation, quick for faster runs

git checkout $PULL_PULL_SHA
cargo bench --profile dev -- --quick # FIXME: dev for faster compilation, quick for faster runs

cp -r $REPORT_PATH $ARTIFACTS
