include common/Makefile.common.mk

test:
	cargo test

build:
	cargo build

lint: lint-scripts lint-yaml lint-markdown lint-protos lint-licenses
	cargo clippy

check:
	cargo check

fix:
	cargo clippy --fix --allow-staged --allow-dirty
	cargo fmt

format:
	cargo fmt

release:
	./scripts/release.sh

gen: format

gen-check: gen check-clean-repo

presubmit: export RUSTFLAGS = -D warnings
presubmit: build test lint gen-check
