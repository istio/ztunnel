include common/Makefile.common.mk

test:
	cargo test

build:
	cargo build

release:
	cargo build --release

check:
	cargo check

format:
	cargo clippy --fix --allow-staged --allow-dirty
	cargo fmt
