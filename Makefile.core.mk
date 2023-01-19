include common/Makefile.common.mk

test:
	cargo test --benches --tests --bins

build:
	cargo build

# Test that all important features build
build-features:
	cargo build --features console

# target in common/Makefile.common.mk doesn't handle our third party vendored files; only check golang and rust codes
lint-copyright:
	@${FINDFILES} \( -name '*.go' -o -name '*.rs' \) \( ! \( -name '*.gen.go' -o -name '*.pb.go' -o -name '*_pb2.py' \) \) -print0 |\
		${XARGS} common/scripts/lint_copyright_banner.sh

lint: lint-scripts lint-yaml lint-markdown lint-licenses lint-copyright
	cargo clippy

check:
	cargo check

cve-check:
	cargo deny check advisories

license-check:
	cargo deny check licenses

fix: fix-copyright-banner
	cargo clippy --fix --allow-staged --allow-dirty
	cargo fmt

format:
	cargo fmt

release:
	./scripts/release.sh

gen: format

gen-check: gen check-clean-repo

presubmit: export RUSTFLAGS = -D warnings
presubmit: build test lint gen-check build-features
