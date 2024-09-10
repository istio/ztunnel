include common/Makefile.common.mk

FEATURES ?=
ifeq ($(TLS_MODE), boring)
	FEATURES:=--no-default-features -F tls-boring
endif

test:
	RUST_BACKTRACE=1 cargo test --benches --tests --bins $(FEATURES)

build:
	cargo build $(FEATURES)

# Build the inpodserver example
inpodserver:
	cargo build --example inpodserver

# Test that all important features build
check-features:
	cargo check --no-default-features -F tls-boring
	cargo check -F jemalloc
	(cd fuzz; cargo check)

# target in common/Makefile.common.mk doesn't handle our third party vendored files; only check golang and rust codes
lint-copyright:
	@${FINDFILES} \( -name '*.go' -o -name '*.rs' \) \( ! \( -name '*.gen.go' -o -name '*.pb.go' -o -name '*_pb2.py' \) \) -print0 |\
		${XARGS} common/scripts/lint_copyright_banner.sh

lint: lint-scripts lint-yaml lint-markdown lint-licenses lint-copyright
	cargo clippy --benches --tests --bins $(FEATURES)

check:
	cargo check $(FEATURES)

cve-check:
	cargo deny check advisories $(FEATURES)

license-check:
	cargo deny check licenses $(FEATURES)

fix: fix-copyright-banner
	cargo clippy --fix --allow-staged --allow-dirty $(FEATURES)
	cargo fmt

format:
	cargo fmt

release:
	./scripts/release.sh

gen: format

gen-check: gen check-clean-repo

presubmit: export RUSTFLAGS = -D warnings
presubmit: check-features test lint gen-check

clean:
	cargo clean $(FEATURES)

rust-version:
	./common/scripts/run.sh /usr/bin/rustc -vV