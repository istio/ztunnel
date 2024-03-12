include common/Makefile.common.mk

FEATURES ?=
ifeq ($(TLS_MODE), boring)
	FEATURES:=--no-default-features -F tls-boring
endif
ifeq ($(TEST_MODE), root)
	export CARGO_TARGET_$(shell rustc -vV | sed -n 's|host: ||p' | tr [:lower:] [:upper:]| tr - _)_RUNNER=sudo -E
endif

test:
	RUST_BACKTRACE=1 cargo test --benches --tests --bins $(FEATURES)

test.root:
	CARGO_TARGET=`rustc -vV | sed -n 's|host: ||p' | tr [:lower:] [:upper:]| tr - _`_RUNNER='sudo -E' RUST_BACKTRACE=1 cargo test --benches --tests --bins $(FEATURES)

build:
	cargo build $(FEATURES)

# Test that all important features build
check-features:
	cargo check --features console
	cargo check --no-default-features -F tls-boring
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
	cargo fmt $(FEATURES)

format:
	cargo fmt $(FEATURES)

release:
	./scripts/release.sh

gen: format

gen-check: gen check-clean-repo

presubmit: export RUSTFLAGS = -D warnings
presubmit: check-features test lint gen-check

clean:
	cargo clean $(FEATURES)
