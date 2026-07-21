include common/Makefile.common.mk

FEATURES ?=
ifeq ($(TLS_MODE), boring)
	FEATURES:=--no-default-features -F tls-boring -F jemalloc
else ifeq ($(TLS_MODE), aws-lc)
	FEATURES:=--no-default-features -F tls-aws-lc -F jemalloc
else ifeq ($(TLS_MODE), openssl)
	FEATURES:=--no-default-features -F tls-openssl -F jemalloc
endif

test:
	RUST_BACKTRACE=1 cargo test --benches --tests --bins $(FEATURES)

# The throughput bench needs netns privileges, which BUILD_WITH_CONTAINER=1 (default)
# already provides via Makefile.overrides.mk (--privileged + /var/run/netns mount).
#   make bench BENCH_ARGS="-F jemalloc -- --save-baseline master"
#   make bench BENCH_ARGS="-F jemalloc --bench basic -- --baseline master"
BENCH_ARGS ?=
bench:
	RUST_BACKTRACE=1 cargo bench $(FEATURES) $(BENCH_ARGS)

coverage:
	FEATURES=$(FEATURES) ./scripts/test-with-coverage.sh 

build:
	cargo build $(FEATURES)

# Build the inpodserver example
inpodserver:
	cargo build --example inpodserver

# Test that all important features build.
# Each TLS mode is checked with jemalloc (the combination release builds ship)
# and one without it to keep the non-jemalloc cfg paths compiling.
check-features:
	cargo check --no-default-features -F tls-boring -F jemalloc
	cargo check --no-default-features -F tls-aws-lc -F jemalloc
	cargo check --no-default-features -F tls-openssl -F jemalloc
	cargo check --no-default-features -F tls-aws-lc
	(cd fuzz; RUSTFLAGS="--cfg fuzzing" cargo check)

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
	(cd fuzz; cargo update ztunnel 2>/dev/null || true)

gen-check: gen check-clean-repo

presubmit: export RUSTFLAGS = -D warnings
presubmit: check-features test lint gen-check

clean:
	cargo clean $(FEATURES)

rust-version:
	./common/scripts/run.sh /usr/bin/rustc -vV
