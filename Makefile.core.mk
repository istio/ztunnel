include common/Makefile.common.mk

test:
	cargo test --benches --tests --bins

build:
	cargo build

# override target in common/Makefile.common.mk, only check golang and rust codes
# load order: Makefile -> Makefile.overrides -> Makefile.core -> Makefile.common
# cannot override in Makefile.overrides
lint-copyright-banner:
	@${FINDFILES} \( -name '*.go' -o -name '*.rs' \) \( ! \( -name '*.gen.go' -o -name '*.pb.go' -o -name '*_pb2.py' \) \) -print0 |\
		${XARGS} common/scripts/lint_copyright_banner.sh

lint: lint-scripts lint-yaml lint-markdown lint-licenses lint-copyright-banner
	cargo clippy

check:
	cargo check

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
presubmit: build test lint gen-check
