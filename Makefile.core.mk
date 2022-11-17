include common/Makefile.common.mk

test:
	cargo test

build:
	cargo build

# override target in common/Makefile.common.mk, only check golang and rust codes
lint-copyright-banner:
	@${FINDFILES} \( -name '*.go' -o -name '*.rs' \) \( ! \( -name '*.gen.go' -o -name '*.pb.go' -o -name '*_pb2.py' \) \) -print0 |\
		${XARGS} common/scripts/lint_copyright_banner.sh

lint: lint-scripts lint-yaml lint-markdown lint-licenses lint-copyright-banner
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
