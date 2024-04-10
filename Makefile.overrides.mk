# Use the build container by default
BUILD_WITH_CONTAINER ?= 1

rust-version:
	./common/scripts/run.sh /usr/bin/rustc -vV