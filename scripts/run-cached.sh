#!/bin/bash
set -e

SCRIPT_INPUT=("$@")

# Function to log error and execute command
function error_and_exec() {
    echo "Error: $1" >&2
    exec "${SCRIPT_INPUT[@]}"
}

# Check if RUST_CACHE_DIR is set
if [ -z "${RUST_CACHE_DIR}" ]; then
    error_and_exec "RUST_CACHE_DIR is not set" "$@"
fi

# Check if out/ directory exists
if [ -d "out" ]; then
    error_and_exec "out/ directory already exists" "$@"
fi

# Get current branch name
if [ -z "${PULL_BASE_REF}" ]; then
    error_and_exec "Could not determine current branch" "$@"
fi

# Make sure we are on presubmit
if [ "${JOB_TYPE}" != "presubmit" ]; then
    error_and_exec "Caching only available on presubmit" "$@"
fi

CACHE_DIR="${RUST_CACHE_DIR}/${PULL_BASE_REF}"


# Strip binaries to keep things smaller
cat <<EOF > ~/.cargo/config.toml
[target.'cfg(debug_assertions)']
rustflags = ["-C", "strip=debuginfo"]
EOF
# Check if branch cache exists
if [ ! -d "${CACHE_DIR}" ]; then
    # Not an error, we may need to populate it the first time
    echo "Cache for branch ${PULL_BASE_REF} not found, we will populate it"  >&2
else
    echo "Found cache for branch ${PULL_BASE_REF}, copying it"  >&2
    # Copy cache to out directory
    mkdir -p out
    cp -ar "${CACHE_DIR}" out/rust
    echo "Cache size: $(du -sh out/rust)"  >&2
fi

# Run the provided command
"$@"

# Clean up everything except build and deps directories
find out/rust -mindepth 1 -maxdepth 1 -type d \
  ! -path "out/rust/debug" \
  -exec rm -rf {} +

find out/rust -mindepth 2 -maxdepth 2 -type d \
    ! -path "out/rust/debug/build" \
    ! -path "out/rust/debug/deps" \
    ! -path "out/rust/debug/.fingerprint" \
    -exec rm -rf {} +

# Update the cache with our state
tmp="${RUST_CACHE_DIR}/${RANDOM}"
tmp_to_delete="${RUST_CACHE_DIR}/${RANDOM}"

echo "Backing up cache"  >&2

# Move our cache into the volume (this is slow since its cross-filesystem)
mv out/rust "${tmp}"
# Move the existing cache - we would delete it now, but mv is faster than delete, so we do this later
# to prevent the time period when things are down
# Note: we could use `exch` here in the future, but its not in our Ubuntu version
mv "${CACHE_DIR}" "${tmp_to_delete}" || true
# Populate the cache with our new info
mv "${tmp}" "${CACHE_DIR}"
# Remove the old one
rm -rf "${tmp_to_delete}" || true
