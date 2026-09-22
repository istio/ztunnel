#! /bin/bash
set -eux

REPORT_PATH="out/rust/criterion/"
COMPARE_BENCH="$(mktemp)"
cp benches/pool_compare.rs "$COMPARE_BENCH"

restore_pull_revision() {
  status=$?
  trap - EXIT
  git checkout -- Cargo.toml || true
  rm -f benches/pool_compare.rs
  git checkout --force "$PULL_PULL_SHA" || true
  rm -f "$COMPARE_BENCH"
  exit "$status"
}
trap restore_pull_revision EXIT

git checkout "$PULL_BASE_SHA"
cargo bench -- --save-baseline master
cp "$COMPARE_BENCH" benches/pool_compare.rs
if ! grep -q 'name = "pool_compare"' Cargo.toml; then
  cat >> Cargo.toml <<'EOF'

[[bench]]
name = "pool_compare"
harness = false
EOF
fi
cargo bench --bench pool_compare -- --save-baseline master
git checkout -- Cargo.toml
rm benches/pool_compare.rs

git checkout "$PULL_PULL_SHA"
cargo bench -- --baseline-lenient master

# Capture profiles for the same-destination cases that expose pool contention.
cargo bench --bench pool -- hbone_pool_same_destination_spawned/production/32 --profile-time 10
cargo bench --bench pool -- hbone_pool_same_destination_spawned/production/512 --profile-time 10
cargo bench --bench pool_compare -- hbone_pool_compare_single_flow/production --profile-time 10

cp -r "$REPORT_PATH" "$ARTIFACTS"
trap - EXIT
rm -f "$COMPARE_BENCH"
