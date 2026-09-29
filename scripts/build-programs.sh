#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pairkey_sbf_rustc="${PAIRKEY_SBF_RUSTC:-$HOME/.cache/solana/v1.56/platform-tools/rust/bin/rustc}"
if [[ ! -x "$pairkey_sbf_rustc" ]]; then
  echo "Install SBF platform tools v1.56 first, or set PAIRKEY_SBF_RUSTC to their rustc path."
  exit 1
fi
RUSTC="$pairkey_sbf_rustc" cargo build-sbf --manifest-path programs/pair-registry/Cargo.toml --tools-version v1.56 --no-rustup-override --sbf-out-dir target/deploy -- --locked --target-dir target/sbf-v1.56
RUSTC="$pairkey_sbf_rustc" cargo build-sbf --manifest-path programs/example-controller/Cargo.toml --tools-version v1.56 --no-rustup-override --sbf-out-dir target/deploy -- --locked --target-dir target/sbf-v1.56

RUSTC="$pairkey_sbf_rustc" cargo build-sbf --manifest-path programs/example-policy/Cargo.toml --tools-version v1.56 --no-rustup-override --sbf-out-dir target/deploy -- --locked --target-dir target/sbf-v1.56
