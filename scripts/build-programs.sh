#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z "${PAIRKEY_SBF_RUSTC:-}" && -f .local/ci-tools/env.sh ]]; then
  source .local/ci-tools/env.sh
fi
: "${PAIRKEY_SBF_RUSTC:?Run python3 scripts/install-ci-tools.py and source .local/ci-tools/env.sh first}"
: "${PAIRKEY_SBF_SDK:?Set the matching repository-local SBF SDK}"
[[ -x "$PAIRKEY_SBF_RUSTC" && -x "$PAIRKEY_SBF_SDK/dependencies/platform-tools/llvm/bin/clang" ]]
for pairkey_program in pair-registry example-controller example-policy; do
  RUSTC="$PAIRKEY_SBF_RUSTC" cargo build-sbf \
    --manifest-path "programs/$pairkey_program/Cargo.toml" \
    --sbf-sdk "$PAIRKEY_SBF_SDK" --tools-version v1.56 \
    --skip-tools-install --no-rustup-override --sbf-out-dir target/deploy \
    -- --locked --target-dir target/sbf-v1.56
 done
