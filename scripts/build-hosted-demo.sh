#!/usr/bin/env bash
# Run as the unprivileged service user on Linux. Program IDs must match devnet.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PAIRKEY_REGISTRY_ID:?Set the deployed registry program ID}"
: "${PAIRKEY_CONTROLLER_ID:?Set the deployed controller program ID}"
export RUSTUP_TOOLCHAIN=1.88.0
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_DEV_OPT_LEVEL=2
export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true
# Optimize the hosted development binaries while retaining the debug-assertion
# gate that prevents development attestation from entering release artifacts.
bash experiments/silence-dkls23/bootstrap.sh build --release --locked
cargo build --locked -p pairkey-demo -p pairkey-worker -p pairkey-coordinator \
  --features pairkey-worker/dev-simulation --target-dir target/hosted-demo
cargo test --locked -p pairkey-demo --target-dir target/hosted-demo
python3 website/check-site.py
