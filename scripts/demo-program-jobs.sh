#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .local/ci-tools/env.sh
# Registry and example controller run on local Solana; EVM is only a signing destination.
PAIRKEY_DEMO_MULTI_ONLY=1 PAIRKEY_DEMO_PROGRAM_ONLY=1 PAIRKEY_DEMO_JOB_LIFECYCLE=1 target/debug/local_demo
