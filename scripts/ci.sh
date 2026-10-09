#!/usr/bin/env bash
# Same gate locally and in GitHub Actions. Export only selected public evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
source .local/ci-tools/env.sh
if [[ -d .local/ci-report ]]; then
  pairkey_previous_report="$(mktemp -d .local/ci-report-previous.XXXXXX)"
  mv .local/ci-report "$pairkey_previous_report/report"
fi
mkdir -p .local/ci-report
pairkey_run() {
  local label="$1"
  shift
  "$@" 2>&1 | tee ".local/ci-report/$label.log"
}
pairkey_run versions bash -c 'rustc --version; solana --version; anvil --version; "$PAIRKEY_SBF_RUSTC" --version'
# Match the research configuration in native sidecar and platform. No fault feature.
pairkey_run native bash experiments/silence-dkls23/bootstrap.sh build --release --locked
# Fault injection is confined to the standalone test executable, never the deployed sidecar.
pairkey_run native-invariants bash experiments/silence-dkls23/bootstrap.sh test --release --locked --test invariants
pairkey_run native-faults bash experiments/silence-dkls23/bootstrap.sh test --release --locked --features research-faults --bin dkls-spike d_driver::tests:: -- --test-threads=1
pairkey_run format cargo fmt -- --check
pairkey_run clippy cargo clippy --workspace --all-targets --features pairkey-worker/dev-simulation --locked -- -D warnings
pairkey_run default-worker cargo check -p pairkey-worker --no-default-features --locked
pairkey_run host-tests cargo test --workspace --features pairkey-worker/dev-simulation --locked
pairkey_run sbf bash scripts/build-programs.sh
pairkey_run registry-tests cargo test -p pairkey-platform-tests --test registry --locked -- --ignored
pairkey_run approval-rules-tests cargo test -p pairkey-platform-tests --test approval_rules --locked -- --ignored
pairkey_run program-approval-tests cargo test -p pairkey-platform-tests --test program_approval --locked -- --ignored
pairkey_run build cargo build --workspace --features pairkey-worker/dev-simulation --locked
pairkey_run ed25519-demo target/debug/local_demo
pairkey_run multi-demo env PAIRKEY_DEMO_MULTI_ONLY=1 PAIRKEY_DEMO_JOB_LIFECYCLE=1 target/debug/local_demo
python3 scripts/collect-ci-evidence.py
