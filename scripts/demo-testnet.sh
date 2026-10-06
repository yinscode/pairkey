#!/usr/bin/env bash
# Dedicated Solana devnet + Base Sepolia demo. Never uses a default wallet.
set -euo pipefail
cd "$(dirname "$0")/.."
source .local/ci-tools/env.sh
umask 077
pairkey_demo_dir="$PWD/.local/testnet-demo"
mkdir -p "$pairkey_demo_dir"
chmod 700 "$pairkey_demo_dir"
for pairkey_demo_name in owner registry controller; do
  if [[ ! -f "$pairkey_demo_dir/$pairkey_demo_name.json" ]]; then
    if [[ -f "$pairkey_demo_dir/state.json" ]]; then echo "Missing established key: $pairkey_demo_name; restore the complete private directory." >&2; exit 1; fi
    solana-keygen new --silent --no-bip39-passphrase --outfile "$pairkey_demo_dir/$pairkey_demo_name.json"
  fi
done
export PAIRKEY_REGISTRY_ID="$(solana-keygen pubkey "$pairkey_demo_dir/registry.json")"
export PAIRKEY_CONTROLLER_ID="$(solana-keygen pubkey "$pairkey_demo_dir/controller.json")"
case "${1:-serve}" in
  addresses)
    solana-keygen pubkey "$pairkey_demo_dir/owner.json"
    printf 'Registry: %s\nController: %s\n' "$PAIRKEY_REGISTRY_ID" "$PAIRKEY_CONTROLLER_ID"
    ;;
  build)
    bash experiments/silence-dkls23/bootstrap.sh build --release --locked
    for pairkey_demo_program in pair-registry example-controller example-policy; do
      RUSTC="$PAIRKEY_SBF_RUSTC" cargo build-sbf \
        --manifest-path "programs/$pairkey_demo_program/Cargo.toml" \
        --sbf-sdk "$PAIRKEY_SBF_SDK" --tools-version v1.56 \
        --skip-tools-install --no-rustup-override --sbf-out-dir "$pairkey_demo_dir/programs" \
        -- --locked --target-dir target/testnet-sbf
    done
    cargo build -p pairkey-demo -p pairkey-worker -p pairkey-coordinator \
      --features pairkey-worker/dev-simulation --locked --target-dir target/testnet-demo
    ;;
  verify)
    PAIRKEY_PROGRAM_DIR="$pairkey_demo_dir/programs" cargo test -p pairkey-platform-tests \
      --test registry --locked --target-dir target/testnet-demo -- --ignored
    ;;
  deploy)
    [[ "$(solana --url https://api.devnet.solana.com genesis-hash)" == 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG' ]]
    for pairkey_demo_program in pair_registry example_controller; do
      if [[ "$pairkey_demo_program" == pair_registry ]]; then pairkey_demo_key=registry; else pairkey_demo_key=controller; fi
      solana --url https://api.devnet.solana.com --keypair "$pairkey_demo_dir/owner.json" program deploy \
        --program-id "$pairkey_demo_dir/$pairkey_demo_key.json" \
        --max-len "$(wc -c < "$pairkey_demo_dir/programs/$pairkey_demo_program.so" | tr -d ' ')" \
        "$pairkey_demo_dir/programs/$pairkey_demo_program.so"
    done
    ;;
  serve)
    exec target/testnet-demo/debug/pairkey-demo "$pairkey_demo_dir"
    ;;
  *) echo 'Usage: scripts/demo-testnet.sh addresses|build|verify|deploy|serve' >&2; exit 2 ;;
esac
