# PairKey hosted application program

This download contains your application program and the typed PairKey v2 ABI.
You do not run PairKey signers or deploy another gateway.

Before building, obtain the intended gateway from the hosted `/api/v2/config`.
Pin it as `PAIRKEY_REGISTRY_ID` when building. The repository default is for local
fixtures and must not be used against a different hosted gateway.

```sh
PAIRKEY_REGISTRY_ID=YOUR_HOSTED_GATEWAY cargo build-sbf -- --locked
solana program deploy --url devnet --keypair YOUR_DEVNET_WALLET.json \
  target/deploy/pairkey_hosted_controller_example.so
```

Edit `vendor/programs/example-controller/src/approval.rs` in the downloaded bundle.
`AppPolicy::allows` defines caller, destination, path and payload rules. The module
also contains owner-authorized policy updates, authenticated read-only evaluation,
and atomic on-chain approval with a remaining-approvals counter. Preserve its
caller authentication and exact-request binding when adding application logic.

The entrypoint forwards the actual deployed program ID; every wallet gets its own
`["controller", owner]` authority PDA and `["pairkey-policy", owner]` rules PDA.
Set a policy with the hosted SDK before requesting a signature. Changing policy or
approval mode retains that authority and its keys.

Off-chain evaluation currently requires immutable deployed code. Build and test
your application before considering removal of its upgrade authority; that action
is irreversible. Upgradeable programs use on-chain approval. Simulation does not
consume a budget, nonce or counter, and is not atomic with later signing or chain
execution. Only `pairkey_approve_commit` consumes the example counter.

From the source repository, the same implementation lives at
`programs/example-controller/src/approval.rs`; the website generator bundles it
with its dependencies so the downloaded example builds without this checkout.
