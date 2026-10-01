# CI and scoped EVM sessions

October 12, 2026. This extends the local multi-suite integration with controller-enrolled EVM sessions and a reproducible CI gate. It does not change the custom DKLS23 construction's review status or add production TEE support.

## Run the gate

Use Rust 1.88.0 with rustfmt and Clippy, Python 3.12+ and curl:

```sh
python3 scripts/install-ci-tools.py
bash scripts/ci.sh
```

The installer supports Linux x86_64 and macOS arm64. It downloads official, checksum-pinned releases into `.local/ci-tools`: Agave 3.0.14, Foundry/Anvil 1.3.1, and SBF platform tools v1.56. It never changes the user's rustup aliases or default toolchain. Checksums and release URLs are in `scripts/install-ci-tools.py`. The copied Agave SDK has a local installer shim: its strip script otherwise invokes the older bundled downloader even when `cargo-build-sbf --skip-tools-install` is set. Compilation and stripping use the pinned v1.56 compiler and LLVM tools.

The gate builds the default, fault-disabled native D sidecar and the platform from the same experiment configuration, checks workspace-member formatting and Clippy, checks the worker without development features, runs host tests, rebuilds all three SBF programs, runs the explicit registry tests, and runs both complete process demos. Do not use `cargo fmt --all`: it formats the excluded pinned native dependency, which the source bootstrap correctly rejects as drift.

`.github/workflows/ci.yml` runs the gate on pushes, pull requests and manual dispatch on Ubuntu 24.04. Host Rust and downloaded tools are pinned; third-party actions use commit pins. The workflow has read-only repository permission and uploads only `.local/ci-report/`. That directory contains gate logs, selected public JSON results and binary hashes; worker roots, identity seeds, native journals and validator ledgers are excluded. Local reruns archive the preceding report so an early failure cannot upload stale success evidence.

No Git remote was configured in this checkout when the workflow was added. A successful local gate establishes the scripts and macOS toolchain execution; the first GitHub-hosted Linux result still needs a configured remote and push. Linux-specific failures, if any, must be resolved before claiming the hosted job is green. Branch-protection requirements must also be enabled separately in repository settings.

## EVM grant and authorization

`EvmSessionGrant` is a separate schema, with separate `evm-session` PDAs. Existing Solana `SessionGrant` bytes, PDA seeds and instruction discriminants are preserved. Two new registry instruction variants are appended: `GrantEvmSession` and `RevokeEvmSession`. The example controller supports both through CPI. Rebuild/redeploy the registry and controller programs and replace workers/clients together; old binaries cannot grant these new sessions.

A controller grants:

- a namespace/account path and `key_digest`, computed from the complete enrolled backend `Key`;
- the EVM chain ID and one 20-byte recipient;
- a maximum value in wei per operation;
- a maximum gas price in wei and maximum total gas fee in wei;
- an enrolled service-key or passkey credential;
- a policy version, start time and expiry, with duration at most 24 hours.

The current transfer adapter still requires canonical legacy EIP-155 native transfers with gas limit exactly 21,000 and no calldata. Workers check `gas_price * gas_limit` with overflow refusal, and enforce both fee caps. The account destination must equal `evm_destination(chain_id)`. The key digest binds scheme, public key, namespace, path and backend registration, preventing a delegate from selecting another signing key. This grant does not authorize ERC-20 calls, contract calls, EIP-1559, arbitrary prehashes or RedPallas messages.

All limits are per operation. `cumulative_budget: Some(...)` is rejected. A valid session can authorize multiple different nonces up to its per-operation bounds; there is no total-spend promise. EVM transaction nonces handle destination execution replay. Re-signing the same authorized transaction remains possible. Expiry/revocation stops future issuance after observation and cannot invalidate an already issued EVM signature.

## SDK sequence

1. Enroll the key with `Client::signing_key` and verify both worker identities/certificate as before.
2. The account or controller program sets a policy allowing sessions, then publishes `grant_evm_session(payer, controller, registration, grant)`. Use `key.key.digest()` for `grant.key_digest`.
3. Build the versioned EVM `Intent` and a `Commit` descriptor over `intent.bytes()`. The descriptor is always needed; publishing a per-operation COMMIT is required only when registry policy requires it.
4. Set `Authorization.policy_version` and `session_id`. Compute `policy::evm_session_challenge(&authorization, &commit, &grant)` and attach `policy::service_proof` or a passkey assertion. The domain differs from Solana session proofs and binds the exact intent through the COMMIT and complete grant digest.
5. Add a separate access proof when policy requires it, then submit through `Client::sign_intent`. Workers independently fetch the EVM session PDA and recheck its owner, namespace, policy version, key/scope, delegate proof, revocation and validity interval before signing output is released.
6. Revoke with `revoke_evm_session`. A revoked session ID cannot be re-created. A policy version change invalidates old grants; issue a new grant under the new version.

`require_commit` and `require_session` retain their existing meanings. COMMIT+SESSION enforces both authorities. The existing Solana-only SIMULATE parser does not understand EVM intents and fails closed; it is not bypassed. EVM session messages are refused at the Ed25519 worker begin endpoint. RedPallas continues to require exact COMMIT approval.

The working example is `tests/platform/src/bin/local_demo/evm_sessions.rs`. It uses a real delegate key and Solana grant, confirms no per-operation request account exists, obtains a DKLS23 signature and executes the transfer on local Anvil. It runs once with an account controller and once through program CPI. Further checks send correctly signed out-of-scope requests directly to both workers, enforce COMMIT+SESSION after a policy change, reject the old policy version, and reject signing after revocation.

## Simulation compute regression

The repeated gate exposed an intermittent compute-budget failure in the existing passkey SIMULATE flow. `pairkey-types` now computes framed SHA-256 digests with Solana's hash syscall on SBF and the existing software implementation on the host. The concatenated inputs, digest outputs, addresses and wire formats are unchanged. The evaluator still accepts precisely the identity-proof instruction followed by evaluation; no extra budget/preparatory instruction is admitted.

The registry runtime regression now includes the maximum allowed RP-ID/origin lengths and both worker identities, and requires simulation to stay below 100,000 compute units. Host-generated policy and state hashes must match the SBF syscall results for that transaction to succeed.

## Evidence and limits

The complete local gate passed on macOS arm64 on October 12: 45 host tests, six explicit registry runtime tests using freshly rebuilt programs, the full original Solana/policy demo, all four account/CPI DKLS23 and RedPallas flows, and both scoped EVM session executions. Formatting, Clippy with warnings denied and the worker without development features passed. The [checked-in public snapshot](ci-session-test-evidence.json) records this run. The GitHub workflow is left ready locally as requested; it has not run on a hosted Linux runner.

The host policy tests re-sign altered operations with a valid delegate key to distinguish scope enforcement from invalid-proof rejection. Cases cover recipient, amount, gas price, total fee, multiplication overflow, gas limit, chain, path, key/registration, validity interval under both clocks, revocation, owner/PDA confusion, policy downgrades, independent access proofs, SIMULATE refusal, unsupported suites, canonical encoding, nonce/proof replay and grant binding. The SBF tier exercises account/CPI grant creation, duplicate-ID refusal, revocation and policy versioning, alongside the existing Solana cases.

The SBF compiler emits upstream NAF-table stack diagnostics for functions that are absent from the linked program symbol tables, and the older Agave post-processor emits unknown-syscall warnings. These warnings do not substitute for runtime verification: the gate requires the freshly built programs to pass both LiteSVM tests and actual validator demos.

The generated `.local/ci-report/validation.json` records the tested base commit, dirty-tree status, test counts and artifact hashes. The accompanying `multi-evidence.json` records both EVM session executions and refusals. Passing these local cases is not a cryptographic proof, a production deployment assessment, or a demonstration of independent hardware/provider trust.
