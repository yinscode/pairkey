# Solana-authorized DKLS23 and RedPallas — October 12, 2026

PairKey now has a local worker/coordinator/SDK route for DKLS23 secp256k1 ECDSA and FROST RedPallas, alongside the existing FROST Ed25519 route. Both new suites accept exact COMMIT approvals from a Solana account or a controller program through CPI. This is a development integration; it does not close the cryptographic, hardware, recovery or production release gates.

## What is implemented

| Suite | Authorization | Signed output | Destination evidence |
| --- | --- | --- | --- |
| FROST Ed25519 | Existing COMMIT, constrained SESSION and SIMULATE | Ed25519 signature over the approved Solana message | Existing validator transfer and policy suites |
| DKLS23 secp256k1 | Exact COMMIT, account or program/CPI | Low-S recoverable ECDSA signature; canonical EIP-155 transaction | Native transfers executed on local Anvil |
| FROST RedPallas | Exact COMMIT, account or program/CPI | 64-byte RedPallas signature | Independently verified with ordinary `reddsa::VerificationKey<orchard::SpendAuth>` |

The RedPallas route signs messages of 1–512 bytes. It does not build Orchard transactions, supply transaction randomizers, generate spend proofs, or implement Zcash wallet scanning. Signature compatibility alone is not an Orchard wallet integration.

## Approval and enrollment

The existing Ed25519 registration remains the **authorization namespace**. No Solana program ABI or existing Ed25519 address changes are needed. The registry's `RequestRecord.derived_key` is still the Ed25519 namespace-derived key; it must not be presented as the ECDSA or RedPallas destination key.

An application calls `Client::signing_key(KeyRequest, pinned_identities)` to enroll a backend key for a specific namespace, account path and suite. Both workers authenticate their public enrollment data using their existing platform identities. The SDK verifies both signatures, context and the backend certificate before returning the key. DKLS certificates additionally bind the native D identities. RedPallas certificates contain proofs of possession for both root-derived public shares.

The application constructs `Intent { version: 1, key, payload }`. `intent.bytes()` is a domain-prefixed canonical Borsh encoding that binds:

- authorization registration digest;
- signing suite, public key and backend registration digest;
- account path and destination;
- the complete payload and intent version.

It creates the usual `Commit` over these bytes and publishes that COMMIT, either directly or through its controller program. It then calls `Client::sign_intent(SignRequest, pinned_identities)`. Both workers independently read current finalized Solana authority using the existing core, freshness checks, policy checks and local issuance fence. Workers compute the destination signing hash themselves. The relay cannot substitute a caller-provided prehash.

The new coordinator endpoints are `POST /multi/keys` and `POST /multi/sign`. They are synchronous and serialize multi-suite operations; concurrent requests receive HTTP 429. They do not yet use the Ed25519 `/jobs` queue, SSE, or on-chain response cache. Returned signatures include two identity-signed, request-bound receipts marked `development: true`, `hardware_backed: false`, with both worker boot IDs and finalized observation slots. These receipts are development identity assertions, not hardware attestation.

The source example is `tests/platform/src/bin/local_demo/multi.rs`. The Rust API is in `sdk/src/multi.rs` and `crates/pairkey-signing`.

## Backend details and limits

**DKLS23:** each platform worker starts its own native Spike D child with its own private root file. The platform authenticates the native worker identity under the enrolled platform identity and binds the peer's current platform boot. Only protocol transport frames can cross the relay endpoint; arbitrary native commands and fault requests cannot. Native D registration, donor consumption, quarantine journals and lifecycle checks remain in effect. The platform checks current authority before exposing each outgoing signing frame and final receipt. An abandoned active operation kills the child after the bounded operation timeout; replacement creates a fresh native boot.

This integration prepares a fresh donor for each signing request. It does not claim a warm donor reuse optimization or that the Silence constructor/secrecy/reuse proof obligations have been resolved. It uses the existing patched Spike D dependency without adding another upstream DKLS patch. The standalone experiment retains its own workspace/lockfile, while the platform lockfile now includes that experiment as a dependency. Review the upstream Silence license before distribution; the platform's own Apache metadata does not relicense its dependencies.

**RedPallas:** uses pinned `reddsa 0.5.2` FROST with its Pallas/Orchard SpendAuth generator. Each worker derives its share from its own root, with a separate suite/namespace/path/role domain. The public key is the two-share interpolation `2*S_A - S_B`. This is another custom root-derived setup, with the same need for specialist construction review as PairKey's Ed25519 setup; using upstream signing code does not make the setup audited.

RedPallas signing uses fresh two-round nonces. A non-cloneable owner consumes its nonce before finish validation. An attempt lease blocks duplicate starts while finish is in flight, allows reset/expiry to cancel issuance, and retains its capacity permit until the actual nonce owner exits. The 15-second lifetime includes authorization RPC waits. Both round-two envelopes bind the ordered commitment transcript. Stale rounds burn the attempt without falsely attributing cheating; authenticated invalid signature shares stop the worker. Native nonce/key objects are cleared on drop, but this local process makes no physical memory-erasure or snapshot-resistance guarantee.

New backend paths currently require worker enrollment. A returned public key/certificate supports offline address computation and verification; it does not add the existing Ed25519 SDK's offline child derivation to these suites. Root loss recovery remains unimplemented.

**EVM scope:** the adapter supports canonical legacy EIP-155 native transfers, fixed gas limit 21,000, nonzero recipient, no calldata, `u64` nonce/value/gas price and bounded chain ID. It is checked against the [published EIP-155 vector](https://eips.ethereum.org/EIPS/eip-155). It does not implement ERC-20 calls, contract calls, EIP-1559, EIP-712 or Hyperliquid. Chain ID is bound both in the account destination and the transaction prehash. Solana authorizes the operation; workers sign off chain and a relayer submits the resulting transaction to the destination chain.

**Policy composition:** the new routes require COMMIT and reject SESSION until a destination-specific session adapter exists. Existing access-proof requirements still apply. Existing Solana-only SIMULATE policies cannot evaluate these intent bytes and fail closed; they are not silently skipped. Approval can authorize signing the same bytes again. EVM nonce rules prevent duplicate execution of the demonstrated transfer; raw RedPallas messages have no built-in application replay protection.

## Reproduce

The platform now resolves the pinned local DKLS source, so bootstrap it before running root workspace Cargo commands on a fresh checkout. Build the platform's sidecar without `research-faults`:

```sh
bash experiments/silence-dkls23/bootstrap.sh build --release --locked
cargo fetch --locked
bash scripts/build-programs.sh
cargo test --workspace --features pairkey-worker/dev-simulation --locked
cargo test -p pairkey-platform-tests --test registry --locked -- --ignored
cargo build --workspace --features pairkey-worker/dev-simulation --locked
PAIRKEY_DEMO_MULTI_ONLY=1 target/debug/local_demo
```

The multi-suite demo additionally needs Anvil on PATH. Use `cargo fmt` (workspace members only), not `cargo fmt --all`: the latter also reformats the excluded pinned source dependency and the bootstrap checksum checks correctly reject that drift. Rebuild the native sidecar and platform together when the experiment manifest or configuration-bound files change; a mismatched native configuration is refused. The normal Solana/Ed25519 demo remains `target/debug/local_demo`; the policy-only flow is `PAIRKEY_DEMO_POLICY_ONLY=1 target/debug/local_demo`. Private roots and development identity seeds remain in ignored `.local/<run>/` directories. Do not publish those directories.

The multi-suite demo runs account and program/CPI approvals for both suites, independently verifies signatures/receipts, executes both EVM transfers, rejects EVM replay and wrong-chain verification, restarts both actual platform workers and checks stable keys plus fresh signatures, then freezes each namespace and checks refusal for both suites. It also bypasses SDK/coordinator request validation to check that each worker rejects altered payload/destination intents under the original COMMIT. Unit tests cover the EIP-155 vector, RedPallas proof/key/domain checks, consumed/stale nonce refusal, and cancellation during authorization RPC while retaining capacity. This evidence is a bounded test result, not a security proof.

## Validation for this change

[Public test evidence](multi-suite-test-evidence.json) records all four account/program × DKLS23/RedPallas flows, both executed EVM transaction hashes, direct worker substitution refusal, receipt tampering refusal, stable-key restarts and freeze refusal. The final locked/offline host suite passed 41 tests; the five explicit registry runtime tests also passed. The complete original Ed25519 transfer/restart/policy demo passed, as did Clippy with warnings denied, workspace-member formatting, default-feature worker compilation and the checksum-validated native sidecar build without fault features.

The SBF tests and demos used existing unchanged program artifacts. A fresh SBF build could not run because the configured v1.56 compiler is absent on this machine. Artifact hashes and this limitation are recorded in the evidence. A temporary mixed native/platform build was refused by the DKLS configuration check; rebuilding both at the same configuration restored operation.

## Remaining work

- Review the multi-suite authorization binding, custom RedPallas setup and Spike D construction independently; resolve the outstanding Silence proof obligations and licensing boundary.
- Add scoped EVM sessions, contract/type-specific adapters and application replay semantics. Add Orchard transaction/randomization integration only when its exact requirements are selected.
- Extend the synchronous API with durable/public job handling, recovery, retries/backpressure and an explicit multi-suite response-cache schema if required by applications.
- Prove active-operation fault/restart matrices, mixed-version refusal and resource bounds beyond the covered local cases; integrate the selected native D fault harness into CI without enabling fault injection in deployment binaries.
- Finish real TEE provisioning/attestation, protected entropy, rollback/fork controls, trusted bootstrap/time, independent provider state sources and root recovery. Local restarts do not establish these properties.
- Finish application access as outlined below.

## Minimal application access work (item 3)

The least work is to reuse the existing worker credential proofs and Solana controller/session authority. Access methods decide who may request an operation; they do not require another MPC signing algorithm.

**Passkeys:** retain the existing ES256 assertion verification and challenge binding. Add a small server registration endpoint and browser UI: issue a single-use registration challenge; verify the WebAuthn registration response, origin and RP ID; persist the credential ID, public key, user association and relevant authenticator/counter metadata; have the existing controller explicitly enroll/revoke that credential. Then use the existing assertion helper for exact COMMIT access proofs or supported Solana sessions. Test a real browser/authenticator. A reputable WebAuthn server implementation can supply the ceremony rather than writing a new verifier. Follow the [WebAuthn registration verification requirements](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential); counters are signals, not a universal clone-detection guarantee.

**OIDC with ephemeral keys:** the client generates an ephemeral Ed25519 key and keeps its private half locally. A small auth broker runs authorization-code login with PKCE, verifies the provider's token signature, issuer, audience, nonce and expiry, and maps the stable `(issuer, subject)` to a previously authorized PairKey account. A single-use broker challenge binds that login transaction to the ephemeral public key, account and requested scope; require proof of possession of that key. The controller approves a short-lived existing service-key session, or explicitly delegates tightly bounded grant issuance to a controller program that recognizes the broker. Workers then verify the existing Ed25519 service proofs. They do not need to parse JWTs or contact an identity provider. Follow [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html) and [PKCE](https://www.rfc-editor.org/rfc/rfc7636).

For the smallest first OIDC increment, require one existing controller approval per session. That avoids adding broker authority to the on-chain controller. If login must grant access automatically, a narrowly scoped broker/controller delegation is additional work and a real trust decision: an OIDC token alone does not control a Solana namespace. Bound grant expiry by the login/session policy, implement revocation, and never treat the ephemeral key as a bearer token.

Existing Solana transfer sessions can use this approach first. EVM/RedPallas COMMITs can use an enrolled access credential now, but session-only use of the new routes needs a new destination policy adapter. The smallest next adapter is the already constrained EVM native transfer: chain, sender/key, recipient, amount, gas/fee caps and expiry. Arbitrary RedPallas messages should keep exact COMMIT approval until an application-specific operation and replay policy is defined. Cumulative budgets still require durable accounting and are outside the minimal integration.
