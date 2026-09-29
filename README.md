# PairKey local platform

An experimental local platform covering Phases 0–3 and the Solana portions of Phases 6–7, built against the [implementation plan](docs/platform-implementation-plan.md). [Architecture v0.4](docs/architecture-v0.4.md) remains the reference architecture; [ADR 001](docs/adr-001-local-frost-construction.md) records the alternative KDF/FROST construction and its review boundary.

Two worker processes reconstruct their own FROST Ed25519 shares from independently provisioned roots. An untrusted relay forwards encrypted MPC envelopes. Solana account or program approvals bind exact message bytes. The public SDK derives accounts offline, prepares requests, polls or subscribes to results, and verifies signatures and identity-signed receipts.

This is a local development implementation. No Phala/Oyster accounts are needed to run it. Mock attestation and private development provisioning files establish no hardware confidentiality, KMS durability, protected entropy, snapshot resistance, or independent provider trust. External cryptographic review and real provider probes remain release gates. Public production funding is unsupported.

## Run

Prerequisites: Rust 1.88.0, Agave CLI/test-validator 3.0.15, and SBF platform tools v1.56 (Rust 1.89.0). Cargo.lock pins dependencies. The program script uses the downloaded compiler directly and isolated target artifacts rather than changing shared rustup aliases.

```sh
cargo fetch --locked
bash scripts/build-programs.sh
cargo test --workspace --features pairkey-worker/dev-simulation --locked
cargo test -p pairkey-platform-tests --test registry --locked -- --ignored
cargo build --workspace --features pairkey-worker/dev-simulation --locked
target/debug/local_demo
```

The runtime test tier requires both compiled programs and is intentionally explicit. An ignored test is not validation evidence. The demo launches its own validator on selected ports, two workers and a relay, funds only local accounts, runs account/CPI transfers and fault cases, and stops its child processes on exit. It writes public results to `.local/<run-id>/evidence.json`. Development roots/identity seeds in that directory are private files and must remain excluded from source control.

## API and boundaries

Coordinator: `POST /registrations` returns a proposal authenticated by both enrolled identities; the controller then registers it on Solana. `POST /jobs` delivers bytes for an existing approval. `GET /jobs/:id` polls; `GET /jobs/:id/events` streams SSE results. The relay has no provisioning files or approval authority.

Workers: `/health`, `/attest`, `/proof`, `/ack`, `/begin`, `/finish`, `/result`, and `/abort`. Development servers bind loopback only. Worker configs pin authorization genesis, registry, enclave-set ID/governor, participant identities, and a state-provider domain. Each worker reads finalized registry data independently. Both local adapters use the same test validator; this does not demonstrate disjoint production RPC trust domains. Local system time is a test clock, not an authenticated hardware clock.

COMMIT records permanently authorize exactly the approved bytes. Signing can repeat; destination replay rules decide execution counts. A new blockhash or nonce requires a new approval. Response records cache a verified signature. Freezes and retirement stop future issuance after observation; they cannot invalidate a signature already produced or an extracted historical threshold.

Nonces are memory-only, single-use and limited to 64 live owners, including in-flight finishes. Finish cancellation, abort, expiry and error paths drop the owned nonce and key; the 15-second deadline also covers authorization RPC waits. Round-two shares bind the exact ordered commitments, so mixing generations of the same external attempt is refused without falsely blaming a peer. Replacement processes abort old boot contexts and start fresh attempts. Intact provisioning preserves addresses. Losing a root permanently is a different event; recovery is not implemented. Authenticated cryptographic failures stop the affected worker and surface an incident; an operator must retire/freeze affected registry state before restarting after an incident. That incident flag itself is process-local.

A local issuance lock orders confirmed control/policy/incident updates and aborts with the final authorization checks and creation of the encrypted contribution. Updates recorded first prevent issuance; contributions issued first may still be delivered after an update. This does not provide instantaneous chain revocation, cross-replica fencing, or snapshot resistance. See the [October 10 audit remediation and production blockers](docs/implementation-status.md#frost-audit-remediation-october-10-2026).

Development attestation is excluded from release builds. A worker built without `dev-simulation` refuses startup because a production provisioner is not installed. The local relay also refuses a release-mode startup. ECDSA, OAuth integration, agents, Hyperliquid and root recovery remain later work. SESSION, service-key/passkey proofs and constrained SIMULATE are available locally as described below.

See [implementation evidence and remaining gates](docs/implementation-status.md).


## SESSION and application access

The controller calls `set_policy` and `grant_session` on Solana, directly or through the example controller CPI. Grants bind one derived account/path, authorization-network destination, delegate credential, recipient, per-operation lamport limit, policy version, and a validity interval of at most 24 hours. `revoke_session` is permanent; issuing a replacement uses a new ID. Policy versions advance by exactly one and invalidate old grants/proofs. Records are public; signer key packages remain memory-only.

The first destination adapter accepts only a canonical legacy Solana message containing one System Program transfer, paid and signed by the derived account. Extra instructions, lookup tables, additional signers, a different recipient, an excessive amount, an incorrect destination, and arbitrary digests are refused. This narrow adapter is intentional. EVM sessions await the ECDSA backend; nonce-advance instructions and other Solana operations require separate adapters.

Use `policy::solana_destination(network)` for the path destination. Construct a `Commit` as the exact-operation descriptor even for a session; it does not need to be published on chain unless registered policy requires COMMIT. Set `Authorization.policy_version` and `session_id`, compute `policy::session_challenge`, and attach a service-key signature or ES256 passkey assertion. A separately enrolled `Policy.access` credential, when configured, also requires `policy::access_challenge`. Submit through `Client::submit_authorized`; polling, SSE and receipt verification use the existing flow. Service credentials are Ed25519 proof-of-possession keys, not bearer API tokens.

Passkey assertions check the registered P-256 SEC1 public key, exact operation challenge, RP-ID hash, pinned HTTPS origin, assertion type, user presence, user verification, flags and signature. Cross-origin assertions, extensions, and attestation data in assertions are refused. Credential enrollment is an explicit controller authorization; the browser helper can create a key for controller enrollment, but this crate does not implement a server registration/attestation verification ceremony, discoverable-account login, or authenticator counter storage. A zero or repeated sign counter is not a clone-detection guarantee. See [browser assertion helper](sdk/examples/passkey-client.js). OAuth is deferred by user choice.

A policy can require COMMIT, SESSION, or COMMIT+SESSION, plus access proof and SIMULATE. If neither a session nor a mandatory session rule applies, the worker requires COMMIT; there is no unauthenticated fallback. Repeating an operation proof authorizes only its exact bytes. Destination replay rules still decide execution counts. Grants have per-operation limits only: `cumulative_budget: Some(...)` is rejected. Total budgets, exclusive resources and cross-chain settlement are unsupported until durable reservations exist.

## Constrained SIMULATE

`Policy.simulation` pins an immutable executable program's full account-byte hash and the per-operation limit. For loader-v3, workers resolve the canonical ProgramData PDA, verify its loader owner and ProgramData state, require no upgrade authority, and pin the complete ProgramData bytes. A program pointer alone is insufficient; active upgrade authorities are refused. Both workers first verify COMMIT/session/access authority, independently parse the exact signing message, then construct precisely two simulation instructions: a native Ed25519 proof from their enrolled identity and the evaluation call. They sign the full simulation transaction with their own identity, use a finalized blockhash, enable `sigVerify`, and disable blockhash replacement. Worker identity accounts must have enough test lamports for simulated fees; simulations do not broadcast or spend them.

The sample evaluator checks the registry-owned set/namespace/policy, worker proof, exact policy/state/input commitment and absence of preparatory instructions. Structured return data must come from the pinned program and approve the exact input. Workers recompute the expected statement from their own observations; caller-provided simulation results are never accepted. Code and policy state are rechecked during begin, finish and result authorization. Code responses use a bounded 4 MiB streaming read; ordinary RPC responses retain their smaller bound.

RPC state and simulation are trusted inputs from each worker's configured source. `minContextSlot` is a lower bound, not an exact snapshot selector. The evaluator commits the relevant public records; changes between read and simulation cause refusal. Local sources still share one validator. This does not authenticate arbitrary chain state or provide production consensus proof.

Both workers recheck current authority before every MPC stage. Local clock age and chain-time bounds apply, and a monotonic three-second progress lease cannot be renewed by repeatedly reading a stalled slot. Overlapping older reads within that lease do not extend it; confirmed negative controls and policy-version fences remain authoritative. Public fences reset on process restart, and trusted bootstrap plus authenticated time/disjoint provider assumptions remain hardware gates. Session revocation stops issuance after observation; it cannot revoke an already issued signature.

The local demo includes service SESSION, service SESSION+SIMULATE, passkey SESSION+SIMULATE, and COMMIT+SESSION+SIMULATE transfers. Passkey evidence in the demo uses a software authenticator fixture; a physical/browser authenticator ceremony has not been tested. To run only these new flows after building:

```sh
PAIRKEY_DEMO_POLICY_ONLY=1 target/debug/local_demo
```

Attempt transcript domain v2 binds the complete public authorization envelope to MPC channels and receipts. RoundTwo additionally requires `transcript_digest = digest("pairkey/frost-commitment-transcript/v1", (attempt_digest, A_commitment_bytes, B_commitment_bytes))`, using the canonical framed Borsh digest helper. A fresh commitment pair distinguishes retries even if a caller repeats its external attempt ID; duplicates while pending or in flight are refused. Missing transcript digests are rejected. Namespace/account derivation stays v1, so existing account addresses are preserved. Old and new worker binaries must not be mixed during this local wire-format update; abort outstanding attempts and restart both workers together. DKLS23 remains an unimplemented proposal.
