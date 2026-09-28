# PairKey local platform

An experimental Phase 0–3 platform built against the [implementation plan](docs/platform-implementation-plan.md). [Architecture v0.4](docs/architecture-v0.4.md) remains the reference architecture; [ADR 001](docs/adr-001-local-frost-construction.md) records the alternative KDF/FROST construction and its review boundary.

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

Nonces are memory-only, single-use, bounded and cancelled on failure. Replacement processes abort old boot contexts and start fresh attempts. Intact provisioning preserves addresses. Losing a root permanently is a different event; recovery is not implemented. Authenticated cryptographic failures stop the affected worker and surface an incident; an operator must retire/freeze affected registry state before restarting after an incident. That incident flag itself is process-local.

Development attestation is excluded from release builds. A worker built without `dev-simulation` refuses startup because a production provisioner is not installed. The local relay also refuses a release-mode startup. ECDSA, SESSION, SIMULATE, general login, agents, Hyperliquid and root recovery remain later phases.

See [implementation evidence and remaining gates](docs/implementation-status.md).
