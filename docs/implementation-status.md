# Phase 0–3 implementation evidence

The local software track is implemented and validated. The original Phase 0 hardware exit is **not passed**: Task 5 still requires real Phala and Oyster access. The user has no accounts yet and requested continuing without them. No provider account, paid resource, public deployment, or real-asset wallet has been created.

Architecture v0.4 and the earlier Hyperliquid MVP are unchanged. The platform plan controls sequencing; [ADR 001](adr-001-local-frost-construction.md) authorizes the experimental KDF/FROST construction only for controlled local tests. Independent cryptographic review remains mandatory before real assets.

## Requirement audit

| Task | Local evidence and status |
|---|---|
| 1 | ADR 001 defines roots, namespaces, immutable derivation authority, accounts, requests, attempts, stateless workers and fresh signing; records precedence and COMMIT limits. |
| 2 | Cargo.lock pins FROST Ed25519/core/rerandomized 2.2.0; upstream MIT/Apache-2.0 metadata and v0.6.0 audit boundary reviewed. Constructor availability is not treated as injected-share audit coverage. |
| 3 | Independent HKDF-SHA512 scalars; role/namespace-bound possession proofs; `P=2*S_A-S_B`; subgroup, identity and encoding checks; native signatures and malicious-peer cases pass. External review remains a production gate. |
| 4 | Exact-message SHA256 recipe, canonical Borsh, bounds and permanent approvals documented. Original-byte verification, distinct signatures over identical bytes, execution counts, recent-blockhash expiry, changed blockhash approvals, and durable nonces tested on Agave. |
| 5 | **Deferred/unverified:** real provider attestation, KMS restart/upgrade durability, protected entropy, snapshots/cloning, clock trust and cross-provider latency. Local adapters establish none of these properties. |
| 6 | ADR declares global root scope, independent release governance, permanent-loss consequences, proposed peer-plus-C escrow and approvals, historical quorum bounds, and no refresh claim. Recovery implementation remains Phase 9. |
| 7 | Separate types, authorization core, FROST backend, channel adapter, worker, relay, SDK and two programs. Core receives public observations/time/trust inputs; FROST receives roots and RNG; backend setup type permits optional future encrypted material. |
| 8 | Both workers validate role-bound proofs, their own reconstructed share and the same registration. Enrolled identity signatures bind the controller and public registration; on-chain controller authority is required. |
| 9 | Offline public derivation; immutable namespace/public-key/domain/path encoding; fixed public vectors and distinct namespace/path/domain checks. Native transactions confirm SDK/worker/on-chain derivation agreement. |
| 10 | Only own shares are reconstructed; ephemeral key packages and nonce state are erased on drop/eviction; workers never serialize secret packages or write mutable secret state. Development provisioning/trust seeds remain external private files. |
| 11 | Fresh two-round FROST signing; encrypted context/role/boot-bound peer messages; atomic nonce consumption before finish validation; concurrency, replay and tampering checks pass. No signing template can switch the approved bytes. |
| 12 | Canonical enclave-set, namespace, request and response PDAs; scheme/version/public metadata, controller, identity keys, governor and bounded records. Host and SBF runtime validation pass. |
| 13 | Real account signer required; immutable append-only exact-message request; no consumption or cancellation promise. Wrong authority is rejected. |
| 14 | Sample program checks owner and authority PDA and uses invoke_signed for registry CPI. False callers/PDA substitutions fail. Local genesis-loaded programs are immutable; other deployments inherit their actual program upgrade governance. |
| 15 | Each worker independently reads finalized registry accounts, checks ownership/PDAs/enrollment/genesis, current controls and delivered bytes. Relay references cannot authorize. Both local adapters share one validator; real disjoint provider trust remains unverified. |
| 16 | Verified API signatures and identity-signed receipts with mock attestation evidence; optional native Ed25519-verified response cache. Forged responses fail. Cache does not promise exactly-once execution. |
| 17 | Offline-derived accounts funded locally; account and CPI approvals produce executed native transfers. Different valid signatures over identical messages execute once on selected Agave; expiry and durable nonce behavior tested. |
| 18 | Separate OS processes for A, B and relay; confidential authenticated MPC routing; bounded jobs, streaming response reads, bodies, envelopes, worker requests, SSE subscriptions and nonce buffers; cancellation and timeouts. Relay has no provisioning files or approval key. |
| 19 | Reserved development measurement, signed role/boot/channel-key evidence, challenge binding and peer key possession through authenticated encryption. Development attestation cannot enter release builds; dev workers require a dev registry set. |
| 20 | SDK namespace proposal/identity verification, offline address derivation, account/CPI request helpers, payload submission, polling, SSE subscriptions, signature and receipt verification. Full service path exercised. |
| 21 | Sixteen process-kill cases: both workers, both namespaces, before round one, after round one, after round two and after result. Old boot/nonce contexts fail; fresh attempts retain addresses. Previously issued signatures remain valid. Permanent provisioning loss is not covered by restart. |
| 22 | Finalized independent reads, pinned provider-domain configuration, bounded age/chain-lag checks, monotonic starting slot, live freeze/retirement refusal and finalized resumption tested. Local OS time and shared validator are explicit test assumptions. Matching replies are not consensus proofs. |
| 23 | Real MPC tests, three LiteSVM SBF tests, real validator/process tier, fault matrix, eight simultaneous jobs per namespace, non-secret diagnostics and verified mock-attested receipts. Latency samples captured below. |

## Validation

All these commands passed on the final implementation:

```sh
cargo test --workspace --features pairkey-worker/dev-simulation --locked --offline
cargo test -p pairkey-platform-tests --test registry --locked --offline -- --ignored
cargo clippy --workspace --all-targets --features pairkey-worker/dev-simulation --locked --offline -- -D warnings
cargo build --workspace --features pairkey-worker/dev-simulation --locked --offline
target/debug/local_demo
```

There are seventeen substantive crypto/channel/authorization/HTTP/subscription/derivation tests and three explicit SBF integration tests, plus the validator/process suite. Ordinary workspace runs intentionally skip the SBF tier; its separate passing invocation is the evidence.

The negative release check `cargo build --release -p pairkey-worker --features dev-simulation --locked --offline` failed as expected with `development attestation must not enter release artifacts`. Production startup without a production provisioner also refuses; this is not a production build/deployment validation.

[Public test evidence](local-test-evidence.json) records two ordinary transfers (account and program), a durable-nonce transfer, expired-message execution count zero, explicit `AlreadyProcessed` replay rejection while the blockhash remains valid, sixteen restart cases and eight concurrent jobs per namespace. In the final local run, 36 relay signing samples gave p50 **90 ms**, p95 **237 ms**, p99 **274 ms** using floor-index empirical quantiles. These include peer handshake, authorization reads and fresh MPC/result verification; they exclude approval inclusion/finality and SDK polling/subscription delay. They are development-machine samples, not hardware service limits.

Host compiler: Rust 1.88.0. Runtime: Agave 3.0.15. SBF tools: v1.56/Rust 1.89.0. The program build uses a direct compiler path and isolated artifacts to avoid shared rustup-alias interference. Software point arithmetic exceeded Solana's compute budget; public checks use native curve syscalls instead. Native malformed-point tests and transfers pass. Upstream unused NAF-table stack diagnostics are emitted during dependency compilation; those functions were confirmed absent from the linked program symbols. CLI unknown-syscall warnings were checked against successful execution on both LiteSVM and Agave; no such warning is taken as runtime validation by itself.

## Remaining hardware and release gates

The full original Phase 0 exit still needs Task 5. Complete attestation-chain, provisioning durability/release, restart/image-upgrade, protected entropy, memory clone/rollback, trusted-clock and cross-provider network probes once provider access exists. Independently governed release authorities and genuinely disjoint production state providers must also be established.

Custom derivation/proofs/native curve integration require independent specialist review. Root recovery, historical-material limits and governance must be implemented and reviewed before a public release; changing registry epochs cannot revoke an extracted historical signing threshold. Authenticated crypto failures set a process-local refusal flag and surface an incident; operators must retire/freeze authoritative registry state before restarting after an incident. This is not a durable automatic root-wide incident system.

ECDSA/DKLS23, SESSION, SIMULATE, broader authentication, agents, Hyperliquid and recovery implementation are not silently included in the local Phase 0–3 track.

## Continuation audit: response and subscription bounds

The previous local implementation turn made concrete progress. Reinspection found that some relay/SDK responses were collected before their size check, and SSE subscriptions had no admission limit. Shared bounded readers now reject oversized Content-Length and unfinished chunked bodies before collecting the full response; the same reader covers RPC, relay health/MPC and consumer namespace/job responses. Transport/status errors omit credential-bearing URLs. SSE admission is limited to 64 live subscriptions, and dropping the client body releases the permit. Three hostile-HTTP tests and a subscription-lifetime test pass.

The original full objective remains incomplete: Task 5 hardware evidence and actual independent state-provider deployment are unavailable without provider access. Names assigned to local provider domains do not establish independent trust domains. No hardware success or full goal completion is inferred from these software checks.

Continuation audit also found that confirmed freezes did not advance the worker’s read boundary. Correctly bound negative records now set a public in-memory fence requiring a strictly later finalized slot for active resumption; older concurrent reads are refused. Malformed negative records cannot advance that fence. Two focused authorization tests cover old/same-slot views, concurrent starts, monotonic updates and slot overflow. Restart still relies on the declared trusted-state bootstrap and does not persist this public fence.

The cryptographic public-registration check now explicitly rejects equal verification shares: equal evaluations would make the interpolation polynomial constant and let either participant hold the aggregate secret. Host tests and the native malformed-registration tier include this degenerate case. This strengthens the experimental boundary and does not replace independent review.

Public derivation also refuses a zero child verification share, since the other holder could then recover the child key from its own share and public coefficient. It refuses an identity group key as well. A known-scalar public-vector test covers these edge cases; normal deterministic vectors remain unchanged. Both host and native derivation apply the checks.

## Full-goal blocked audit

The missing real-provider access condition has persisted across the initial access request, the user’s explicit reply that neither account exists, and the current automatic goal continuation. The local code and test improvements are concrete progress, but do not satisfy the mandatory hardware gate. All current test jobs are terminal, and the local harness stops its child processes; no live provider deployment is awaiting completion.

The full Phase 0–3 goal is blocked on actual Phala/Oyster deployment access and the resulting Task 5 evidence. Once available, run the real attestation/KMS/entropy/restart/image-release/clock/clone/latency probes and establish independent state-provider deployment. Do not mark the full goal achieved from the saved local evidence. This does not pause or cancel the objective; it records the external prerequisite.
