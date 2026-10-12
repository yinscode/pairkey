# PairKey

PairKey is a programmable key protocol: a Solana program, Solana account,
passkey or OIDC identity authorizes an exact request, and two signers jointly
produce a message signature for Solana, EVM, Zcash, NEAR or Bitcoin. The hosted
v2 API runs at `https://pairkey.com/api/v2`; developers do not operate signing
workers. Start with the [source quickstarts](website/docs/quickstart.html),
[interactive demo](https://pairkey.com/demo), or [hosted API contract](docs/offchain-approval-api.md).

## Hosted approval v2

An account wallet signs each exact request off-chain. A passkey assertion or
OIDC ID token binds a short-lived Ed25519 key that signs that request. A Solana
program authenticates its caller and uses `pairkey_approve` for read-only,
immutable-code evaluation or `pairkey_approve_commit` to consume state and record
approval in one transaction. Both signers check current rules independently.
No namespace registration transaction or saved policy is required to start;
optional Solana rules are versioned and reused across requests. V2 sessions are
deferred. These APIs return message signatures, not destination transactions.

The [implementation record](docs/offchain-approval-plan.md) and [deployment
evidence](docs/offchain-approval-deployment.md) distinguish local coverage from
public-devnet checks. The public deployment has two development signer processes
on one host; its hardware and cryptographic review boundaries are documented in
the [security guide](website/docs/security.html). The older `/api/v1` registration,
COMMIT and transfer-session paths remain available for existing integrations.

## Local platform and legacy API

An experimental local platform covering Phases 0–3 and the Solana portions of Phases 6–7, built against the [implementation plan](docs/platform-implementation-plan.md). [Architecture v0.4](docs/architecture-v0.4.md) remains the reference architecture; [ADR 001](docs/adr-001-local-frost-construction.md) records the alternative KDF/FROST construction and its review boundary.

Two worker processes reconstruct their own FROST Ed25519 shares from independently provisioned roots. An untrusted relay forwards encrypted MPC envelopes. Solana account or program approvals bind exact message bytes. The public SDK derives Ed25519 accounts offline, prepares requests, polls or subscribes to results, and verifies signatures and identity-signed receipts. A separate local route now supports Solana-authorized DKLS23 ECDSA and FROST RedPallas; see [multi-suite signing and application access](docs/multi-suite-signing.md).

This is a local development implementation. No Phala/Oyster accounts are needed to run it. Mock attestation and private development provisioning files establish no hardware confidentiality, KMS durability, protected entropy, snapshot resistance, or independent provider trust. External cryptographic review and real provider probes remain release gates. Public production funding is unsupported.

## Run

Prerequisite: Rust 1.88.0 with rustfmt and Clippy, Python 3.12+, and curl. The checksum-pinned installer supplies Agave 3.0.14, Anvil 1.3.1 and SBF platform tools v1.56 (Rust 1.89.0) under ignored `.local/ci-tools`. Cargo.lock pins dependencies. Shared rustup aliases are unchanged. See [CI and EVM sessions](docs/ci-and-evm-sessions.md).

```sh
python3 scripts/install-ci-tools.py
source .local/ci-tools/env.sh
bash experiments/silence-dkls23/bootstrap.sh build --release --locked
cargo fetch --locked
bash scripts/build-programs.sh
cargo test --workspace --features pairkey-worker/dev-simulation --locked
cargo test -p pairkey-platform-tests --test registry --locked -- --ignored
cargo build --workspace --features pairkey-worker/dev-simulation --locked
target/debug/local_demo
```

The runtime test tier requires both compiled programs and is intentionally explicit. An ignored test is not validation evidence. The demo launches its own validator on selected ports, two workers and a relay, funds only local accounts, runs account/CPI transfers and fault cases, and stops its child processes on exit. It writes public results to `.local/<run-id>/evidence.json`. Development roots/identity seeds in that directory are private files and must remain excluded from source control.

## Legacy local message demo

A loopback backend connects the website to per-message Solana program or account approval, FROST Ed25519 / DKLS23 secp256k1 / FROST RedPallas signing, derived public keys, and fresh signature verification for Solana, EVM, Zcash and NEAR. It does not broadcast destination transactions. The earlier Base transfer/session API is retained separately. It uses dedicated testnet wallets and two local development signer processes. See the [testnet setup guide](website/docs/testnet.html) for funding, limits, and reconciliation.

```sh
bash scripts/demo-testnet.sh addresses
bash scripts/demo-testnet.sh build
bash scripts/demo-testnet.sh verify
# Fund the printed dedicated owner with devnet SOL before deployment.
bash scripts/demo-testnet.sh deploy
bash scripts/demo-testnet.sh serve
```

Open `http://127.0.0.1:4180/demo`. This older approval path needs devnet SOL; hosted v2 account, passkey and OIDC message approvals do not broadcast per-message Solana transactions. Base Sepolia ETH is needed only for the legacy transfer API. The local testnet backend is separate from the public hosted deployment. Builds and local tests alone do not establish successful public-testnet execution.

## Hosted testnet demo

The demo deployment uses `pairkey.com` for the public website and docs, with the
live `/demo` and `/api/*` publicly accessible over HTTPS without a password. Deployment
templates are in `scripts/deploy/`. The backend still binds only
`127.0.0.1:4180`; `PAIRKEY_DEMO_ORIGIN=https://pairkey.com` pins the accepted
Host/Origin and `PAIRKEY_DEMO_ROOT=/opt/pairkey/app` locates its assets and DKLS
executable. This is a shared demo: visitors share signing state and operation
history. Origin checks are not authentication. The existing request bounds,
single-operation gate, and 256-operation journal limit remain in place; keep
the internal worker and coordinator ports private.

`scripts/build-hosted-demo.sh` builds Linux binaries with Rust 1.88.0 and one
compile job. Supply the deployed `PAIRKEY_REGISTRY_ID` and
`PAIRKEY_CONTROLLER_ID`. It keeps the development coordinator's required debug
assertions, builds the DKLS subprocess in release mode, and runs demo tests.
The service runs as `pairkey` with persistent private state in
`/opt/pairkey/state`. Start/restart it with `systemctl restart pairkey-demo` and
inspect it with `journalctl -u pairkey-demo` on the droplet.

Before migrating an existing demo, wait for operations to finish, stop its old
backend and workers, and copy the complete current private state, including
roots, identities, job journal, saved service ports, and incident latches. Never
run both hosts against copies of the same state. Keep a private offline backup;
do not place this state in the static web root or source archive. This remains a
testnet development deployment with both signers on one host, not independent
TEE infrastructure.

## API and boundaries

Coordinator: `POST /registrations` returns a proposal authenticated by both enrolled identities; the controller then registers it on Solana. `POST /jobs` delivers bytes for an existing approval. `GET /jobs/:id` polls; `GET /jobs/:id/events` streams SSE results. The relay has no provisioning files or approval authority.

Workers: `/health`, `/attest`, `/proof`, `/ack`, `/begin`, `/finish`, `/result`, and `/abort`. Development servers bind loopback only. Worker configs pin authorization genesis, registry, enclave-set ID/governor, participant identities, and a state-provider domain. Each worker reads finalized registry data independently. Both local adapters use the same test validator; this does not demonstrate disjoint production RPC trust domains. Local system time is a test clock, not an authenticated hardware clock.

COMMIT records permanently authorize exactly the approved bytes. Signing can repeat; destination replay rules decide execution counts. A new blockhash or nonce requires a new approval. Response records cache a verified signature. Freezes and retirement stop future issuance after observation; they cannot invalidate a signature already produced or an extracted historical threshold.

Nonces are memory-only, single-use and limited to 64 live owners, including in-flight finishes. Finish cancellation, abort, expiry and error paths drop the owned nonce and key; the 15-second deadline also covers authorization RPC waits. Round-two shares bind the exact ordered commitments, so mixing generations of the same external attempt is refused without falsely blaming a peer. Replacement processes abort old boot contexts and start fresh attempts. Intact provisioning preserves addresses. Losing a root permanently is a different event; recovery is not implemented. Authenticated cryptographic failures stop the affected worker and surface an incident; an operator must retire/freeze affected registry state before restarting after an incident. The incident latch is now persisted beside the root file and remains set across restarts; see [durable incident handling](docs/program-jobs-and-lifecycle.md).

A local issuance lock orders confirmed control/policy/incident updates and aborts with the final authorization checks and creation of the encrypted contribution. Updates recorded first prevent issuance; contributions issued first may still be delivered after an update. This does not provide instantaneous chain revocation, cross-replica fencing, or snapshot resistance. See the [October 10 audit remediation and production blockers](docs/implementation-status.md#frost-audit-remediation-october-10-2026).

Development attestation is excluded from release builds. A worker built without `dev-simulation` refuses startup because a production provisioner is not installed. The local relay also refuses a release-mode startup. DKLS23 ECDSA and FROST RedPallas are available through the local multi-suite route. OAuth is not part of this older local route; hosted v2 supports configured OIDC issuers. Agents, Hyperliquid and root recovery remain later work. SESSION, service-key/passkey proofs and constrained SIMULATE are available locally as described below.

See [implementation evidence and remaining gates](docs/implementation-status.md).


## SESSION and application access

The controller calls `set_policy` and `grant_session` on Solana, directly or through the example controller CPI. Grants bind one derived account/path, authorization-network destination, delegate credential, recipient, per-operation lamport limit, policy version, and a validity interval of at most 24 hours. `revoke_session` is permanent; issuing a replacement uses a new ID. Policy versions advance by exactly one and invalidate old grants/proofs. Records are public; signer key packages remain memory-only.

The first destination adapter accepts only a canonical legacy Solana message containing one System Program transfer, paid and signed by the derived account. Extra instructions, lookup tables, additional signers, a different recipient, an excessive amount, an incorrect destination, and arbitrary digests are refused. This narrow adapter is intentional. Scoped EVM native-transfer sessions are available through the multi-suite API; nonce-advance instructions and other Solana operations require separate adapters.

Use `policy::solana_destination(network)` for the path destination. Construct a `Commit` as the exact-operation descriptor even for a session; it does not need to be published on chain unless registered policy requires COMMIT. Set `Authorization.policy_version` and `session_id`, compute `policy::session_challenge`, and attach a service-key signature or ES256 passkey assertion. A separately enrolled `Policy.access` credential, when configured, also requires `policy::access_challenge`. Submit through `Client::submit_authorized`; polling, SSE and receipt verification use the existing flow. Service credentials are Ed25519 proof-of-possession keys, not bearer API tokens.

Passkey assertions check the registered P-256 SEC1 public key, exact operation challenge, RP-ID hash, pinned HTTPS origin, assertion type, user presence, user verification, flags and signature. Cross-origin assertions, extensions, and attestation data in assertions are refused. Credential enrollment is an explicit controller authorization; the browser helper can create a key for controller enrollment, but this crate does not implement a server registration/attestation verification ceremony, discoverable-account login, or authenticator counter storage. A zero or repeated sign counter is not a clone-detection guarantee. See [browser assertion helper](sdk/examples/passkey-client.js). This paragraph describes the legacy session flow; hosted v2 uses a bound ephemeral-key passkey proof.

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

Attempt transcript domain v2 binds the complete public authorization envelope to MPC channels and receipts. RoundTwo additionally requires `transcript_digest = digest("pairkey/frost-commitment-transcript/v1", (attempt_digest, A_commitment_bytes, B_commitment_bytes))`, using the canonical framed Borsh digest helper. A fresh commitment pair distinguishes retries even if a caller repeats its external attempt ID; duplicates while pending or in flight are refused. Missing transcript digests are rejected. Namespace/account derivation stays v1, so existing account addresses are preserved. Old and new worker binaries must not be mixed during this local wire-format update; abort outstanding attempts and restart both workers together. The October 12 [multi-suite integration](docs/multi-suite-signing.md) adds separate routes for Spike D (COMMIT or scoped EVM SESSION) and RedPallas (COMMIT); its construction review remains open.

## DKLS23 and RedPallas local demo

With Anvil on PATH and the binaries built as above:

```sh
PAIRKEY_DEMO_MULTI_ONLY=1 target/debug/local_demo
```

This exercises account and program/CPI approvals for both suites, EVM native-transfer execution, worker replacement, approval substitution refusal and namespace freezes. Results are written to `.local/<run-id>/multi-evidence.json`. New backend key enrollment requires workers; existing Ed25519 offline derivation is unchanged. See the [scope, API, tests and remaining work](docs/multi-suite-signing.md).

## CI

After installing the pinned tools, run `bash scripts/ci.sh`. GitHub Actions runs the same gate on pushes and pull requests: source bootstrap, formatting, Clippy, host tests, fresh SBF builds, explicit registry tests, and both complete process demos. Only selected public evidence and gate logs are collected in `.local/ci-report/`; roots, identity seeds and validator ledgers are excluded.

## Program-controlled jobs and lifecycle

The application path uses a Solana controller program/PDA for authorization. DKLS23 and RedPallas now support durable submission, polling, SSE, duplicate-submission recovery and explicit cancellation through `/jobs`. Completed results survive coordinator replacement; interrupted jobs require an explicit fresh attempt. Workers persist incident latches across restarts. See [API, retry semantics, program demo and lifecycle evidence](docs/program-jobs-and-lifecycle.md) and the [Rust program client](sdk/examples/program_jobs.rs).
