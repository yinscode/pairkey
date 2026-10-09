# Off-chain approval implementation

Branch: `codex/offchain-approval`. Commits are intentionally dated October 9–10,
2026, at the user's request. Existing unrelated working-tree changes are excluded.

## Decisions

- No registration transaction in the new signing flow. Workers still construct
  and validate public key metadata; existing derivation inputs and keys stay stable.
- Account owners sign the exact request. Passkeys and OIDC authenticate a bound,
  short-lived Ed25519 key, which signs the exact request. Scoped sessions are deferred.
- Ordinary policies are compact Solana records, optional until configured. Each
  signer independently reads and enforces them. Updates reuse the record and
  increase its revision. An RPC failure is never interpreted as an absent policy.
- Custom `pairkey_approve` code is deployed on Solana and evaluated through RPC
  simulation. Off-chain code cannot be submitted to ordinary Solana simulation.
- `pairkey_approve_commit` is used when approval changes persistent state. A
  simulation cannot safely consume a nonce, cumulative budget, or one-time allowance.
- Message signing covers Solana, EVM, NEAR, Zcash, and Bitcoin. Destination and
  message rules do not imply transaction parsing or cumulative spending limits.
- Preserve the legacy registration, COMMIT, session, receipt and journal formats.
  Introduce versioned new authorization data without silently changing old digests.

## Commit-sized stages

1. **Authorization foundation**: canonical request/source/binding types, bounded
   standard rules, account and passkey authentication, exact-message and expiry tests.
2. **Policy management**: optional registration-free policy records, monotonic
   revisions, wallet updates, passkey P-256 precompile updates, dual-signer attested
   OIDC updates. Test wrong owners, stale revisions and malformed native proofs.
3. **Independent signer enforcement**: registration-free observations, account and
   bound-identity authentication, OIDC issuer/audience/JWKS validation, fresh policy
   checks at release, durable request claims at both workers and coordinator.
4. **Program approvals**: authenticated caller context and read-only simulation ABI,
   program/code/account binding, atomic on-chain approve-and-commit example.
5. **Hosted integration**: public SDK/API, lazy key setup, recovery-safe retries,
   account/program quickstarts and demo, identity configuration and documentation.
6. **Integration verification**: all five suites, concurrent/restart/uncertain
   outcomes, old-flow compatibility, website checks and deployment readiness notes.

## Security and rollout requirements

Every approval binds the namespace, exact committed bytes, destination/path,
request ID, source, policy revision/digest and expiry. Every worker verifies
authentication independently; a coordinator's approval is insufficient. Bound
ephemeral keys cannot substitute an unrelated JWT or passkey assertion.

Program simulation authenticates real callers rather than trusting a transaction's
signer flags. Simulation depends on RPC correctness and is not atomic with signing
or later destination-chain execution. Persistent state transitions use commit.

Policy and replay fences must survive process restarts. An uncertain signing
attempt cannot be retried with fresh protocol randomness as a new request. Local
persistence is not distributed rollback protection. Existing signing roots,
namespace addresses, journals and incident latches must not be reset.

The live deployment uses development workers. New code must not imply production
TEE attestation or live OIDC integration before the relevant configuration and
verification exist. Deployments require checking for active jobs and preserving
all private runtime state. Do not run the migrated local testnet worker state.

## Progress

- Branch created; legacy formats and enforcement paths inspected.
- Stage 1 complete: additive types and account/passkey authentication; six tests
  pass with `cargo test -p pairkey-core -p pairkey-types --locked --offline`.
  These primitives are not yet connected to signer release or hosted endpoints.
  OIDC proof verification remains disabled until stage 3.
- Stage 2 complete: optional `rules` PDAs, account-signed updates, native P-256
  passkey updates and dual-identity attested OIDC updates. Passkey identities use
  canonical compressed SEC1 keys; legacy credential encodings remain unchanged.
  Same-size policy edits preserve the rent deposit, and no deletion fallback exists.
  Four new SBF tests and six existing registry SBF tests pass. The 27 relevant host
  tests pass (HTTP loopback tests require running outside the filesystem sandbox).
  CI runs the new SBF tests after building programs. The SBF toolchain still emits
  its existing dalek stack/syscall diagnostics; these exercised program paths pass
  in LiteSVM. This is not evidence that every unused compiled path is safe.
- Stage 3 in progress: configured-issuer RS256 ID-token verification now binds
  issuer, audience, subject, token nonce, ephemeral key and exact request. It uses
  ring for RSA verification and strict typed claims, including rejecting present
  null/mistyped optional time claims. Ten core tests pass, including real RSA
  signatures over malformed claims. JWKS fetching and signer integration remain.
  A separate durable approval store now persists request/attempt claims before
  issuance, makes interrupted work uncertain on restart, recovers completed public
  results, and preserves policy, clock and negative-control fences. Four store
  tests cover concurrency, restarts, mismatched retries and storage failures.
  Authentication proofs must travel privately; public receipts contain only their
  commitment, never an OIDC token. The store and proofs still need worker integration.
- Stages 4–6 pending. The new policies are not yet enforced by running signers or
  exposed through the hosted UI; do not deploy the gateway separately as a feature.
