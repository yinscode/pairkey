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
  The chain authorization core now supports absent namespace/COMMIT accounts,
  verifies the pinned set and fresh observation, and preserves freeze/retirement.
  Existing custom policies require explicit owner-authored new rules before using
  the new flow. New rules also restrict legacy COMMIT/session authorization.
  Workers now fetch the rules account for legacy requests; four new chain-core
  tests, existing authorization tests and ten worker regression tests pass.
  Worker integration is now implemented: each worker privately authenticates the
  request, caches its bounded proof until expiry, and uses only a proof commitment
  in public protocol messages. JWKS are fetched only from configured HTTPS URLs.
  Durable claims precede signing nonce generation in all worker suites; policy and
  authentication are checked again before releasing output. Observing a stricter
  policy fences previously prepared requests even when the new request is denied.
  Coordinator/SDK private ingress is available. Fifteen worker tests pass, including
  actual registration-free account/Ed25519 and bound-passkey/RedPallas signing,
  invalid proofs, cached public results, cancellation and policy races. Targeted
  clippy checks pass.
  Coordinator off-chain jobs now use a separate durable journal. Both workers
  revalidate private authentication before the coordinator reserves a request;
  the original attempt is persisted before protocol work begins. Request IDs
  cannot be reassigned or retried with fresh randomness. Restart marks unfinished
  work uncertain; `/jobs/:id/recover` only reads and verifies both workers' cached
  receipts, even after approval expiry. SDK retries preserve the original job ID
  and verify matching semantic approvals and a matching receipt pair. Eight
  coordinator tests pass, including real Ed25519/RedPallas recovery, concurrent
  retries, incomplete worker results, tampered receipts and failed persistence.
  OIDC policy updates now have private worker/coordinator endpoints and SDK native
  instruction construction. An owner-bound ephemeral key signs a policy-specific
  message; both workers independently verify the configured issuer's token and the
  exact update before attesting. Only public attestations enter the transaction;
  the gateway checks revision, expiry and set status at execution. Fifteen core
  tests and sixteen worker tests pass, including real RSA-token policy management,
  wrong-action signatures, issuer configuration, changed updates and incident
  refusal. Four policy SBF tests and six legacy registry SBF tests pass against the
  rebuilt programs. The existing SBF toolchain diagnostics remain as noted above.
  Remaining integration verification must exercise the full hosted path and all
  five chain adapters; these foundation tests do not establish that rollout.
- Stage 4 in progress: additive program-source identity, caller-proof and approval
  ABI types preserve the existing program-controlled PDA as derivation authority.
  A new gateway instruction records an exact approval through that PDA without
  namespace registration. The example controller implements `pairkey_approve`
  and `pairkey_approve_commit`, owner-managed destination/path rules, and a
  persistent remaining-approvals counter. Simulation authenticates a signer-bound
  caller/context and the exact state snapshot against the application's pinned
  enclave set; it never consumes the counter. Commit atomically decrements the
  counter and records approval, with duplicate/failing CPI rolling the change back.
  Programs can also update standard rules through authenticated CPI.
  Off-chain mode pins immutable code; on-chain mode uses the committed PDA
  authorization and supports upgradeable programs. Four new SBF tests cover these
  paths, real transaction-size bounds, state changes, forged authority and fake
  enclave sets. The ten existing policy/registry SBF tests also pass.
  Expanding the instruction enum exposed a live SBF decoder stack overflow; moving
  legacy handlers into separate functions removed that diagnostic. The on-chain
  PDA curve check uses the native syscall because this SDK's Pubkey method panics
  on SBF. Existing dalek/toolchain diagnostics remain as previously documented.
  Worker integration is complete: each worker verifies the caller's exact request,
  fetches finalized application state, and runs its own signed RPC simulation or
  reads the exact gateway approval. Release checks bind the decision again, with
  durable state fences that reject stale prepared views after a newer denial.
  Three actual-SBF worker tests produce and verify FROST signatures, check that
  commit consumes the application counter exactly once, and reject forged caller
  proofs and tampered simulation results. Two additional core-context tests pass.
  Workspace tests, all-target clippy and formatting pass; the three ignored SBF
  worker tests and doc tests also pass in a serial run. CI runs this integration
  gate after building the programs.
- Stage 5 in progress: `/api/v2` now supports lazy identity metadata and derived
  keys without a registration transaction, canonical exact-message preparation,
  private authentication at both workers, durable hosted jobs, and public-only
  recovery. Existing `/api/v1` routes and keys remain compatible. No JWT, passkey
  assertion or caller signature is stored in the hosted job journal. The Rust SDK
  verifies namespace attestations, key certificates, prepared bytes, and the exact
  off-chain approval in both result receipts. Real HTTP tests with two workers
  produce signatures for Solana, NEAR, Zcash and Bitcoin; a separate native-sidecar
  test produces a DKLS EVM signature. The RPC fixture supplies finalized account
  reads only and rejects all transaction broadcasts. Tests also cover changed
  messages, invalid caller proofs, stale rules, same-request retries, recovery,
  and interrupted hosted persistence. The native hosted test is added to CI.
  Hosted policy and example-program helpers now construct unsigned owner actions,
  read current revisions and reject stale updates. OIDC provider settings are
  loaded from a private optional file and independently validated by each worker;
  no provider is enabled implicitly. Four hosted integration tests execute actual
  SBF code: wallet policy edits, native P-256 passkey policy edits followed by a
  bound-ephemeral signing request, atomic program commit followed by signing, and
  read-only program simulation through each worker's own RPC call. Simulation
  neither creates an approval account nor consumes the program's counter. These
  SBF tests are included in CI. See `docs/offchain-approval-api.md` for the versioned
  API contract, identity proof flow, policy costs and operator configuration.
  Workspace tests (including doc tests), all-target clippy and formatting pass
  after this integration; the four hosted SBF tests were also run explicitly.
  The browser v2 SDK now verifies canonical approval bytes before wallet signing,
  validates namespace attestations and transaction instructions, supports bound
  ephemeral identities, and saves public-only recovery metadata before submission.
  Rust-generated vectors cover all five chains and wallet/program management
  instructions. All 38 website tests pass, as do generated-doc/link checks,
  workspace all-target clippy and formatting. A real HTTP browser-SDK test with
  both workers signs and recovers all five suites (including native DKLS); it is
  now gated in CI alongside Node 22, vector consistency and website checks.
  Curve-specific key certificates and full receipt verification remain the Rust
  SDK's responsibility; browser Ed25519 checks do not imply full multisuite proof
  verification. Both public quickstarts now use v2: account message authorization,
  explicit program policy setup, immutable read-only evaluation or on-chain commit,
  all five chains, and recovery that cannot resubmit or consume another allowance.
  The shared page lifecycle passes all five real hosted signing/reload-recovery
  flows; 43 website tests and generated page/link checks pass. Browser inspection
  confirms the updated controls and safe missing-wallet/no-saved-job errors.
  The downloadable program now includes the typed ABI and tested application
  policy implementation, rejects legacy forwarding at its entrypoint, and builds
  outside this repository. Its extracted SBF binary passes the four approval tests;
  CI builds and tests that exact archive. Existing dalek/SBF diagnostics remain as
  noted above. The offline verifier now requires the original v2 approval and
  still verifies legacy transcripts. Its regression test and workspace clippy pass.
  The public docs and message demo now use the same v2 lifecycle. The demo connects
  visitor wallets, supports explicit program setup and approval mode selection,
  derives all five destination keys, and records public-only tab-local history.
  Signer cards only show completion after the matching result and receipts return;
  recovered saved metadata is not presented as fresh verification. The Verify
  button checks the displayed inputs through the service, and the transcript can
  be verified independently with the Rust example. Forty-five website tests,
  generated-site/link checks, and Rust formatting pass. Manual browser QA against
  two real development workers and actual program SBF on an in-memory chain
  completed account and program signing, accepted the original signature, rejected
  a changed message, and recovered the original account job. The fixture completed
  exactly two jobs and was shut down. Download serving now includes ZIP and Rust
  source MIME types, exercised by the hosted browser integration test.
  A configured production OIDC issuer has not been exercised through the hosted
  HTTP path; complete isolated HTTPS issuer coverage and rollout review remain.
- Stage 6 remains open: complete the hosted program and bound-identity paths,
  full CI, website checks and deployment readiness review. These changes are not
  deployed; do not deploy the gateway separately as a feature.
