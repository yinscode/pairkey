# Spike D brief for Sol: derived keys through native migration, bounded native OT reuse

2026-10-11, written by the Claude reviewer at the project owner's request. Spike D is an experiment
in the same tree as Spikes A, B and C. It is not a production design and makes no security claim
beyond what its tests show. Read first: [DERIVED-SHARES-VIA-MIGRATION.md](DERIVED-SHARES-VIA-MIGRATION.md)
Mode 1, [MODE-2-MINIMAL-SPEC.md](MODE-2-MINIMAL-SPEC.md) sections 3 to 5 for the state machine,
[OT-POOL-RULES.md](OT-POOL-RULES.md), [SHARE-FLOW-AND-OT-REUSE.md](SHARE-FLOW-AND-OT-REUSE.md), and
the failure mapping in `src/lifecycle.rs:96-156`.

## 0. What Spike D is

Spike A's migration route, hardened into a complete flow:

1. Each party derives its additive contribution from its root, as today.
2. The two parties fix the wallet key through a minimal commit-then-reveal exchange, then run native
   `migration::run` with the contribution, the agreed key and the chain code. The audited refresh core
   commits to the contribution in round 1, reveals it in round 2, checks the key, runs base OT and PPRF,
   and returns a complete native keyshare: shares at native random coordinates, both OT seed sets, the
   zero seed and a session id.
3. The keyshare is held in RAM only and reused for native signing up to a bound, then rotated through
   native `key_refresh::run`, which regenerates shares, OT seeds and zero seed for the same key.
4. Restart, expiry, the use bound, or any incident discards the cache; recovery is migration again
   from roots and the public record.

What D removes relative to C: the research constructor, the share conversion, the pool, the coin flip,
the custom channel carrying OT messages. What D adds relative to A: registration ordering, a cache and
reuse controller, generation agreement, hedged seeds, journals, and the failure policy.

**No donor and no seed sharing across wallets in D.** Migration already yields audited per-wallet OT
seeds, so a DKG donor would only be needed to share one seed set across wallets, and that requires a
splice or constructor, which is exactly what D removes. If flat cold-wallet latency is required later,
pre-warm the expected wallets after boot rather than share seeds; a shared-seed design is a separate
spike with the pairing-wide rules in OT-POOL-RULES.md section 6.

## 1. Non-negotiables

- No change to native parameters, algorithms or dependency versions. No new native patches. D must not
  depend on the constructor hunk; the duplicate-party-id and abort-preservation hunks stay as they are.
- No `pre_signature` and `finish` split. One `sign::run` per attempt, message known beforehand.
- No deterministic seeds anywhere. Entropy from the OS for every protocol run, hedged as in section 2.5.
- Every protocol run uses fresh randomness and a new instance id. Nothing is resumed.
- Secrets persisted: roots only. Keyshares, seeds and signing state live in RAM and are zeroized.
- Testing in an isolated snapshot with separate target and evidence directories, as `bootstrap.sh`
  does. Do not edit other reviewers' documents. Keep A, B and C working.

## 2. Design

### 2.1 Derivation

Introduce derivation version 2 for D wallets: HKDF info over a version label, a pairing identifier
derived from the ordered identity pair, a namespace label, a root epoch, the role and the wallet id.
Keep version 1 for existing experimental wallets. Rationale: today the same root, role and wallet id
reproduce the contribution with any peer, `src/lib.rs:64-75`.

### 2.2 Registration, Mode 1

One ceremony per wallet, over the authenticated setup channel, driver mediated.

- Reserve: journal `(pairing, role, wallet id, attempt id)` with create-new and fsync before anything is
  sent. One live ceremony per wallet id.
- Commit: send `H("pairkey/registration/commit/v2", key_id, identities, role, C_r, salt)`, salt of 32
  random bytes, after journaling `(C_r, salt)` locally.
- Acknowledge: journal the peer's commitment; reveal nothing until it is durable.
- Reveal: send `(C_r, salt)`; verify the peer's reveal against its commitment; a mismatch is a peer
  violation.
- Derive: `Q = C_0 + C_1`, reject identity; chain code by the existing public rule over the wallet id and
  `Q`.
- Record: wallet id, identities, roles, both commitments, both points, `Q`, chain code, versions, no
  coordinates. Both parties endorse with their identity keys, as identity binding only. Store under the
  prepared and committed journal flow that already exists in `src/registration.rs`.
- Retry rules: after the local reveal was sent, the wallet id is completed only against the committed
  peer value or retired; a retry with a new peer commitment is refused; `describe` returns commitments,
  never points; `Hello` no longer carries the contribution.

### 2.3 Key establishment

`migration::run(setup, seed, relay, contribution, Q, chain_code)` with a `SetupMessage` whose instance
id is the digest of the creation context: record digest, operation kind, attempt id. The returned
keyshare's `final_session_id` is the generation id; both parties exchange it and confirm equality
before the generation is usable. Store the generation id in the public record's operational metadata,
not in the record itself.

### 2.4 Cache and reuse controller

- RAM map keyed by `(pairing, wallet id, generation id)` holding the native keyshare in a zeroizing
  owner, a use counter and a creation time.
- Limits, configurable, defaults: 1,000 signatures or 24 hours per generation, whichever first. These
  are hygiene bounds, not cryptographic ones; document them as such and never claim an unlimited
  lifetime.
- Generation agreement before every `sign::run`: the pre-sign exchange carries the generation id; a
  mismatch discards both sides' cache entries for that wallet, is classified as a context burn, and
  leads to a joint rotation. This is incident safety, not only availability: mismatched generations
  fail native consistency check 3, which the lifecycle maps to a configuration freeze.
- Rotation: `key_refresh::run` with `KeyshareForRefresh::from_keyshare(&cached, None)` when a cache
  entry exists on both sides; `migration::run` from roots otherwise. Both parties switch generation only
  after exchanging and confirming the new id; the old entry is zeroized and its id retired.
- Discard on: use bound, age bound, restart, any incident, any failed rotation, explicit operator
  request.

### 2.5 Signing

- Seed per attempt: `H("pairkey/sign-seed/v2", 32 bytes from OsRng, context digest, attempt counter)`
  truncated to the native seed size. Entropy stays in; the context makes a repeated entropy draw harmless
  for a different message.
- Instance id: digest of record digest, generation id, chain path, prehash, attempt id. Journal the
  instance ids received from the peer with create-new files under the pairing scope and refuse repeats.
- Persist and fsync a per-pairing attempt counter before round 1; refuse to sign on counter regression.
- After `sign::run`: verify the signature against the derived public key, require low-S, check the
  recovery id, as `src/pool_worker.rs:443-450` does.

### 2.6 Failure policy

| Native error | Classification | Action, scope is the pairing |
|---|---|---|
| `AbortProtocolAndBanParty`, `InvalidMessage`, `InvalidCommitment`, `InvalidDigest`; migration and refresh `InvalidMessage`, `InvalidCommitmentHash`, `BigFVecMismatch`, `PPRFError`, DLog failures | peer violation | quarantine the peer for every wallet, cut every concurrent session, drop all cached keyshares of the pairing, retire their generation ids |
| `FailedCheck`, `K256Error`, `InvalidPreSign`, migration `InvalidKeyRefresh` | aggregate, unattributed | freeze the pairing configuration, stop concurrent sessions, drop caches, investigate |
| `InvalidFinalSessionID`, channel context mismatch, generation mismatch | context | burn the attempt, drop the wallet's cache on both sides, reconcile and rotate |
| `AbortProtocol`, `MissingMessage`, `SendMessage`, timeouts | transport | burn the attempt; rate-limit per peer; a cluster within a window triggers rotation of the affected wallets |

Reuse the shared incident authority, `ReleaseGate` and `pair_scope` in `src/lifecycle.rs`, so A, B, C
and D share one quarantine state; a route change must never clear an incident.

## 3. Safeguards checklist, with where each is enforced

1. Commit-before-reveal with durable reservation: registration module and journal, section 2.2.
2. Retirement of a wallet id after a revealed-then-failed ceremony: journal state machine.
3. Derivation bound to pairing, namespace, epoch, version: `Root::derive_v2`.
4. Fresh hedged seed per protocol run, consumed by value: signing and migration call sites.
5. Instance-id journal and attempt counter: wrapper around every native run.
6. Generation agreement before signing and before switching generations: pre-sign exchange.
7. Reuse bound and age bound: cache controller.
8. Failure policy with pairing scope and concurrent cutoff: lifecycle mapping; build the concurrent
   cutoff even if the first worker is sequential.
9. Zeroization of keyshares on discard, rotation and exit: zeroizing owners; `Keyshare` already zeroizes
   on drop.
10. No snapshot or restore of signer processes: a documented deployment requirement, plus the counter and
    journals as detectors; the test suite must include a replay drill.
11. Both roots never co-located outside tests: fixture-only exception, asserted in the driver.
12. Output verification before release: signature, low-S, recovery id.

## 4. Tests and validations

Unit and property tests:
- Derivation v2 vectors; different pairing, namespace or epoch changes the contribution; v1 untouched.
- Commitment binding and hiding; reveal against a wrong commitment rejected; replay of a commitment under
  another wallet id or identity pair rejected.
- Journal crash-at-every-step for reserve, commit, acknowledge, reveal, record, in the style of
  `src/reservation_tests.rs`; no reveal before the peer's commitment is durable; a revealed-then-failed
  wallet id is retired; two concurrent first attempts produce one ceremony.
- Migration refuses a wrong expected key or chain code with the expected native error and classification.

Reuse, rotation and cache:
- Use bound: the N plus first signature is refused on both sides and triggers rotation; age bound likewise.
- Rotation through refresh preserves `Q` and chain code, changes the generation id, and the old generation
  is refused afterwards; cross-generation mixing between peers is refused before `sign::run` and, if
  forced past the agreement in a test, fails native check 3 and is classified as a freeze.
- Restart drops the cache and recovery through migration reproduces the public record exactly.

Adversarial, in a scratch copy, using `sl_mpc_mate::coord::adversary` and a modified `run_inner`:
- Malicious peer during migration: wrong polynomial degree, inconsistent commitments, a different
  contribution on a retry after the honest reveal, a replayed round-1 session id; assert the classification,
  the pairing-wide quarantine and that the honest contribution was never revealed twice under different
  peer commitments.
- Malicious peer during signing: the existing injected faults plus a replayed round-1 message against a
  party whose seed is deliberately repeated by the test; assert the instance-id journal refuses it.

Replay and randomness drills:
- Repeat a seed in the test harness and assert the peer refuses the repeated instance id and that the
  hedged seed differs when only the prehash differs.
- Attempt counter regression refuses signing.

Soak and uniqueness:
- At least 1,000 signatures across several wallets with concurrent sessions, asserting all instance ids
  distinct and, through a test-only hook on the native setup, all final session ids distinct; seeds
  byte-identical throughout a generation.

Regression probes carried over from `review-evidence/`: the choice-XOR negative control, the
selective-abort probe in its multi-trial form, the layout test adapted to native keyshares.

Assurance driver: a D route in the fault schedules with the same expected diagnostics and incident
expectations as A, extended with generation mismatch, use bound, rotation and replay cases; `clippy`,
`fmt`, both feature modes.

Measurements for the REVIEW.md table: flights and medians for first signature per wallet per boot,
later signatures, rotation, at 0 and 50 ms injected delay.

## 5. Evidence and acceptance

- Isolated snapshot runs with logs, `terminals/` records and evidence directories, as for A, B and C.
- A `SPIKE-D-REPORT.md` with: the exact flow and flights, the test inventory with counts, the
  measurements, the failure matrix as implemented, the list of custom code with line counts, and an
  explicit statement of what remains open.
- Acceptance: all tests green in both feature modes; the adversarial suite classifies every case as
  specified; no secret is persisted; the native patch set is unchanged; A, B and C still pass.

## 6. Out of scope and open items to carry

Out of scope: production attestation and provisioning, cross-host incident authority, snapshot
resistance beyond detection, proactive security against eventual compromise of both roots, any parameter
or dependency change.

Open items to carry into the Silence questions, not to resolve here: migration as a supported
additive-share import with coverage; a typed initial derived-keygen operation; the compiled OT stack's
realization of Functionality 5.1 and any usage bound for seed reuse; the 2026/976 reconciliation.

## 7. Suggested order

1. Derivation v2 and registration Mode 1 with journals and crash tests.
2. Migration call with generation agreement; single signature end to end.
3. Cache controller with bounds, rotation through refresh, discard rules.
4. Hedged seeds, instance-id journal, attempt counter, replay drills.
5. Failure policy and concurrent cutoff; adversarial suite.
6. Soak, measurements, driver schedules, report.

## 8. Why registration remains, with migration or refresh

Both entry points are key recovery, not key creation. `migration::run` takes the expected public key
and chain code as arguments; `key_refresh::run` takes a `KeyshareForRefresh` whose `public_key` and
`root_chain_code` are required fields. Both enter the same `run_inner`, which rejects an identity
expected key before round 1 (`keygen/dkg.rs:191-197`) and aborts right after round 2 unless the
committed contributions sum to the expected key (`411-419`), and which requires both parties to
supply the same chain code (`584-594`). Lost-share recovery does not help: `cond2` rejects any lost
party when the lost count exceeds `N - T`, which is zero for two of two.

So before the first run for a wallet the parties must have exchanged their public contributions and
agreed on the key and chain code. That exchange is the registration of section 2.2, and it must be
commit-then-reveal because the native round-1 commitment comes too late to order an exchange that
already happened in the clear. Refresh changes nothing here; it only adds a fabricated Shamir share
for the wrapper to multiply back into the contribution.

| | Migration | Refresh |
|---|---|---|
| Needs agreed key and chain code first | yes | yes |
| Takes the contribution as | the additive scalar | a fabricated share at an agreed coordinate |
| Entry point on the README's audited list | no | yes, but the from-parts constructor is not DKG output |
| Core that runs | `run_inner` with `KeyRefreshData` | the same |

The only way to remove the pre-run exchange is Mode 2, a first-run mode in the core that accepts no
expected key, which needs Silence's change and keeps the reservation-and-retire journal, since an
aborted first run has already revealed the honest point. After the first run no route registers
again: recovery and rotation pass the recorded key and chain code and the native check enforces them.
