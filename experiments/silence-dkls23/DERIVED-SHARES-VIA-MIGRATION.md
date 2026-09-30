# Derived shares through the audited refresh core: two registration modes

Draft design note, 2026-10-11, written by the Claude reviewer at the project owner's request. It
expands options O-B, O-C and O-C' of [DECISION-KEYGEN-OT-SCOPE.md](DECISION-KEYGEN-OT-SCOPE.md).
It is not a decision and not an approval. Native pin `af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`;
theorem source DKLs23, eprint 2023/765, version of December 14, 2023. Nothing here labels a proof
gap an exploit.

## 1. Summary

Both modes feed root-derived contributions into Silence's migration entry point, which runs the
audited refresh core. That core commits to each party's contribution before revealing it, checks
that the contributions are consistent with the expected key, runs base OT and PPRF inside the
audited protocol, and emits a complete native keyshare with fresh OT seeds and a zero seed. There
is no keyshare constructor, no share conversion, no OT pool and no custom channel carrying OT
messages.

The modes differ in one thing only: how the two parties agree on the expected public key and chain
code before the first run for a wallet.

- Mode 1 adds a small commit-then-reveal exchange to PairKey's registration. No native change.
- Mode 2 asks the library for a first-run mode without an expected key, so the native round-1
  commitment provides the ordering. This is a distinct operation in the library, not a one-field
  change; see [MODE-2-MINIMAL-SPEC.md](MODE-2-MINIMAL-SPEC.md).

Recommendation: implement Mode 1 now and ask Silence for Mode 2.

## 2. What the native core does with a derived share

Facts from the pinned source. Paths are relative to
`.local/silence-dkls23/sources/dkls23-af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src`.

| Step | Where | What happens |
|---|---|---|
| Entry | `keygen/migration.rs`, `run(setup, seed, relay, s_i_0, public_key, root_chain_code)` | Builds `KeyRefreshData { s_i_0, lost_keyshare_party_ids: [], expected_public_key, root_chain_code }` and calls `keygen::run_inner`. About forty lines plus abort handling. |
| Input validation | `keygen/dkg.rs:191-197` | Rejects an identity expected key, too many lost parties, and a zero share for a party not marked lost. |
| Constant term | `keygen/dkg.rs:209-210` | `polynomial.set_constant(s_i_0)`. The struct comment at lines 67-72 states that the shares must sum to the private key. |
| Round 1 | `keygen/dkg.rs:215-237` | Feldman commitments to the whole polynomial, including the contribution, are hashed with a random `r_i` and broadcast as the commitment. |
| Round 2 | `keygen/dkg.rs:340-378` | Polynomial commitments, `r_i`, the second commitment and DLog proofs are revealed; each commitment is recomputed and checked; the degree is checked at line 366. |
| Key check | `keygen/dkg.rs:411-419` | The public key is the sum of the constant-term commitments and must equal the expected key, else `InvalidKeyRefresh`. This happens before the peer's OT1 message is processed at line 423; the local OT1 message was already generated and sent with round 2, lines 296 to 330. |
| Chain code | `keygen/dkg.rs:332-334`, `584-594` | In refresh mode the supplied chain code is used and all parties' values must be equal. |
| OT and zero seed | `keygen/dkg.rs:296-300`, `446-450`, `463-467`, `476-480` | Base-OT and PPRF session ids derive from the final session id; the lower-indexed party samples the pairwise zero seed and sends it encrypted in round 3. |
| Final proofs | `keygen/dkg.rs:626-642` | The final DLog proofs are bound to the root chain code. |

What Spike A already does: [worker.rs:261](src/worker.rs:261) builds a keygen setup with the
request context as instance id, ranks `[0, 0]`, threshold 2 and the wallet key id, draws a fresh
seed, and calls `migration::run` with the party's contribution as `s_i_0`, the manifest's public key
as the expected key and the manifest's chain code. The contributions enter directly. The `a/2`,
`-b` conversion exists only for Spikes B and C.

Consequences:

- Removed relative to Spikes B and C: `patches/research-keyshare.rs`, the share conversion, the pool,
  the coin flip, and the custom channel for OT messages.
- Still outside Silence's audited list: the migration wrapper itself, which the upstream README marks
  as not audited although it only wraps the audited refresh core; the registration step described
  below; the duplicate-party-id and abort-preservation patches, both candidates for an upstream pull
  request; the audit-to-pin gap; and the realization of Functionality 5.1 by the compiled OT stack,
  which Silence's own flow shares.
- After the first run, every later run passes the recorded key. The native check then prevents a
  peer from changing its contribution, and the chain-code equality check prevents drift.

## 3. Mode 1: commit-then-reveal registration

### 3.1 Protocol

One ceremony per wallet, driver mediated, over the existing authenticated setup channel.

0. Both parties know the wallet key id and each other's identity. Each derives its contribution
   `c_r` from its root with the existing KDF (`src/lib.rs:64-75`) and computes `C_r = c_r * G`.
1. Commit. Each party samples a salt of at least 256 bits and sends
   `com_r = H("pairkey/registration/commit/v1", key_id, identities, r, C_r, salt_r)`.
   Before sending, it journals `(key_id, r, C_r, salt_r, com_r)` with create-new and fsync.
2. Acknowledge. Each party records the peer's commitment in the same journal and acknowledges it.
   A party reveals nothing until it holds the peer's commitment durably.
3. Reveal. Each party sends `(C_r, salt_r)`. The receiver recomputes the commitment and rejects
   any mismatch as a protocol violation attributable to the authenticated peer.
4. Derive. Both compute `Q = C_0 + C_1`, reject the identity, and derive the chain code as
   `H("pairkey/chain-code/v1", key_id)` or the existing hash of `(key_id, Q)`. Either is public.
   The key-id-only form also serves Mode 2.
5. Record and endorse. The wallet record holds the key id, both identities, both commitments, both
   points, `Q` and the chain code. Each party endorses it with its identity key, as today. The
   endorsement binds identity to the record; it carries no cryptographic weight for the key.
6. Run migration with `s_i_0 = c_r`, expected key `Q`, and the chain code.

Flights: two plus the record acknowledgement, once per wallet, then the four native flights.

### 3.2 Journal and retry rules

- A commitment for a key id is written once with create-new and is never replaced. A second
  ceremony for the same key id must reuse the journaled values.
- An honest party never reveals for a key id for which it has not journaled the peer's commitment.
- If the peer aborts after seeing the honest reveal, the peer is already bound by its commitment.
  The wallet can be completed only against that commitment. If the peer never reveals, the key id
  is retired; it is not reused with a fresh peer commitment.
- `describe` must return commitments, not contributions. Today it returns the `Hello` messages,
  which reveal the points.

### 3.3 Security argument

Functionality 3.2 receives the corrupt party's contribution before the honest polynomial is sampled.
Protocol 7.1 realizes that ordering with a commit step followed by a decommit step, and section 7
notes that no proof of knowledge is needed because the argument only requires a uniform public key
and consistent shares. Mode 1 applies the same two steps to one point per party. It is not literally Protocol 7.1, which
commits to polynomial data and sends private evaluations; the commitment functionality and the
joint output mapping have to be stated before Theorems 7.2 and 4.1 are invoked.

- Ordering. The corrupt commitment is journaled and acknowledged before the honest point is revealed,
  so the corrupt contribution is fixed first. The commitment is binding under the hash assumption.
- Uniformity. The honest contribution is a PRF of `(role, key_id)` under the root, so it is uniform
  in the adversary's view under the PRF assumption on HKDF-SHA512 with the documented salt and info.
- Consistency. The migration run aborts unless both contributions sum to `Q`, and its round-1
  commitment, degree check and final DLog proofs give the share consistency that Simulator 4.2 uses.

This meets the ordering requirement of Functionality 3.2. The complete mapping, covering the
simulator for the commitment, prior disclosures, retries and concurrent wallets, remains to be
written before Theorem 4.1 is invoked per wallet; the Functionality 5.1 question stays open beside it. Wallets under one root are independent PRF outputs. The static-corruption and
authenticated-channel assumptions of section 2.2 are inherited.

### 3.4 Changes to the current code

- `src/registration.rs`: add the commitment phase before the existing endorsement flow; reuse the
  `Prepared` journal for commitments; keep `Endorsement` as identity binding.
- `src/lib.rs`: `Hello` becomes the reveal message. Its proof challenge may stay as a sanity check
  but is no longer load bearing.
- `src/pool_driver.rs` and the process drivers: `describe` returns commitments; `register` runs
  acknowledge, reveal, derive and record.
- No native change. No parameter change. A change of chain-code derivation changes child addresses
  of existing experimental wallets; record the choice.

### 3.5 Tests

- Crash at every step on either side. Restart must either complete against the journaled peer
  commitment or retire the key id. No reveal may ever precede a durable peer commitment.
- Equivocation: a peer that reveals a point not matching its commitment is rejected and quarantined.
- Replay: a commitment from one key id or one identity pair is rejected under another.
- Determinism: repeated ceremonies for a key id produce the same record.
- Differential: the same contributions through Mode 1 plus migration, compared with a native run on
  the same inputs where the test API allows, on public key, chain code and signatures.

## 4. Mode 2: derive mode in the library

### 4.1 Behaviour

A first run for a wallet passes no expected key. The core sets the constant term to the derived
share as before, commits in round 1, reveals in round 2, computes the public key as the sum of the
constant-term commitments and continues. The output public key and chain code are persisted as the
public wallet record. Every later run for that wallet passes them as expected inputs in ordinary
refresh mode.

### 4.2 What has to change in the library

`key_refresh_data` gates eight places in `run_inner`: input validation at `keygen/dkg.rs:191`, the
constant term at 209, the chain-code source at 333, lost-party handling at 388, 509 and 571, the
expected-key check at 417 and the chain-code agreement at 584. Initial derived key generation needs
the constant-term override together with the non-refresh chain-code path at lines 333 to 337 and
596 to 601, and without the expected-key check. That is a distinct operation type with its own
validation, not an optional field on the migration wrapper. [MODE-2-MINIMAL-SPEC.md](MODE-2-MINIMAL-SPEC.md)
section 2 specifies the two operations and the chain-code policy.

### 4.3 Gating rules in PairKey

- A durable reservation keyed by root namespace, role and wallet id is written before the first
  native message. Both parties authenticate the operation kind in the request context that forms
  the instance id, so a mode mismatch fails authentication.
- One initial attempt per wallet id. After any failure, timeout or restart during that attempt the
  wallet id is retired; a retry would let a corrupt peer choose a new contribution after seeing the
  honest one. The state machine and retry table are in [MODE-2-MINIMAL-SPEC.md](MODE-2-MINIMAL-SPEC.md)
  sections 3 to 5.
- Possible relaxation, for decision: the honest party knows whether it sent its own round-2 reveal,
  and the wrapper can recognise outbound message ids, as the test probe in
  `src/pool_worker.rs:424-431` does. A retry under the same reservation would be safe only when the
  local round-2 message was never sent.
- The output record is public data, written with create-new and fsync like any other record, and
  later recoveries pass its key and chain code in ordinary refresh mode.

### 4.4 Security argument

This follows the route of Theorem 7.2 for native key generation with one change: the honest
constant term is a PRF output rather than a fresh random scalar. The native round-1 commitment
fixes the corrupt contribution before the honest reveal; the degree, commitment and DLog checks
give consistency; the PRF assumption gives uniformity. The mapping still has to be written out,
including the reservation and retirement rules above, prior disclosures and concurrent attempts.

### 4.5 How to obtain it

Ask Silence for a typed initial derived-key generation operation, with its input, chain-code and
abort contract and a coverage statement, as drafted in Q1a of
[SILENCE-REVIEW-QUESTIONS.md](SILENCE-REVIEW-QUESTIONS.md). A local patch of the audited key
generation core is not proposed.

### 4.6 Tests

- Mode mismatch between parties fails before round 1.
- A derive run against a key id that already has a record is refused locally.
- The derived public key equals the sum of the parties' public contributions and signatures verify.
- A peer that changes its contribution on a later refresh-mode run is rejected by the native check.

## 5. Comparison

| | Mode 1 | Mode 2 |
|---|---|---|
| PairKey cryptographic code | commitment exchange, small | none beyond record handling |
| Native change | none | a typed initial-keygen operation in the library |
| One-time flights per wallet | 2 plus acknowledgement, then 4 | 4 |
| Argument | Protocol 7.1 applied to one point per party | Theorem 7.2 route with a PRF constant term |
| Residual custom surface | registration code, migration wrapper | migration wrapper, patched core if local |
| Available now | yes | after Silence ships the operation |

A third variant, exchanging points in the clear and arguing security through additive key tweaks, is
recorded in the decision thread as a fallback argument only and is not developed here.

## 6. Open items common to both modes

- Ask Silence to document the migration entry point as a supported additive-share import and to
  state whether the review of the refresh core covers it.
- Pin to a Silence-vouched revision covering the post-audit refactors.
- Functionality 5.1 realization and the 2026/976 dimension question remain upstream questions.
- The chain-code and public child derivation assumptions of obligation O2 are unchanged.
- Zeroization limits in [SECURITY-REVIEW.md](SECURITY-REVIEW.md) apply unchanged.
- Any cache of native packages must check that both peers hold the same package generation before
  native signing: mismatched generations fail native consistency check 3, which the lifecycle maps
  to a configuration freeze (case 5 in [OT-POOL-REVIEW.md](OT-POOL-REVIEW.md) section 3).
