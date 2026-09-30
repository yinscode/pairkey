# OT pool review: results

Review performed 2026-10-11 by the Claude reviewer against the plan in
[OT-POOL-REVIEW-COVERAGE.md](OT-POOL-REVIEW-COVERAGE.md); revised the same day after Astra's
reconciliation in `356ac2c` and the minimal review specification. Code reviewed: the working tree at
`1a507bc`, whose non-documentation files are identical to `73f318a`, the native pin
`af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7` with the five PairKey hunks applied, and
`sl-oblivious 1.0.0-beta` from the registry. Theorem source DKLs23, eprint 2023/765. This is an
internal source review with test evidence. It is not an audit, it does not prove that the compiled
OT stack realizes Functionality 5.1, it does not establish security against a peer that chooses
setup messages, aborts and later wallets adaptively, and it asserts no exploit.

## 1. Verdict

Every row of the coverage matrix that was marked closable is closed as implementation evidence: by
source comparison, by existing tests, or by the test written for this review. No defect was found in
the pool's composition relative to Silence's native rounds. Two statements in the first version of
this review were wrong and are corrected below: the per-signature index of the zero shares is
`digest_i`, not the package-bound final session id, and native signing has no duplicate round-1
session-id check. One expectation in the coverage matrix was wrong and is corrected: reservation
precedes agreement and retires the entry. The malicious-composition obligations O3 and O4 are not
closed by any of this; under the migration route they become not applicable rather than proven.

| Row | Result |
|---|---|
| Base OT | Equivalent to native rounds OT1 and R3: same calls, same decode-then-process validation, same session-id argument order, fresh OS randomness. |
| PPRF | Equivalent: same `build_pprf` and `eval_pprf` calls, same direction convention, proof failure is a peer violation on both sides. |
| Session ids | Unique per generation and entry, direction-separated, same value on both sides, burned on disk before the first OT message. |
| Zero seed | Stored where native signing reads it; signs cancel; the per-signature index is `digest_i`, the hash of both parties' round-1 session ids and nonce commitments, not the package id; a mismatch fails native check 3. |
| Seed-to-role mapping | Matches native: the signing receiver uses the sender seed and the signing sender uses the receiver seed, from the same base-OT instance. Mismatched material is detected and attributed. |
| Consumption binding | The package id reaches the native final session id and both MtA session ids, and the channel itself is keyed by the consumption digest. The zero-share index does not include it. A disagreement retires the entry; it does not return it. |
| Single use | Reserve removes before validation; a create-new, fsync'd ledger file per entry under an OS lock; generation destroyed on any failure; crash points tested. |
| Transport | DH keys authenticated by identity-signed boots, contributory check, per-context HKDF key, AEAD with context, sender and label bound, replay excluded by construction. |
| Randomness | OS randomness per coin, per OT instance, per signing seed, per process DH key. |
| Keyshare assembly | Test: native and constructor layouts agree byte for byte outside the fields that differ by design; rebuilt keyshares sign; an identity splice of the OT region signs; one-sided splices, mixed material and mismatched seeds are rejected with typed errors. |
| Failure attribution | Peer-attributable failures quarantine the peer; context and timeout failures burn without attribution, including a withheld coin reveal; aggregate check failures freeze the configuration. Driver schedules assert each diagnostic and the incident expectation. |
| Zeroization | As documented in SECURITY-REVIEW.md; no change. |

## 2. Row-by-row evidence

Paths: `src/...` is `experiments/silence-dkls23/src`; `keygen/...` and `sign/...` are the native pin
under `.local/silence-dkls23/sources/dkls23-af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src`.

### 2.1 Base OT

- Pool, `src/pool_worker.rs:125-141`: `EndemicOTReceiver::new(&base_ot_sid(role, peer), &mut msg1, &mut OsRng)`; peer `msg1` decoded with a length-checked `bytemuck` read, then `EndemicOTSender::process(&base_ot_sid(peer, role), &decoded, &mut msg2, &mut OsRng)`, decode errors mapped to a peer violation.
- Native, `keygen/dkg.rs:296-330` and `446-460`: identical calls with `get_base_ot_session_id(msg1 sender, msg1 receiver, final_session_id)` and the protocol RNG; `process` errors map to `InvalidMessage`.
- Argument order: the native helper takes the message sender first, which is the OT receiver; the pool's `base_ot_sid(receiver, sender)` puts the OT receiver first. Same canonical order on both sides.
- `endemic_ot.rs:134-180` validates every received point and rejects decode failures; `h_function_2` omits the session id in both uses. Inherited, not introduced.

### 2.2 PPRF

- Pool, `src/pool_worker.rs:143-176`: `build_pprf(&pprf_sid(role, peer), &sender_output, &mut sender, &mut pprf)` and `eval_pprf(&pprf_sid(peer, role), &receiver_output, &pprf, &mut receiver_seed)`, error mapped to a peer violation.
- Native, `keygen/dkg.rs:463-470` and `538-549`: `get_all_but_one_session_id(builder, evaluator, final_session_id)` in the same orientation; `eval_pprf` error becomes `PPRFError`, which the lifecycle maps to a peer violation.
- `all_but_one.rs:226` rejects an invalid proof. The driver schedule `truncated-pprf` asserts the diagnostic "invalid pool PPRF length" and an incident, `src/pool_driver.rs:728`, `767-773`; results recorded in `results-assurance.json` under `pool/refusals`.

### 2.3 Session ids

- `src/pool.rs:91-115`: the input digest covers version, recipe, both identities, both boot generations, the configuration digest and the entry id; `sid(label, a, b)` hashes the digest with both roles under distinct labels for base OT and PPRF.
- Uniqueness: `src/pool.rs:462-486` refuses a repeated entry id in a generation and caps a generation at 1024 ids; `src/pool_worker.rs:294-301` burns the setup id in the on-disk `pool-setups` ledger before any OT message, so a crash cannot replay it; boots change the digest across restarts; `restart_discards_unused_pool_and_setup_ids_remain_burned` in `src/pool_tests.rs:367` covers the restart case. This is a structural argument; a finite collision search would not prove it.
- Both sides derive the same id because the channel is keyed by the input digest: a differing input fails authenticated decryption, `src/wire.rs:318-329`.
- Relation to TOB-SILA-5: both directions and both primitives have distinct ids.

### 2.4 Zero seed

- Pool, `src/pool_worker.rs:85-123`: commitment `H(label, input digest, role, coin)` over a 32-byte random coin, reveal, verification, combination `H(label, input digest, coin_0, coin_1)`. Both coins enter the transcript, so the completed digest and therefore the package id commit to the seed.
- Placement: the constructor writes `each(0).zeta_seed` for both parties. Native signing, `sign/dsg.rs:876-914`, reads `each(0)` for both parties and returns `-H` for party 0 and `+H` for party 1. Native DKG stores the seed in the same slot, `keygen/dkg.rs:476-480` and `556`; the test confirms both zeta slots match byte for byte.
- Index, corrected: `get_zeta_i` is called at `sign/dsg.rs:234` with `digest_i`, computed at lines 169 to 183 from the DSG label, both parties' round-1 session ids and nonce commitments. It does not include the keyshare's final session id or the package id. It is fresh per signature because each party's own round-1 session id is fresh, and both parties check agreement on it in round 3 at line 393.
- Native lets the lower-indexed party sample the seed alone; the pool's coin flip is closer to the paper's commit-and-release. For two parties the shares are negatives of each other, so neither variant hides anything from the peer, and the 2026 reference notes that the zero-sharing functionality is unnecessary in this setting.
- Abort, corrected: a withheld reveal surfaces as a command timeout, `src/pool_worker.rs:510`, which is a burn; `src/lifecycle.rs:302` publishes no incident for a burn. The generation is destroyed, the peer is not quarantined, and the driver schedule `setup-timeout` asserts exactly that. Treating adversarial seed selection by repeated aborts as of no known value is an argument from the two-party structure, not a proof covering every abort strategy.
- Mismatch behaviour: the test shows a differing seed fails as `FailedCheck("Consistency check 3 failed")` on both sides, which the lifecycle maps to `FreezeConfiguration`.

### 2.5 Seed-to-role mapping

- Native signing, `sign/dsg.rs:183-200`: the MtA receiver uses `keyshare.sender_seed(peer)`; `sign/dsg.rs:283-300`: the MtA sender uses `keyshare.receiver_seed(peer)`; accessors at `keygen/keyshare.rs:327-333` read `other(peer).send_ot_seed` and `recv_ot_seed`.
- Native DKG writes `send_ot_seed` while acting as EndemicOT sender, `keygen/dkg.rs:463-470`, and `recv_ot_seed` while acting as receiver, `538-549`. The pool's `Material::new(sender, receiver_seed, zero)` and the constructor's `other_mut(1 - party)` reproduce this, `src/pool_worker.rs:210`, `patches/research-keyshare.rs`.
- Test: material taken from an independent run for one party, and a one-sided byte splice of the OT region, both make both sides fail with `AbortProtocolAndBanParty`, which the lifecycle maps to a peer quarantine. `pool_consumption_moves_seeds_into_one_bound_native_package`, `src/pool_tests.rs:217`, covers the positive path with pool material.

### 2.6 Consumption binding

- `src/pool.rs:227-248`: the consumption digest covers the input digest, the completed digest, the entry, the wallet record digest, scheme, path, prehash, receipt, policy version and attempt; the package id is `H(label, completed, consumption digest)`.
- `src/pool.rs:395-432`: the constructor receives the package id as the keyshare final session id and the consumption digest as extra data; `src/pool_worker.rs:402-405` re-checks the extra data; `414-423` uses the consumption digest as the native instance id.
- Native, `sign/dsg.rs:162-167`: the final session id hashes both parties' round-1 ids and the keyshare final session id; `1061-1075` derives both MtA ids from it; `283-285` and `368` reject round-2 and round-3 messages carrying a different final session id; `139-152` rejects duplicate or out-of-range party ids. The zero-share index `digest_i` is separate and does not include the package id. There is no duplicate round-1 session-id check; freshness of both per-signature values rests on each party's own fresh round-1 id, and agreement on them is enforced at lines 283, 368 and 393.
- Agreement: `src/pool_worker.rs:381-391` keys the channel with the consumption digest and exchanges it. The reservation at line 365 removes the entry before this exchange, and the code comments say so. A disagreeing peer therefore costs one entry. The property that matters, no entry used twice, holds; `provenance_and_consumption_mismatches_burn_without_unreserve`, `src/pool_tests.rs:267`, asserts the retirement.

### 2.7 Single use and ownership

- `src/pool.rs:494-530`: reservation finds the entry, removes it before any fallible step, writes the ledger record, then checks provenance against the consumption.
- `src/lib.rs:354-390`: the ledger record is a create-new file named by role and entry under an OS authority lock, written, fsync'd, with the directory fsync'd; `reservation_tests.rs` drives every `ReserveStep` crash point and `PackageStep::ShareDerived` and `Constructed`.
- `src/pool_worker.rs:512-519`: any command failure invalidates the generation and drops all unused entries; `src/pool.rs:366-383` gives entries a 300-second life; capacity is 2 per generation, `src/pool_worker.rs:487`.
- Existing evidence: `concurrent_reservation_has_one_winner_and_cancellation_stays_retired`, `bounded_pool_expiry_empty_and_wrong_generation_fail_closed`, `incident_fences_reserved_packages_and_discards_available_material`, `concurrent_refill_incident_and_reservation_share_release_cutoff` in `src/pool_tests.rs`; `native_pooled_ownership_after_reservation_and_construction_refuses_reuse_and_release` in `src/extended_process_tests.rs:468`; the process suites in `src/pooled_process_tests.rs`. My isolated reproduction at `73f318a` ran the suite green with 83 distinct tests.
- Outside the model, unchanged: a restored VM snapshot revives RAM and the pool with it.

### 2.8 Transport

- `src/wire.rs:246-343`: X25519 between the process's per-boot static key and the peer's boot key, with the contributory check; HKDF-SHA256 with a fixed salt and the context as info; ChaCha20-Poly1305 with a fresh 96-bit nonce per message and associated data `(context, sender role, label)`.
- Authentication of the DH keys: each boot is signed by its root identity and verified at enrollment, `src/pool.rs:140-146` and `src/pool_worker.rs:479-481`; the signing path also checks that its own advertised key was not substituted, `src/pool_worker.rs:347-350`.
- Replay: one message per label and direction per context; a different context means a different key; a wrong label fails the associated data. Decryption failure is a context burn, not an attribution; a post-authentication parse failure is attributed to the peer.
- Nonce volume: at most a handful of messages per key, so random nonces are appropriate here. This differs from the long-lived single-key database the NEAR audit criticised.

### 2.9 Randomness

- `src/lib.rs:28-31`: `fresh()` reads 32 bytes from the OS. Coins, nonces, signing seeds and the per-boot DH key use it; both EndemicOT roles use `OsRng` directly. No RNG state is shared between entries or between the OT and PPRF steps.

### 2.10 Keyshare assembly

- Constructor checks: party in range, non-zero share, non-identity key and public shares, distinct public shares, `2·S_0 - S_1 = pk`, `s·G = S_party`, then a fixed layout with ranks 0, coordinates 1 and 2, the pair seed in `each(0)`, and both OT seeds in `other(1 - party)`.
- Test, section 3: against a native two-party DKG keyshare, the rebuilt keyshare is byte-identical in the header outside the share field, in both rank bytes, in both zeta slots, in the entire 65,600-byte OT seed region and in the extra data. The coordinate and public-share fields differ by design because native DKG draws coordinates at random, `keygen/dkg.rs:213`. The rebuilt keyshares sign under native `sign::run` and both signatures verify. A byte-level identity splice that keeps every native field and replaces only the OT seed region with another run's consistent region also signs; the same splice on one side only is rejected.

### 2.11 Failure attribution

- Preprocessing: commitment mismatch, decode failures, OT and PPRF errors and a completed-digest disagreement are `Failure::violation(Phase::DirectSetup, peer, ...)`, which carries `Action::QuarantinePeer`, `src/lifecycle.rs:96-107`. Channel decryption failure and timeouts are burns, and a burn publishes no incident, `src/lifecycle.rs:302`. The driver schedule asserts the diagnostic for each injected fault, an incident for the attributable ones and no incident for `setup-timeout`, `src/pool_driver.rs:725-780`.
- Signing: `src/lifecycle.rs:108-130` maps `AbortProtocolAndBanParty`, `InvalidMessage`, `InvalidCommitment` and `InvalidDigest` to a peer quarantine, session-id disagreement to a context burn, and `FailedCheck` to a configuration freeze. The test produced `AbortProtocolAndBanParty` for mixed and one-sided OT material and `FailedCheck` for a mismatched zero seed and for mismatched share generations.
- Scope: quarantine is keyed to the pair of identities and the configuration version, `src/lifecycle.rs:160-175`, shared by all routes. Which configuration changes may ever clear an incident, and under what authority, is a policy question for Q5, not something this review decides.

## 3. Evidence

A test module appended to a scratch copy of the patched native crate, outside the repository, run
with `cargo test --offline` against the registry cache. Provenance: native pin `af5ada2a`, the
patched source extracted by `bootstrap.sh` at `73f318a`, workspace members removed from the
scratch `Cargo.toml` so the crate resolves offline, Cargo target and `TMPDIR` under the scratch
directory. Source and filtered log are saved in `review-evidence/`. Five cases, each with exactly two
completed outcomes under a 60-second bound, fresh key material per case, typed error assertions on
negatives with no accepted signature, and explicit `verify_prehash` plus recovery-id checks on
positives:

```
case 1: layouts agree outside x_i/big_s/s_i; 2 verified signatures from rebuilt keyshares
case 2 (mixed OT material): [Err(AbortProtocolAndBanParty(1)), Err(AbortProtocolAndBanParty(0))]
case 3 (zero seed mismatch): [Err(FailedCheck("Consistency check 3 failed")), Err(FailedCheck("Consistency check 3 failed"))]
case 4 (identity splice, consistent seeds both sides): 2 verified signatures
case 4b (one-sided splice): [Err(AbortProtocolAndBanParty(1)), Err(AbortProtocolAndBanParty(0))]
case 5 (mismatched share generations): [Err(FailedCheck("Consistency check 3 failed")), Err(FailedCheck("Consistency check 3 failed"))]
test result: ok. 1 passed; 0 failed
```

What it shows: the constructor places every field where native signing reads it; a consistent
two-party sharing at coordinates 1 and 2 signs under unmodified native signing; the OT seed region
is independent of the key, so a consistent splice signs; inconsistent OT material, an inconsistent
zero seed and shares from different generations are rejected by native checks rather than producing
a signature, and the error classes are the ones the lifecycle maps to quarantine or freeze. Case 5
is the reason a warm-cache design must agree on the package generation before native signing: an
honest restart followed by unilateral recovery would otherwise end in a configuration freeze.

What it does not show: anything about the distribution of seeds the pool produces, which is the
subject of 2.1 to 2.3; the incident effects themselves, which are PairKey lifecycle behaviour
asserted by the driver schedules, not by this in-process test; or anything about Functionality 5.1.
Case 1 re-shares a synthetic test key; it is not a distributed import procedure. Astra inspected the
first version's source and log and did not rerun them; this version has not been independently
rerun either.

Disposition: carry the test into the repository as a test-only change if a constructor or splice
remains in any candidate, without adding a production accessor for secret fields.

## 4. Findings and observations

1. **Coverage correction.** The matrix expected a request disagreement to leave the entry available.
   The code retires the entry at reservation, before agreement, deliberately. Impact: a disagreeing
   peer can waste entries; single use is preserved.
2. **Index correction.** The zero shares are indexed by `digest_i`, not by the package-bound final
   session id, and no duplicate round-1 session-id check exists. Both facts are now stated in 2.4
   and 2.6. Neither weakens binding: the MtA ids carry the package id, and both parties enforce
   agreement on both values.
3. **Withheld reveal.** A peer that withholds its coin reveal causes a timeout burn without
   quarantine, at the cost of one generation per attempt. The project's rule that timeouts do not
   attribute is deliberate; the residual is a denial-of-service lever and an unproved claim that seed
   selection by abort is worthless in the two-party case.
4. **Classification of mismatches.** Mixed or one-sided OT material is attributed to the peer on
   both sides; a zero-seed mismatch and a share-generation mismatch are unattributed configuration
   freezes. The attribution audit in SECURITY-REVIEW.md can cite this evidence.
5. **Generation agreement is incident safety, not only availability.** Any design that caches
   native packages must check that both peers hold the same package generation before `sign::run`,
   or an honest restart becomes a freeze.
6. **Phase naming.** Pool failures reuse `Phase::DirectSetup`. Attribution is correct; a dedicated
   phase would make incident records easier to read.
7. **Inherited items.** `h_function_2` without a session id, the open TOB-SILA-13 question and the
   2026/976 dimension question are shared with Silence's flow and unchanged by the pool.
8. **Scope of closure.** The closures above are implementation properties. They do not establish
   the joint distribution of pool output against malicious setup messages, overlapping entries,
   selective abort and later wallet or message choice, which is what O3 and O4 ask. Under the
   migration route those obligations are not applicable; under any pool they stay open until a
   composition argument exists.

## 5. Unchanged open items

- Realization of Functionality 5.1 by the compiled SoftSpoken plus Masny-Rindal stack.
- The 2026/976 correlation-check dimension question, upstream reference only.
- The audit-to-pin gap.
- Rollback of a confidential VM snapshot.

## 6. Bounded conclusion

As reviewed on 2026-10-11 at the code above: the pool produces OT material by the same calls, with
the same validation and the same direction conventions as native key generation, under session ids
that are unique per generation and entry and bound into the MtA session ids of the signature that
consumes them; each entry is consumed at most once under the tested failure model, including crash
points in the reservation ledger; and a keyshare assembled from pool material is laid out exactly
as native signing expects. This is implementation evidence about custom code reproducing audited
steps. It is not a statement that the OT stack realizes Functionality 5.1, nor that the composition
is secure against a peer choosing messages, aborts and later wallets adaptively. Both remain open
for any pool; option O-C' avoids having to make either statement.
