# Claude review of Spike D at `0f6e0557` (baseline `2d735bd`)

2026-10-12. Scope: the complete donor construction on `codex/spike-d` at commit
`0f6e0557555b73aafa15ce0b590067dad0a747d1`, including the unchanged research constructor and the
unchanged native code it relies on. Native pin `af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`,
`sl-oblivious 1.0.0-beta`. Theorem source DKLs23, eprint 2023/765, version of December 14, 2023;
2026/976 examined for applicability. Read: `SPIKE-D-DONOR-DESIGN.md`, `SPIKE-D-REPORT.md`,
`.local/spike-d-bounded-review-20261012/manifest.json`, the stress and expiry evidence files, and
every source file of the route. No tracked file in the worktree was changed. Both full suites were
rerun independently from a hashed `git archive` of the commit in an isolated snapshot, section 9.
Nothing here is an exploit claim or an approval.

Path conventions: `src/...` and `tests/...` are `experiments/silence-dkls23` at the commit;
`keygen/...`, `sign/...`, `proto/...` are the pinned native crate's `src`; `endemic_ot.rs`,
`all_but_one.rs`, `soft_spoken_ot.rs`, `rvole.rs` are the locked `sl-oblivious` crate's `src`.
Native line numbers were verified against the extracted pin; branch line numbers against the commit.

## 1. Answer to the main question

The construction preserves malicious security under the following explicit assumptions. Each is
labelled established (E), conditional (C) or missing (M) for this commit.

| # | Assumption | Status | Where it is carried |
|---|---|---|---|
| A1 | Static corruption of at most one of the two parties; the honest party's process, memory and filesystem are not under adversary control | model | design note, section 1 |
| A2 | Authenticated channels: identity-signed boots, HKDF and AEAD channel keyed by context, native signed and encrypted messages | E | `src/pool.rs:140-146`, `src/wire.rs:246-343`, `proto/signed.rs`, `proto/encrypted.rs` |
| A3 | Fresh OS entropy at every protocol run, never replayed; no snapshot or restore of a running worker | C, deployment | hedge at `src/d.rs:288-305`; detectors in section 7 |
| A4 | Honest, durable local filesystem shared only by cooperating processes; journals are not rolled back | C, deployment | design note, persistence section |
| A5 | HKDF-SHA512 with the documented salt and info is a PRF under the 32-byte root; roots are independent and never co-located outside tests | C, standard | `src/d.rs:74-91` |
| A6 | Hash commitments and the native hashes behave as random oracles with separated domains; the registration commitment is extractable and equivocable in the programmable ROM, the RVOLE hashes are non-programmable as Theorem 6.1 requires | C, standard but must be stated | `src/d.rs:101-103`; DKLs23 Theorem 6.1, Protocol 7.1 |
| A7 | The compiled EndemicOT, PPRF, SoftSpoken and RVOLE stack realizes Functionality 5.1 and Functionality 3.5 for fresh session ids with the paper's selective-abort leakage, for material produced by one native DKG and used by other sessions | M, the central lemma | section 5 |
| A8 | The pinned parameters give the statistical margins the proofs assume | M, disputed by 2026/976 | section 8 |
| A9 | The native protocols at the pin behave as audited at `1510c2f` | C, pin gap | SECURITY-REVIEW.md |
| A10 | Quarantine after an attributable failure is permanent for the pairing and never cleared by a wallet change, a new donor, a restart or a rollback | C, policy and deployment | `src/lifecycle.rs:291-330`, section 7 |
| A11 | The two signers are the only parties with the roots; the research fixture's co-located roots are a test artefact | model | report, limits |
| A12 | One worker process per pairing, or a controller that prevents overlapping generations | C, not enforced | section 7 |

What is established at this commit: functional correctness across 1,000 signatures, ten wallets, two
paths and ten generations; every structural precondition the theorems need, fresh session ids,
binding of wallet and attempt into the native session ids, commit-before-reveal ordering, retirement
on failure, pairing-wide fencing, each enforced in code and exercised by tests; and the lifecycle
properties under the cooperating-process model. What is conditional: malicious security of signing,
which follows from Theorem 4.1 only through A7 and A8, and registration security, which follows from
the Protocol 7.1 argument only through a mapping lemma not yet written. What is missing: the three
lemmas in section 10.

## 2. Status by obligation

| Obligation | Established | Conditional | Missing |
|---|---|---|---|
| 1 Registration and derivation | ordering, binding, journals, retry rules, derivation separation | realization of Functionality 3.2 | written mapping lemma, programmable-ROM composition note |
| 2 Donor transplantation | separability of seeds from the donor key at the implementation level; representation validity; record and constructor checks | equivalence to DKG-produced seeds | reduction to A7 stated as a lemma |
| 3 Reusable preprocessing | fresh ids per extension, retirement on failure, bounds, regression probes | per-session security given A7 | realization lemma with leakage and reuse across keys; accumulation bound |
| 4 Session and mask binding | complete trace; fixing order; adversary influence limited to its own round-1 contribution | nothing beyond A3 | none, apart from Silence confirming the mask digest's domain is intended |
| 5 Failure and lifecycle | classification, local controls, cross-wallet fence through restart, bounds per generation | pairing-wide permanence under A4 and A10 | multi-process controller; queued-output recall is impossible by design |
| 6 Concrete security | parameter rules of Protocol 5.2 satisfied | Theorem 6.1 and Lemma 6.2 bounds if the IN96 step holds | reconciliation with 2026/976 Theorem B.17; no bound across attempts can be stated today |

## 3. Obligation 1: registration and deterministic derivation

Theorem route: Theorem 4.1 takes its key from Functionality 3.2, which receives the corrupt
contribution before the honest polynomial is sampled; Protocol 7.1 realizes it by commit then
decommit in the F_Com hybrid; Theorem 7.2; section 7 states no proof of knowledge is needed.

| Item and theorem | Code | Inputs, adversary knowledge, required distribution | Enforcement and tests | Gap or counterexample |
|---|---|---|---|---|
| Honest contribution uniform and independent across wallets, Functionality 3.2 sampling step, under A5 | `Root::derive_v2`, `src/d.rs:66-93`: info is the hash of pairing, namespace, epoch, version, role, key id; HKDF-SHA512 with a versioned salt; 64-byte expansion reduced wide; zero rejected; the root's identity must match the wallet's identity for the role, lines 68-73 | input: 32-byte root; adversary knows the wallet domain and the public point after reveal; required: uniform scalar per distinct domain | `derivation_v2_binds_pair_namespace_epoch_wallet_and_preserves_v1`, `src/d/tests.rs:44` | none beyond A5; reduction bias from a 512-bit reduce is negligible |
| Corrupt contribution fixed before the honest point is revealed, Protocol 7.1 steps 2 and 3 | `Opening::commitment`, `src/d.rs:101-103`: hash of wallet domain, role, point and 32-byte salt; `Service::register`, `src/d_worker.rs:161-207`: reserve, journal own commitment, exchange, journal peer commitment, exchange ordered acknowledgement, journal reveal release, exchange openings, verify peer opening against the journaled commitment | adversary sees the honest commitment before sending its own in the same exchange; hiding makes that worthless; it sees the honest opening only after both commitments are durable on the honest side | `commitment_and_record_mutations_refuse` (`tests.rs:68`), `registration_commitments_do_not_replay_across_wallet_role_pairing_or_epoch` (`tests.rs:488`), reveal mismatch as a peer violation in the matrix test (`process_tests.rs:217`) | the simulator for Functionality 3.2 must equivocate the honest commitment, since commitments are exchanged in one flight, and extract the corrupt point from the oracle query. Both hold for a hash commitment in the programmable ROM; this needs to be written, including domain separation from the non-programmable oracles of Theorem 6.1 |
| No second chance after disclosure: a revealed-then-failed wallet id never meets a fresh corrupt contribution | `src/d_worker.rs:128-129` retires a reserved slot with no prepared record on the next attempt; `Journal::reserve_checkpoint`, `src/d/journal.rs:123-154`, create-new; `Journal::prepare`, lines 163-176, idempotent on the exact record; `Journal::commit`, lines 177-188 | adversary may abort after receiving the honest opening | `peer_abort_after_reveal_cannot_return_with_a_new_commitment` (`process_tests.rs:625`), `competing_ceremonies_have_one_reservation_winner_per_role` (`tests.rs:516`), one-sided death matrix (`process_tests.rs:273`) | correct under A4; a rolled-back journal reopens the slot, which is the A4 dependency, not a code defect |
| Concurrent wallets and concurrent ceremonies | distinct key ids give independent PRF outputs; one reservation per role per wallet id; `RegStatus` exchange refuses asymmetric states, `src/d_worker.rs:135-159` | | tests above | independent role winners are not a global winner; the design note says disagreement refuses or retires, which the tests confirm |
| Record validity and chain code | `Record::new` and `Record::validate`, `src/d.rs:116-161`: openings match commitments, aggregate equals the sum of points, chain code is the version-1 public rule over key id and key; `Record::local`, lines 165-173, re-derives and compares | | `only_exact_prepared_certificate_can_activate` (`tests.rs:87`) | the chain code is public and deterministic; the related-key assumption for public child derivation remains the O2 item it always was |
| Possession proof | `Endorsement::new` and `validate`, `src/d.rs:200-245`: Schnorr over the opening point with challenge bound to record digest, role and nonce commitment; nonce from a 512-bit OS draw | | `possession_proof_is_authenticated_and_bound_to_entire_record` (`tests.rs:224`) | supplies no extraction property the mapping needs; extraction comes from the commitment's oracle query. It is identity binding of the record and can stay or go |

## 4. Obligation 2: donor establishment and transplantation

Theorem route: in Theorem 4.1's hybrid model the OT functionality is separate from key generation,
so the signing proof does not care where correlations came from, provided they realize the
functionality for the sessions that use them. The native DKG produces them, the constructor places
them. Algebraic consistency of the shares is necessary, not sufficient; sufficiency is A7.

| Item and theorem | Code | Inputs, correlations, adversary knowledge | Enforcement and tests | Gap or counterexample |
|---|---|---|---|---|
| Donor DKG is an honest native key generation with fresh randomness, Theorem 7.2 route | `Service::prepare`, `src/d_worker.rs:264-354`: context digest over peers, boot generations, configuration, limits and attempt, line 272; attempt id burned on disk before any message, 283; counter issued, 287; hedged seed, 288; `keygen::run`, 314; errors mapped by `Failure::native_migration`, 316-325 | the donor key is random and never used; the adversary learns the donor public key and, as a participant, its own share and seeds | `native_donor_violation_and_aggregate_failure_matrix` covers PPRF corruption and abort-send loss (`process_tests.rs:217`) | none specific to D; the base-OT selective-abort leakage of section 5 applies here exactly as in native DKG |
| Separability of seeds and zero seed from the donor signing key | `keygen/dkg.rs`: base OT receiver randomness and sender randomness come from the protocol RNG independently of the polynomial, lines 296-330 and 446-470; the zero seed is sampled by the lower-indexed party, 476-480, stored at 556; the final DLog proofs, 626-642, cover shares and chain code only; no native check relates seeds to the key | the seeds are random correlations statistically independent of the donor polynomial given the RNG | `Donor::extract`, `src/d/material.rs:57-112`: pinned offsets 172, 98, 368, zero slot at 66 of entry 0, sizes 32,768 and 32,832 checked, copies in zeroizing owners, the donor keyshare dropped at line 99 with native `ZeroizeOnDrop`; `native_donor_extraction_reuses_exact_material_with_concurrent_transient_wallets` (`tests.rs:366`) | established at the implementation level. The formal statement that signing with these seeds equals signing with freshly generated ones is immediate in the hybrid model once A7 holds; it should be written as a corollary of the realization lemma, not assumed |
| Representation validity: the package is a legitimate output form of Functionality 3.2 | `Donor::package`, `src/d/material.rs:124-161`: shares `a/2` and `-b`, public shares `A/2` and `-B`, session id over record digest, generation and instance, extra data the instance; `Keyshare::pairkey_research_two_party`, `keygen/pairkey_research.rs:7-47`: non-zero share, non-identity points, distinct public shares, `2·S_0 - S_1 = Q`, `s·G = S_party`, ranks 0, coordinates 1 and 2, zero seed in entry 0, both seeds in the single peer entry | adversary knows `A`, `B`, `Q`, the coordinates and the public shares | layout test in `review-evidence/pairkey_research_layout_test.rs`; tamper matrix `transient_package_tamper_matrix_records_native_validation_boundary` (`native_review_tests.rs:220`) | counterexample recorded by the tamper matrix: native signing accepts a package whose public-share, key-id or extra fields were altered and signs the correct wallet; coordinate, aggregate-key and session alterations are refused. So record validation, `Record::local` and the constructor are the trust boundary for those fields, inside the honest process of A1. Not a vulnerability, a boundary to state |
| Pairing and role fixedness | `Donor::package` refuses a record whose identities differ from the donor's, lines 129-132; the donor key may never be a wallet key, 125-128; generation agreed and journaled, `src/d_worker.rs:327-345` | | multiwallet and rotation tests (`process_tests.rs:75`) | roles are fixed per pairing by construction; a role swap would fail at the generation agreement or at native checks |

## 5. Obligation 3: reusable preprocessing

Theorem route: Functionality 5.1 serves any number of sessions with fresh session ids; Protocol 5.2
and Theorem 6.1 realize Functionality 3.5 per session in the F_EOTE hybrid with a non-programmable
oracle, Lemma 6.2 and Claim 6.7 supplying the statistical terms and the fixing order of α_0, α_1
before θ; section 8.2 assumes setup once per pair of parties and reuse thereafter. SoftSpokenOT
proves its extension in a model that permits selective-abort guesses against the receiver's secret
output, Theorems 5.1 and 6.2 of the chapter, and the endemic base OT is Masny and Rindal's figure 8.

| Item and theorem | Code | Inputs, correlations, adversary knowledge, required distribution | Enforcement and tests | Gap or counterexample |
|---|---|---|---|---|
| Fresh session id per extension, Functionality 5.1's `sid is fresh` | the MtA id is `H(final session id, sender, receiver)`, `sign/dsg.rs:1061-1075`; the final session id hashes both round-1 ids and the package id, `162-167`; the honest round-1 id is drawn from the ChaCha RNG seeded by the hedged seed, `sign/dsg.rs:75-99`; `R1Guard::observe`, `src/d/guard.rs:58-96`, journals every authenticated own and peer round-1 id with create-new before use | adversary controls its own round-1 id and may choose it after seeing the honest one; it cannot repeat the honest id | `authenticated_r1_replay_journal_and_native_final_sid_observer` (`tests.rs:190`), `age_generation_and_replay_refuse_before_native_freeze` repeat-seed and instance-replay cases (`process_tests.rs:107`), `identical_wallet_path_prehash_concurrent_attempts_have_distinct_observed_sessions` (`native_review_tests.rs:170`), stress evidence: 1,000 distinct final ids | counterexample if the condition fails: `reused_base_and_extension_sid_expose_choice_xor_but_fresh_sid_breaks_it` (`tests/d_ot_regressions.rs:6`), the receiver's matrix is the seed expansion XOR its choices, `soft_spoken_ot.rs:117-227`. Structurally unreachable under A3 and A4 |
| Permitted leakage: accepted setups can reveal a base choice | `endemic_ot.rs:239-269` decodes only the chosen branch; `all_but_one.rs:113-230` verifies the proof over what was decoded | the malicious base-OT sender learns one choice bit per undetected guess; the honest receiver's choices are its punctured indices, the correlation secret of the extension sender role, `rvole.rs` sender path | `selective_abort_each_accepted_setup_reveals_same_base_choice` (`tests/d_ot_regressions.rs:44`); my 256-trial run, 120 accepted all on the unmodified branch | this is the chapter's guess-set model, not a defect. The required statement is that the realization holds with this leakage term for the compiled stack; the pinned sources give no proof text for the combination, and TOB-SILA-13 recorded exactly this as partially resolved |
| Does later success amplify a leaked bit? | signing-time guesses go through the correlation check, `soft_spoken_ot.rs:397-404`, and the RVOLE checks `rvole.rs:151-160, 225`; a wrong guess is `AbortProtocolAndBanParty`, mapped at `src/lifecycle.rs:108-130` | with k known bits of a chunk the cheating receiver passes with probability 2^-(4-k) instead of 2^-4 for that chunk; each failed guess is visible | donor discarded on every failure, `src/d_worker.rs:600-609`; peer quarantined on attributable failures; bounds 100 and 600 s, `src/d/material.rs:16-43, 175-177` | no amplification without further guesses; each further guess risks the generation and the pairing. The quantitative statement, expected leaked bits before retirement, follows from the guess-set model once A7 is written down; today it is an argument |
| Reuse across keys and sessions within one generation | one donor per worker, one generation at a time, `Service.donor`, retired on bound, `src/d_worker.rs:507-509`, on idle expiry, 585, on in-flight expiry, 597 | per-pair reuse is the paper's model; the audit covered per-keyshare reuse only | multiwallet and rotation tests; stress evidence: ten generations, addresses stable | the lemma must cover polynomially many sessions and both corrupt roles; section 8.2 is a cost-model assumption, not that lemma |

## 6. Obligation 4: session and mask binding

Trace of one attempt, with the moment each value is fixed and what the corrupt peer can influence.

| Value | Where | Fixed when | Corrupt peer influence |
|---|---|---|---|
| Instance | `Request::instance`, `src/d.rs:274-286`: wallet domain, record digest, generation, path, prehash, attempt | at request agreement, `src/d_worker.rs:397-409`, journaled on both sides before any native message | may refuse; cannot alter without the honest side refusing |
| Package session id | `src/d/material.rs:143-146`: record digest, generation, instance | at construction, before `sign::run` | none |
| Hedged seed | `hedged_seed`, `src/d.rs:288-305`: OS entropy, instance, counter, role, operation | at `src/d_worker.rs:467-479`, after the counter is issued at 410 | none |
| Honest round-1 id, nonce share, blinding, channel keys | `sign/dsg.rs:75-99`, all from the seeded RNG | before the honest round 1 is sent; the guard journals the id at send time, `src/wire.rs:91-95` | none |
| Corrupt round-1 id and commitment | its own round 1 | may be chosen after seeing the honest round 1 | free choice; this is the only lever |
| Final session id | `SHA256(sid_0, sid_1, package sid)`, `sign/dsg.rs:162-167`; agreement enforced at 283-285 and 368 | after both round-1 messages | grindable through its own id; fresh because of the honest id |
| Mask digest `digest_i` | `sign/dsg.rs:169-183`: DSG label, both round-1 ids and nonce commitments; agreement enforced at 393 | same moment | same lever; does not contain the package id or the wallet |
| Zero masks | `get_zeta_i`, `sign/dsg.rs:876-914`, called at 234 with `digest_i`; `ζ_0 = -H`, `ζ_1 = +H` over the shared seed from entry 0 | same moment | both parties know the seed; for two parties the honest mask is the negation of the corrupt one, which is exactly what Functionality 3.4 leaks to a corrupt party; the corrupt party may select which mask value applies by grinding its round-1 id, equivalent to shifting its own share, harmless |
| MtA ids | `mta_session_id`, `sign/dsg.rs:1061-1075`, both directions | after the final session id | fresh by construction |
| Extension and RVOLE | seed expansion and checks keyed by the MtA id, `soft_spoken_ot.rs:138-143, 189-190`; gadget, θ and µ in `rvole.rs:93-136, 137-230, 248-320` | per round | its own inputs and messages, checked |
| Output | signature verified, low-S, recovery id, `src/d_worker.rs:487-495` | before release | none |

Enforcement and tests: `seed_hedge_keeps_entropy_and_separates_context_role_counter_operation`
(`tests.rs:165`), `counter_regression_and_partial_issuance_fail_closed` (`tests.rs:176`), the
observer tests above, mismatched zero seed in the matrix test, which fails native check 3 at
`sign/dsg.rs:429` and freezes. Gap: none at the binding level. Two facts to keep in view: the mask
digest omits the package id, so the masks are session-bound but not wallet-bound, which is sufficient
because they are public to both parties; and the only adaptive lever the peer holds is its own
round-1 contribution, whose effect on the honest party is confined to which public mask value
applies and to session-id grinding that the honest id defeats.

## 7. Obligation 5: failure and lifecycle composition

Theorem route: Protocol 3.6 step 8 and the audit's TOB-SILA-12 require that a failed check stop
concurrent sessions and denylist the counterparty; everything else here is engineering under A4.

| Control | Code | Local control or cryptographic guarantee | Tests | Gap |
|---|---|---|---|---|
| Round-1 replay guard | `R1Guard`, `src/d/guard.rs`; hooks in `src/wire.rs:91-95, 160-173` | local, honest filesystem; refuses a repeated authenticated id from either side before use; a duplicate delivery is treated as replay and burns | `tests.rs:190`, repeat-seed case | duplicate delivery on an at-least-once transport self-burns; dedupe in front of it; journals grow per signature with no pruning yet |
| Counter and rate accounting | `Counter`, `src/d/journal.rs:199-277`: immutable issuance markers, head rename, regression refused; abort markers with clock-regression refusal; fewer than three transport events per 60 s | local | `tests.rs:176, 248`; first stress schedule tripped the limiter through driver shutdown, documented | detects head regression against markers, not a rolled-back filesystem |
| Release gate and incident scope | `ReleaseGate`, `src/lifecycle.rs:224-330`; pairing scope `163`; incident published for non-burn failures | local authority shared by cooperating processes; orders setup, native and result handoffs against publication; cannot recall frames already queued | `donor_route_actual_setup_r4_result_cutoff_with_positive_and_bypass_controls` (`process_tests.rs:346`), `wallet_incident_fences_other_registered_wallet_across_worker_restarts` (`process_tests.rs:482`) | permanence of quarantine is A10; an operator reset or a rollback reopens the pairing |
| Classification | `Failure::native_sign`, `src/lifecycle.rs:108-130`; `native_migration`, 131-156; D context burns in `src/d_worker.rs:39-41` | local mapping to actions | matrix test (`process_tests.rs:217`): quarantine for PPRF, abort-send loss, reveal mismatch, round-1 tampering; freeze for zero-seed mismatch; burns without quarantine for age, missing donor, instance replay, repeated seed (`process_tests.rs:107`) | aggregate failures are frozen rather than attributed, by design |
| Donor retirement | `Service::discard`, `src/d_worker.rs:93-103`; called on every command failure, 600-609, on bound, 507-509, on expiry, 585 and 597 | local | `incomplete_donor_retirement_marker_cannot_report_success` (`process_tests.rs:444`), `age_expiry_cancels_inflight_attempt...` (`process_tests.rs:168`), real 602 s expiry evidence | RAM-only material is cloned by a VM snapshot; retirement markers are per filesystem |
| Bounds | `Limits`, `src/d/material.rs:16-43`, capped at 100 and 600 s; `usable` and `reserve`, 116-123, consume before signing | local, per generation, per process | `default_hygiene_is_100_attempts_or_600_seconds_with_strict_edges` (`material.rs:182`), `native_donor_multiwallet_rotation_and_use_bounds` (`process_tests.rs:75`), stress attempt-101 refusal | not a global bound: a second process or a cloned process holds its own donor and counters; the generation agreement prevents mixing but not parallel use of one cloned generation. Treat 100 as hygiene per process, as the design note says |

## 8. Obligation 6: concrete security

Pinned parameters: `KAPPA = 256`, `LAMBDA_C = 256`, `LAMBDA_S = 128`, `S = 128`, `L_BATCH = 2`,
`RHO = 1`, `OT_WIDTH = 3`, `K = 4`, 64 trees, `XI = 512 = KAPPA + 2·LAMBDA_S`, unchanged. These
satisfy Protocol 5.2's dimension rules. Theorem 6.1 gives computational security per RVOLE instance
in the F_EOTE hybrid with a non-programmable oracle; Lemma 6.2, Claims 6.5 and 6.10, uses the
Impagliazzo-Naor step to bound the statistical terms by 2^-λs, so 2^-128 at the pin; Claim 6.7 fixes
α_0 and α_1 before θ. Across q instances the computational terms add linearly; the statistical terms
add as q·2^-128.

The 2026/976 preprint, Theorem B.17, requires for the DKLs24 variant with the gadget chosen at the
onset, which is the compiled `rvole.rs` arrangement, that `m ≥ log q + 7s + 2 log(s+1) + 2s·log(e·m/s)`
for statistical parameter `s`. With `m = 512` and `log q = 256` the largest `s` satisfying it is 12;
the simplified table row without the last term admits 35. If that analysis applies to the pinned code,
the statistical margin per RVOLE instance is between 12 and 35 bits, not 128, and a cheating party
passes a check with inconsistent inputs with probability up to about 2^-12 per instance rather than
2^-128. Whether it applies, and to which party's input, is the reconciliation Silence owes; the
preprint's section 4.5 attack in the endemic-OT hybrid model should be read against the compiled
stack in the same exercise. Nothing in the donor design changes this; it is the margin of every
Silence signature at this pin.

What bound can be stated across attempts, wallets and generations today: none that is independent of
A7 and A8. Conditionally, with A7 and the paper's own margins, each session is independent given
fresh ids, and the leakage an adversary can accumulate against one generation's correlation secret
before retirement is bounded by the guess-set model, k bits with probability 2^-k, with no carry-over
between generations because each has fresh base OTs. Under the 2026/976 margin instead, the operative
cap is the policy: a failed cheat quarantines the pairing permanently under A10, so exposure per
adversary identity is about 2^-s per generation it is allowed to attack; across many pairings or
with resettable quarantine that cap does not hold. That is why A10 is listed as an assumption and
why the reconciliation is the most consequential open item.

## 9. Independent rerun

A `git archive` of `0f6e0557` was extracted into an isolated snapshot with the native archive copied
in, every source, manifest and script hashed, and both suites run through
`bootstrap.sh test --locked --offline` with separate temporary and evidence directories.

Default features: 80 passing test entries, no failures, exit=0; per binary: ok. 52 passed; 0 failed; 4 ignored; 0 measured; 0 filtered out; finished in 15.73s;ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s;ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 2.06s;ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 96.52s;ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s;ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s;

Fault-enabled features: 111 passing test entries, no failures, exit=0; per binary: ok. 52 passed; 0 failed; 4 ignored; 0 measured; 0 filtered out; finished in 15.76s;ok. 33 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 335.68s;ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 2.04s;ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 97.65s;ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s;ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.23s;

The counts match the report and the manifest: 78 runtime tests plus 2 compile-fail checks by default, 109 runtime tests plus 2 compile-fail checks with faults enabled. Hashes of every source, manifest and script in the archived tree, the commit id and the filtered logs are in `review-evidence/spike-d-0f6e055-claude-rerun.output.txt`. Clippy, formatting, the stress run and the expiry probe were not rerun here.

The stress and expiry evidence was inspected, not rerun: `stress.json` records 1,000 signatures, ten
wallets, two paths, ten distinct generations, all instance ids, observed final session ids and
aggregate `r` values distinct, addresses stable, one expected attempt-101 refusal and no unexpected
failure; `expiry.json` records a 602-second wait, a context burn without incident, a fresh generation
and a verified signature at the same address.

## 10. Conclusions

**Strongest defensible security statement today.** At this commit, for two parties under A1 to A6
and A9 to A12, every structural precondition of DKLs23's signing theorem is enforced and tested: each
extension runs under a session id that contains a fresh honest contribution and the agreed wallet,
generation and attempt; the honest contribution to the wallet key is fixed by a binding commitment
before the peer's is revealed and a disclosed contribution is never re-run against a fresh peer value;
donor material is produced by unmodified native key generation and placed into a package that is a
valid representation of the key-generation functionality's output; any attributable failure retires
the material and fences the pairing. Given additionally the realization lemma A7 and the paper's own
statistical margins A8, Theorem 4.1 applies per wallet with Functionality 3.2 supplied by the
registration up to the mapping lemma, and the adversary's knowledge of any generation's correlation
secret is bounded by the guess-set leakage until retirement. Without A7 and A8 the statement reduces
to: no deviation from the native computations other than package assembly, no composition defect
found, and functional correctness at scale.

**Exact missing lemmas.**
- L1, realization and transplant: the compiled EndemicOT, PPRF, SoftSpoken and RVOLE stack realizes
  Functionality 5.1 and Functionality 3.5 for fresh session ids, both corrupt roles and polynomially
  many sessions, with the chapter's selective-abort leakage, when the base-OT material was produced
  by one native DKG and is used by sessions under other packages. Corollary: signing with transplanted
  seeds equals signing with freshly generated ones.
- L2, registration mapping: the commit-then-reveal exchange with the journal rules realizes
  Functionality 3.2 in the programmable ROM, with equivocation of the honest commitment and extraction
  of the corrupt point from the oracle query, covering prior disclosure, retries, concurrent wallets
  and the domain separation from the non-programmable oracles of Theorem 6.1.
- L3, concrete margin: a reconciled statistical bound for Protocol 5.2 at `ξ = 512`, `λs = 128`,
  between Lemma 6.2's Impagliazzo-Naor step and 2026/976 Theorem B.17, with the section 4.5 attack
  checked against the compiled code.
- L4, small: two-party zero sharing with a shared, possibly adversarially selected seed and a
  session-bound digest realizes Functionality 3.4's leakage profile. Routine, but it should be on paper.

**Most useful adversarial experiments, in order.**
1. A cheating RVOLE party in a scratch `sl-oblivious` that follows the 2026/976 analysis and measures
   the actual pass rate of inconsistent inputs against the compiled checks at `ξ = 512`. If the margin
   is near 12 bits, a few thousand trials show it; if near 128, nothing does. This is the only
   experiment that can move L3 locally.
2. An accepted leaky donor carried into signing, then a cheating extension receiver using the known
   base-choice bits, measuring the consistency-check pass rate against the predicted 2^-(4-k) per
   chunk; confirms the amplification analysis and the retirement policy's effect.
3. Two worker pairs on one pairing, plus a cloned-process variant: parallel use of one cloned donor,
   generation mismatch, an incident in one during the other's round 4; confirms the multi-process
   assumptions A4, A10 and A12 are the right ones.
4. Full-directory rollback with repeated entropy: shows journals do not detect it, the hedge prevents
   nonce and session reuse, and the peer's records still refuse a forgotten quarantine.
5. Registration adversary with a replaying relay: delayed commitment, commitment copied from another
   pairing, reveal then abort then new commitment; the existing tests cover most, the relay form
   covers ordering under message reordering.

**Minimum independent review to close each obligation.**
1. Registration: a cryptographer's review of L2, one page plus the journal rules; internal is enough
   if the reviewer owns the ROM composition argument.
2. Transplantation: Silence's confirmation that signing security does not depend on seed provenance
   beyond A7, and the written corollary; internal review of the constructor boundary recorded by the
   tamper matrix.
3. Reusable preprocessing: L1 from Silence or an external composition reviewer; nothing local closes
   it.
4. Session binding: internal, done here; Silence to confirm the mask digest's domain is as intended.
5. Lifecycle: internal engineering review plus the multi-process experiments; a deployment review for
   A4, A10 and snapshot policy.
6. Concrete security: L3 from Silence or an independent cryptographer, with the pinned parameters
   held fixed; this is the item that gates any production claim for any route, donor or not.
