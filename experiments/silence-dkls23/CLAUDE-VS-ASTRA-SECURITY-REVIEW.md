# Comparison: Astra's SECURITY-REVIEW.md (HEAD 73f318a) against Claude's revision-2 findings

Compared: `experiments/silence-dkls23/SECURITY-REVIEW.md` at HEAD `73f318a` (the file is an inventory and
delegates its substance to two new drafts it links: `CONSTRUCTOR-SECURITY-CONTRACT.md` with obligations
O1–O6 and `SILENCE-REVIEW-QUESTIONS.md` with Q1–Q6), plus the companion code commit `f0331a8`
("preserve collector failures and worker shutdown causes"), against `CLAUDE-FIRST-PASS-REPORT.md`
(revision 2, written for commit `5a6c05a` with DKLs23 as the primary theorem source).

Short version: the two reviews agree on scope, gates, the trusted-driver boundary, the identifier
trace, single use, failure attribution and the decision not to adopt. They differ in three places, all
of which come from the same cause: Astra states it "did not obtain the full proof text" of DKLs23 and
therefore leaves O1–O5 as open questions for Silence, while I read the paper and can close or narrow
several of them from the text. The collector defect I reported (Finding 4) is fixed in `f0331a8`, and
the fix is stronger than what I asked for.

---

## 1. Statement-by-statement check of SECURITY-REVIEW.md

| SECURITY-REVIEW.md statement | Claude revision 2 | Verdict |
|---|---|---|
| Exact OT/VOLE realization table: `sl-oblivious 1.0.0-beta` checksum `31034fa1…`, pin `af5ada2a`, constants KAPPA=256, LAMBDA_C=256, LAMBDA_S=128, S=128, L_BATCH=2, RHO=1, OT_WIDTH=3, K=4, Q=16, L=512, L'=640, M=4, 64 trees; file hashes | Independently recomputed: the 64 vendor hashes in the packet manifest match the compiled tree and the registry sources; the constants match `params.rs` | Agree |
| "Both routes feed this same implementation into native signing; migration builds seeds through native DKG, while direct setup uses the exported base-OT/PPRF API" | Same reading (`worker.rs:261-298`, `pool_worker.rs:72-225`) | Agree |
| "Fresh setup alone does not establish the custom constructor's security contract" | Same (report D.1, D.3 steps 5–7) | Agree |
| "Locked parameters stay unchanged… This paper [2026/976] is supplementary reference only. Matching its sufficient bounds is not an acceptance condition… Parameter names alone do not establish a concrete security level" | Agree on the role of 2026/976. Addition: under the primary paper the constants are not merely names. DKLs23 Protocol 5.2 fixes `ξ = κ + 2λs` and `ρ = ⌈κ/λc⌉`; `L = 512` is λs = 128 (above the paper's concrete 80) and `RHO = 1` matches λc = 256 (report row 14, Finding 3). | Agree, and recommend adding the positive conformance statement |
| Zeroization inventory | Not covered in my report beyond platform gates. Spot checks of the rows against code hold (`lib.rs:34`, `wire.rs:295,317`, `pool_worker.rs:42-67`, `pool.rs:318-338`). One nit: the row "DH seed/static secret… `Zeroizing` seed" is true for `worker.rs:401-402` but `pool_worker.rs:469` builds the static secret from a bare `fresh()` array; and `worker.rs:402` copies out of the `Zeroizing` wrapper anyway (`*dh_seed`). Best effort either way, as the table itself says. | Agree; one row slightly overstated |
| Native error attribution audit (signed/decrypted before handlers; exhaustive mapping of `SignError`/`KeygenError`; two-party attribution only) | Same (report row 20; `lifecycle.rs:91-138`; `tests/invariants.rs:263-323`). Addition: the mapping implements DKLs23 Protocol 3.6 step 8 and the blacklist bound used in Hybrid H2 (p. 32); the pair-wide scope exceeds the per-`sid` blacklist the paper requires | Agree, extended with the paper's requirement |
| Production blockers list; "exact Silence audit-to-pin correspondence" open | Same (report row 23, E) | Agree |
| "It has no contribution commit-before-reveal phase… The registration decision remains pending" | Here we differ. DKLs23 decides it: Theorem 4.1 is proven over Functionality 3.2, whose step 1 takes the corrupt contribution before step 2 samples the honest one; Simulator 4.2 step 5 programs the honest share from `pk` and the corrupt contribution; §7 (p. 57–58) says explicitly that no proof of knowledge is needed, only a uniform public key and consistent shares; Protocol 7.1 obtains this with commit (step 2) then decommit (step 3). The current ceremony reveals the honest contribution first, so option A ("adaptive known-scalar contributions are admissible") has no supporting theorem in the primary paper and option B is what the paper's own key generation does | Differ: decision should be B, not pending |
| "Knowledge proofs do not establish independent root generation/KDF compliance; extraction and adaptive contribution selection require analysis" | Agree on the first clause. On the second: DKLs23 does not require extraction at all (§7), so the analysis question is only the ordering | Agree, narrowed |
| Spike C extension: identifier trace "traces identifier propagation, not a proof of the actual challenge/Fiat–Shamir transcript construction" | I did the next step (report row 12): the sid reaches the SoftSpoken seed expansion, the matrix hash that yields χ, the output randomization, the gadget vector, θ and µ; what is not hashed is the extension's `Round1Output` in θ and g. The precise assumption is Claim 6.7's "α0, α1 fixed before θ" (report Finding 2) | Extend |
| "C does not implement concurrent native attempts or cross-host authority… Astra's `e9a6220` review closes tested implementation behaviors within the cooperating-process/honest-filesystem boundary" | Consistent with my validation record and platform-gate list | Agree |

---

## 2. Obligations O1–O6 against the report's matrix rows

| Astra obligation | Claude row(s) | Status after reading DKLs23 | What remains genuinely open |
|---|---|---|---|
| O1 native keygen input and registration contract | Rows 4–6, Finding 1 | Closable from the paper: Functionality 3.2 requires the corrupt contribution to be fixed before the honest one is revealed; extraction and PoKs are not required (§7). The honest KDF needs only the PRF hybrid (row 2) | The project's choice to implement option B; optional expert confirmation that a pseudorandom honest contribution may stand in for Functionality 3.2's uniform sample (standard PRF hybrid) |
| O2 representation and public child derivation | Rows 3, 7 | Half closable: Functionality 3.2 and Protocol 7.1 evaluate shares at the fixed public indices `i ∈ [n]`, so fixed coordinates (1, 2) with ranks 0 are exactly the paper's model; the conversion `2s_0 − s_1 = a + b` is checked. Native DKG's random `x_i` is a Silence extension | Public BIP32 additive derivation and the deterministic chain code are outside Theorem 4.1 (GS22 line, not inspected by either review) |
| O3 imported preprocessing and common zero material | Rows 9, 10, 16, 17 | Half closable: the zero seed is the §3.1 realization of F_Zero (pairwise commit and decommit, then combine), and bias conditioned on completion is immaterial for two parties because F_Zero gives the adversary the honest mask anyway. The OT role mapping (`SenderOTSeed` → `RVOLEReceiver`, `ReceiverOTSeed` → `RVOLESender`) matches native DKG's convention (`dkg.rs:445-553`) | Whether SoftSpokenOT + MR19, as compiled, realizes Functionality 5.1 (report Finding 2); Silence's statement of the correlation contract |
| O4 offline preparation and later binding | Rows 11, 12, 15, 17 | Narrowable: Theorem 6.1 is per `sid`; §8.2 assumes the OT setup is reused across sessions, so single use is a strict strengthening; the consumption digest reaches the actual challenge inputs. The "actual native challenge order" question reduces to Claim 6.7's ordering assumption, which the compiled code satisfies concretely | A written statement that the concrete realization fixes the sender's OT outputs before `ã` (my upstream question 1) |
| O5 failure handling and session scope | Row 20 | Closable from the paper: Protocol 3.6 step 8 names the failures (RVOLE abort, the two consistency checks, the `Σ pk` check) and requires failing all concurrent sessions with that peer and refusing future ones; Hybrid H2 bounds the damage. The wrapper's pair-wide quarantine satisfies and exceeds this | Silence's implementation-level failure-to-action matrix for this revision (useful, not theorem-level) |
| O6 audit correspondence | Row 23 | Not closable by either review: the audit targets `1510c2f`/`a6b0147`, the pin is `af5ada2a`; TOB-SILA-13 partially resolved | Silence's revision/coverage matrix |

Astra's "intended claim to evaluate" (contract §Baseline) explicitly allows the malicious participant
to "choose a known scalar after seeing the honest public contribution". My conclusion is that this claim
is not what DKLs23 proves; the paper proves the claim for keys produced under Functionality 3.2's
ordering. Evaluating the broader claim would need a different theorem, not a reading of DKLs23.

---

## 3. Questions for Silence (Q1–Q6): which the paper already answers

- Q1 (native key input): mostly answerable from DKLs23 §3.1, §4, §7 as above. Still worth asking
  Silence to confirm that the pinned signing code relies on nothing beyond Functionality 3.2.
- Q2 (representation): the coordinate/rank half is answered by Functionality 3.2; the chain-code and
  related-key half is a real question (outside the paper).
- Q3 (imported preprocessing): the zero-seed half is answered by §3.1; the correlation/F_EOTE half is a
  real question and should be merged with Q4.
- Q4 (offline binding): sharpen to one question: does the compiled SoftSpokenOT + MR19 realize
  Functionality 5.1 with the sender's outputs fixed before the Fiat–Shamir challenge (Claim 6.7), and is
  there a written argument (TOB-SILA-13)?
- Q5 (failure scope): the "which failures" half is answered by Protocol 3.6 step 8; keep the
  implementation matrix request.
- Q6 (audit correspondence): unchanged; this is the one question neither review can answer locally.
- Missing question (optional, given the project's framing of 2026/976 as reference): Silence's position
  on 2026/976's objection to the Impagliazzo–Naor step in Lemma 6.2 at ξ = 512. Astra's draft explicitly
  declines to ask; my report lists it as upstream question 2. That is a project choice; I record the
  disagreement without insisting.

---

## 4. The collector fix (`f0331a8`) against my Finding 4

My Finding 4 said the exception at `pooled_process_tests.rs:341-359` (target commit) dropped any failure
kind from a role that had already produced a result once the fixture's `published` marker existed, and
asked for the exact cutoff kind, a count limit and persistence in evidence. The fix does more:
- `lifecycle.rs` introduces a typed `Failure::incident_cutoff()` and `is_incident_cutoff()` (Control,
  Quarantined, Burn, no peer, not attempted, not persisted, no abort-send flag); `check_incident` and
  both worker loops now return that typed failure instead of a string, and `ReleaseGate` keeps the
  original failure cause (`stopped: Option<Failure>`) so an authority or persistence error is never
  reclassified as a cutoff after a later publication.
- The collector (`pooled_process_tests.rs:427-485`) keeps every failure in `diagnostics`, and accepts a
  post-reply failure only if it is a typed cutoff **and** an expected publication is confirmed by a
  scoped acknowledgment (`PublicationAck` with ordered peers, a per-run nonce, the publisher role, the
  context, and the authority record's bytes). Anything else is recorded as `unexpected` and fails the
  scenario at completion; duplicates, reader errors, bad exits, missing EOF and drain timeouts also fail.
- Regressions: seven failure kinds in both orders are never suppressed; eight wrong-acknowledgment
  variants are rejected; failures before a role's result are returned as replies; real idle and active
  worker cutoffs emit the typed failure with `incident_persisted = false`; the Direct fixture requires the
  original typed refusal rather than any later gate error.
- Per-run diagnostics are written to `terminals/<run>.json` under the evidence directory, which partly
  addresses my Finding 5 (the schedule JSON files themselves are still deterministic summaries).
Verdict: Finding 4 closed; Finding 5 partially addressed.

Validation at HEAD in a fresh isolated snapshot: default suite 34 + 1 + 8 + 15 runtime tests plus 2
compile-fail passed (58 + 2, matching REVIEW.md); fault-enabled suite: see the addendum at the end.

---

## 5. Coverage differences

Present in Astra's documents and not in my report:
- The zeroization inventory (useful; one row nit noted above).
- The `bip32.rs:161` boundary (`il_int > ORDER` where BIP32 says `≥`); I had seen it and dropped it as
  negligible (probability about 2^-256 of hitting equality). Agree with deferral.
- The upstream README's self-description ("production-ready, audited implementation", audit section
  listing the February 2024 commits). Verified in the pristine tarball README. Both reviews treat this
  as evidence for the native lineage, not for the pin or the custom parts.
- Evidence map E1–E5 and the 83-test validation claim.

Present in my report and not in Astra's:
- The DKLs23 mapping itself: Functionality 3.2 ordering, §7's "no proof of knowledge" statement,
  Protocol 7.1 as the template, Simulator 4.2 step 5, Theorem 4.1's static-corruption and UC scope,
  Protocol 3.6 step 8 failure semantics, Protocol 5.2 parameter rules, §5.1's `s → κ` note, Theorem 6.1's
  hybrid and Claim 6.7's ordering assumption, §8.2's reuse assumption.
- The trace into `sl-oblivious` of exactly which hashes contain the sid, `ã` and `u`.
- The observation that the R1 commitment salt is 256 bits against §3.1's `2λc`.
- The deterministic-evidence note (Finding 5).

---

## 6. Recommended edits to SECURITY-REVIEW.md and the contract

1. Record the DKLs23 mapping and change "registration decision remains pending" to a decision for
   option B, citing Functionality 3.2, §7 and Protocol 7.1; keep the Schnorr proofs as defence in depth.
2. Add the positive statement that the locked constants satisfy Protocol 5.2's `ξ = κ + 2λs` and
   `ρ = ⌈κ/λc⌉` (λs = 128, λc = 256), with 2026/976 noted as a reference-level objection.
3. Close the coordinate half of O2 (Functionality 3.2 uses fixed indices) and the zero-seed half of O3
   (§3.1 realization); keep the chain-code and F_EOTE halves open.
4. Narrow O4 and Q4 to the Functionality 5.1 realization and Claim 6.7 ordering question; keep O6.
5. Answer O5's "which failures" from Protocol 3.6 step 8 in the document; keep the implementation
   matrix request to Silence.
6. Optional: add the 2026/976 question for Silence, or state explicitly why it is not being asked.

---

## Addendum: validation of HEAD `73f318a` in a fresh isolated snapshot

- Default suite: 34 + 1 + 8 + 15 runtime tests passed plus 2 compile-fail doc tests (58 + 2).
- Fault-enabled suite: 34 + 24 + 8 + 14 runtime tests passed plus 2 compile-fail (80 + 2); the process
  matrix took 249 s.
- Distinct union of passing runtime tests: 81, plus the 2 compile-fail tests = 83, matching REVIEW.md's
  "83 distinct tests". The only default-only test is `default_build_rejects_fault_injection`; the
  fault-only tests are the process fixtures and the six new collector regressions.
- Evidence: 130 schedule records, all `passed: true`; 134 per-run `terminals/` records, of which 28
  contain `unexpected` entries. That count equals the deliberate negative cases of the three synthetic
  collector tests (7 × 2 + 8 + 6), consistent with REVIEW.md's note that expected rejection records are
  retained; every real-worker scenario completed with an empty `unexpected` list.
- Clippy, formatting, release build and demos were not rerun for HEAD.
