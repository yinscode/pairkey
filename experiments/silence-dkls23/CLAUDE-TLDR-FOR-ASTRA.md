# Claude to Astra: TL;DR for review, 2026-10-11

Branch `silence-dkls23`, commits `5970d7e`, `1a507bc`, `f2adfc4`, `74b4564`, all documentation.
Code is unchanged since `73f318a`. Native pin `af5ada2a`, DKLs23 eprint 2023/765 primary,
2026/976 reference only. No exploit asserted anywhere. Please check the claims below against the
sources, dispute what is wrong, and fold what survives into O1 to O6 and the Silence questions.

## What changed in the analysis

1. **Spike A's migration route is the audited refresh core with root-derived constant terms.**
   `keygen/dkg.rs:209` sets the constant term to the supplied share, lines 215 to 237 commit to the
   full polynomial commitment in round 1, round 2 reveals it, lines 411 to 419 check the expected key
   before the first OT message. Contributions enter directly in `src/worker.rs:261`; no constructor,
   no `a/2, -b` conversion, no pool. Details: `DERIVED-SHARES-VIA-MIGRATION.md`.
2. **Registration survives only because migration needs the expected key as input.** Mode 1: a
   minimal commit-then-reveal in PairKey, mapped to Protocol 7.1. Mode 2: a first-run derive mode in
   the library, three to five lines at `dkg.rs:191` and `417`, best obtained from Silence. Either
   closes O1; the representation half of O2 is moot under migration.
3. **Options with flights, latency and audit scope** are in `DECISION-KEYGEN-OT-SCOPE.md` sections
   11 and 12. Native DKG and refresh are 4 flights (OT1 rides with R2), native signing 4. Recommended
   under no audit budget: O-C or O-C' (per-attempt refresh, warm native keyshare per boot) plus Mode 1.
   Spike B is dominated by Spike A; the pool only buys base-OT freshness per signature over O-C'.
4. **OT pool review** (`OT-POOL-REVIEW-COVERAGE.md`, `OT-POOL-REVIEW.md`, `review-evidence/`):
   all closable rows closed against native rounds OT1 and R3 and the existing suites; no composition
   defect found. New scratch test: constructor output byte-identical to a native DKG keyshare outside
   `x_i`, `big_s`, `s_i`; rebuilt keyshares sign; mixed OT material ends in
   `AbortProtocolAndBanParty` on both sides; a mismatched zero seed fails native check 3.
   Correction to my own matrix: reservation precedes agreement and retires the entry by design.
5. **Paper and code facts that changed the framing.** Section 8.2 assumes OT setup once per pair of
   parties, reused; section 3.1 says zero seeds can be reused indefinitely; so per-pair preparation
   and single use are not conceptual deviations. Native lets the lower-indexed party sample the zero
   seed alone (`dkg.rs:476`), immaterial for two parties. Native DKG draws `x_i` at random
   (`dkg.rs:213`), so byte-identical differential tests are impossible by construction.
6. **O-A package** is 65,968 bytes, of which 65,600 are OT seeds; NEAR's library keeps only the
   scalar because it reruns base OT per triple, so its split does not transfer to Silence's library.

## Unchanged open items

Realization of Functionality 5.1 by the compiled OT stack (Claim 6.7 ordering, TOB-SILA-13); the
2026/976 dimension question; the audit-to-pin gap; VM snapshot rollback; the migration wrapper is
outside the README's audited list although it only wraps the refresh core.

## Specific review asks

- Verify the line-reference mappings in `OT-POOL-REVIEW.md` section 2, especially session-id
  argument order (OT receiver first), seed-to-role mapping (`sender_seed` to the MtA receiver) and
  the zero-seed slot.
- Check the Mode 2 gating argument and whether an optional expected key is the right API shape,
  including the chain-code input in refresh mode.
- Confirm or refute that the native round-1 commitment covers the constant-term commitment, which is
  the basis for saying Mode 1 is needed only because of the expected-key input.
- Judge the additive-tweak fallback argument (Route 3 in the decision thread) or discard it.
- Decide whether to carry `review-evidence/pairkey_research_layout_test.rs` into the repository, as
  a native test inside the research patch or behind a test-support accessor.
- Propose status updates for O1 to O6 and additions to `SILENCE-REVIEW-QUESTIONS.md`: a derive
  mode, vouching for the migration entry point, and the Functionality 5.1 question.
