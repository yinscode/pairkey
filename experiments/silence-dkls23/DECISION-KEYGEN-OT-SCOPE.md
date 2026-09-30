# Decision record: DKLS23 key generation and OT setup scope

Status: proposed, 2026-10-11. Author: Claude (review model), from the first-pass review of
`5a6c05a` and the comparison with Astra's documents at `73f318a`. Not an approval. Architecture v0.4
remains the reference proposal until this record is accepted or superseded.

Related: [CLAUDE-FIRST-PASS-REPORT.md](CLAUDE-FIRST-PASS-REPORT.md),
[CLAUDE-VS-ASTRA-SECURITY-REVIEW.md](CLAUDE-VS-ASTRA-SECURITY-REVIEW.md),
[CONSTRUCTOR-SECURITY-CONTRACT.md](CONSTRUCTOR-SECURITY-CONTRACT.md),
[SILENCE-REVIEW-QUESTIONS.md](SILENCE-REVIEW-QUESTIONS.md), [POOLING.md](POOLING.md),
[docs/architecture-v0.4.md](../../docs/architecture-v0.4.md).

## 1. Question

PairKey wants two-party ECDSA with Silence Laboratories' DKLS23 library. The spikes explored replacing
the library's key generation with root-derived contributions so that workers persist only roots, and
Spike C added wallet-independent OT preprocessing. Which parts of that design are outside the audited
and proven scope of the library, what blocks adoption, and how can the design be brought back inside
the audited scope or kept minimal enough to review and test with confidence?

## 2. What "audited scope" means here

- The Trail of Bits assessment (engagement November to December 2023, fix review January 2024) targets
  `dkls23 1510c2f` and `sl-crypto a6b0147`. Its appendix F reviews the replacement RVOLE against DKLs23
  Protocol 5.2. Fourteen of fifteen findings are resolved; TOB-SILA-13, the missing specification and
  proof for the combined SoftSpokenOT variant, is partially resolved.
- The pinned revision `af5ada2a` is later. Its README marks DKG, DSG, refresh and the OT components as
  audited, and import, export, quorum change and migration as not audited. The README also documents
  post-audit refactors of the setup messages and message serialization, so even the audited protocols
  are not byte-identical to the audited commits. A Silence coverage statement for the pin is required
  for any option (obligation O6).
- The primary security argument is DKLs23 (eprint 2023/765, version of December 14, 2023):
  Theorem 4.1 proves the signing protocol in the hybrid model of Functionality 3.2 (relaxed key
  generation), 3.3 (commitment), 3.4 (zero sharing) and 3.5 (random VOLE); Theorem 6.1 proves the
  VOLE from the endemic OT-extension functionality 5.1; Theorem 7.2 proves the commit-then-decommit
  key generation. Eprint 2026/976 is reference material only.

"Within audited scope" therefore means: the same protocol flow Silence ships, DKG producing a
`Keyshare`, native signing reusing it, no native patches, parameters unchanged, on a revision Silence
vouches for.

## 3. Blockers

| # | Blocker | Why it blocks | Applies to |
|---|---|---|---|
| B1 | Key generation replacement reveals the honest contribution before the peer's is fixed | Theorem 4.1 assumes Functionality 3.2, which receives the corrupt contribution before sampling the honest one; Protocol 7.1 realizes that with commit then decommit; section 7 states that no proof of knowledge is needed, only that ordering. Without it, Theorem 4.1 does not cover wallets created by registration | Spikes A, B, C |
| B2 | Custom OT setup composition | Spike C builds base-OT and PPRF material through exported `sl-oblivious` functions and injects it with a patched constructor. No written argument covers that path. Separately, the compiled SoftSpokenOT plus Masny–Rindal stack is assumed, not proven, to realize Functionality 5.1 (Claim 6.7 ordering; TOB-SILA-13). The second half applies to Silence's own flow too | B, C (first half); all (second half) |
| B3 | Audit-to-pin correspondence | Pin is later than the audited commits; constructor, migration abort patch and duplicate-id fix are unaudited by definition | All |
| B4 | Platform gates | Hostile host, snapshots and rollback, cross-host authority, physical erasure, hardware entropy, production authorization, licensing | All |

B1 is a design decision PairKey can take now. B2 and B3 need Silence. B4 is unchanged from the
project's existing gate list. Parameters are not a blocker: the locked constants satisfy
Protocol 5.2's `ξ = κ + 2λs` with λs = 128 and `ρ = ⌈κ/λc⌉ = 1`; the 2026/976 objection to that
analysis is an upstream question, not a conformance defect.

## 4. Where the spikes differ from Silence's flow

Silence's flow: `keygen::run` once per key, persist the `Keyshare` (shares, OT seeds, chain code,
session id), then `sign::run` for every signature, reusing the OT seeds.

| Component | Silence native | Spike C | Risk |
|---|---|---|---|
| Secret key | Random polynomial sum with commit, open, Feldman and DLog proofs (`dkg.rs`) | Root-derived contributions `a`, `b`; shares `a/2`, `−b` at coordinates 1, 2 | B1 |
| Coordinates and ranks | Random distinct `x_i` | Fixed 1, 2; ranks 0 | Low: Functionality 3.2 itself uses fixed party indices |
| Chain code | Jointly random, commit and open | Public `H(key_id, Q)` | Low: outside the paper either way; public derivation only |
| Base OT and PPRF | Once, inside DKG, sids from the DKG session, over native encrypted messages | Per signature, exported API, sids from the pool input, over PairKey's AEAD channel, single use | B2 |
| Zero-share seed | Lower party chooses it unilaterally | Commit and reveal coin flip | Low: this is the paper's section 3.1 realization |
| Package session id | Random DKG session id | Consumption-bound hash, unique per attempt | Low |
| Keyshare construction | DKG output | Patched constructor `pairkey_research_two_party` | Unaudited; small |
| Signing | `sign::run`, fresh seed, combined API | Unchanged | None |
| Native patches | None | Duplicate party-id fix in `dsg.rs`; best-effort abort send in `migration.rs`; test-only fault hook | Upstream the first; drop the second if migration is unused |
| Persistence | Encrypted `Keyshare` | Roots only | Design driver |

Spike A differs less: it feeds the root-derived contribution into the native refresh core
(`migration::run` calls the same `run_inner` that key refresh uses), so OT setup, chain-code handling,
Feldman checks and DLog proofs run in native code. B1 still applies, and the migration entry point is
marked not audited.

## 5. An option to rule out explicitly

Seeding native DKG deterministically from the roots, so that the `Keyshare` could be re-derived
instead of persisted, is unsafe and must not be pursued. The DLog proofs in `dkg.rs` draw their nonce
from the seeded RNG and their Fiat–Shamir transcript includes the peer's session id; a peer that varies
its session id across re-runs obtains the same nonce under different challenges and recovers the
honest polynomial. The base-OT receiver randomness would be reused in the same way. Root-only
persistence cannot be obtained from the audited DKG; it forces exactly the replacement the spikes made.

## 6. Options

| Option | Stays native | Custom | Persistence | Measured latency (0 ms injected delay) | Review surface |
|---|---|---|---|---|---|
| O-A: v0.4 path. Native DKG once, encrypted external package, native signing | All cryptography | Package encryption, storage, activation | Durable encrypted package | Native signing only | Smallest: B2 second half and B3 only |
| O-B: Spike A per wallet. Root contributions into the native refresh core once, package persisted encrypted | OT setup, chain code, checks, signing | Contribution ordering (B1); migration entry point | Durable encrypted package | Native signing only | Small plus B1 |
| O-C: Spike A per attempt. As O-B but rerun per signature, nothing persisted | As O-B | As O-B | Roots only | 110 ms setup, 13 ms signing, 140 ms wall | Small plus B1 |
| O-D: Spike C with commit-before-reveal | Signing, OT internals | Pool, exported OT setup, constructor, per-entry channel | Roots only | 25 ms online, 119 ms idle refill | Largest: B1 fixed, B2 both halves, constructor |

Latency figures are the medians recorded in REVIEW.md on one local machine and are not production
numbers.

## 7. Decision (proposed)

1. **Adopt commit-before-reveal in registration now**, modelled on Protocol 7.1 steps 2 and 3: each
   worker releases a commitment to its `Hello` bound to wallet id, role, identity and a salt; both
   commitments are journaled and acknowledged; only then are the `Hello`s revealed and checked against
   the commitments. Keep the Schnorr proofs as defence in depth. This closes B1 for every option that
   keeps root-derived contributions, and it changes no public key of an honestly registered wallet.
2. **Decide on persistence.** If an encrypted external package is acceptable, take O-A. It is the only
   option whose cryptography is exactly Silence's flow, and its remaining questions are the shared
   upstream ones. If root-only persistence is a hard requirement, take O-C as the smallest deviation
   that keeps OT setup inside native code, and accept the per-attempt cost.
3. **Keep Spike C as research only** unless the online latency is demonstrably required. If it is,
   obtain from Silence a supported import constructor (they already ship an unaudited `key_import`
   module) and a statement on standalone single-use base-OT setup through their exported API, and
   commission the composition review described in FOLLOWUP-PLAN.md task 6.
4. **Minimize native deviation regardless of option:** upstream the duplicate party-id fix, remove the
   migration abort patch if migration is not used, keep the fault hook test-only, keep parameters and
   dependencies unchanged, and obtain Silence's coverage statement for the pin (O6).
5. **Record the DKLs23 mapping** in CONSTRUCTOR-SECURITY-CONTRACT.md: Functionality 3.2 for O1,
   fixed indices for the coordinate half of O2, section 3.1 for the zero-seed half of O3, Protocol 3.6
   step 8 for O5, and narrow O4 to the Functionality 5.1 realization question.

## 8. Consequences

- O-A and O-B reintroduce durable encrypted state and therefore the v0.4 recovery, activation and
  storage designs. O-C and O-D avoid that but keep root compromise as the single long-term secret, with
  the sequential-compromise limitation already documented.
- Under any option, incident handling must keep the pair-wide quarantine, which implements Protocol
  3.6 step 8, and must extend it across hosts before production.
- The OT-extension assumption (B2, second half) remains open for every option, including v0.4, until
  Silence provides the argument or the project commissions one.

## 9. Tests that would raise confidence

- Commit-before-reveal enforcement: reveal without both commitments is refused; mismatched openings are
  refused; commitments and openings survive restart and are not reissued for a different record.
- Cross-party OT correlation on pool-produced seeds, following the native SoftSpoken unit test pattern,
  so that correlation is checked directly instead of only through end-to-end signatures.
- Compatibility vectors: run native DKG, feed its shares through the constructor, sign, and compare
  with native signing on the same inputs, pinning the constructor to native package semantics.
- Malicious-peer fixtures for inconsistent RVOLE rows and wrong `pk_i`, asserting the native
  `AbortProtocolAndBanParty` and quarantine across all wallets of the pair.
- KDF vectors: determinism per root, wallet and role; independence across wallets; zero rejection.
- For O-C: per-attempt refresh fixtures with a peer that aborts mid-setup, checking no reuse of any
  honest randomness across attempts.

## 10. Open questions and owners

| Question | Owner | Needed for |
|---|---|---|
| Does the compiled SoftSpokenOT plus Masny–Rindal stack realize Functionality 5.1, with the sender's outputs fixed before the Fiat–Shamir challenge (Claim 6.7)? Status of TOB-SILA-13 | Silence | All options |
| Coverage statement for revision `af5ada2a` and the post-audit refactors | Silence | All options |
| Supported import constructor and standalone base-OT API for single-use setup | Silence | O-D |
| Position on the 2026/976 objection at ξ = 512 | Silence, optional | Reference only |
| Persistence decision between encrypted packages and roots only | PairKey | Choice between O-A/O-B and O-C/O-D |
| Independent composition review if O-D is retained | PairKey, external reviewer | O-D |

Acceptance of this record means items 1, 4 and 5 of section 7 start immediately, and item 2 is decided
before any further Spike C engineering.

## 11. Comparison with rounds, deviations and audit scope

Added 2026-10-11 after the question "DKG with derived shares, persist only non-secret information, OT
on every signature". Two readings of that idea lead to different places:
- If "DKG" means Silence's DKG, the honest share `s_i = p_A(x_i) + p_B(x_i)` contains the peer's random
  polynomial and cannot be recomputed from the root plus public data; the peer's contribution arrives
  encrypted and is itself secret. Section 5 rules out re-seeding the DKG from the root. So with the
  native DKG the choices are persisting the share encrypted (O-A, O-B) or re-running the refresh core
  per attempt (O-C).
- If "derived shares" means `a/2` and `−b`, everything secret is already root-derivable, the only
  non-secret state is the wallet record, and the native DKG is not involved. That is Spike B (option
  O-E below). The conversion equals each party using the degree-1 polynomial that vanishes at the other
  party's coordinate, which is why no share material is exchanged and why native DKG cannot produce it.

A round is one message flight; both directions sent together count once. Native DKG and refresh take
4 flights (R1; R2 with OT1; R3; R4). Native signing takes 4 flights (R1; R2; R3; R4). PairKey's
reservation, readiness, coin and base-OT exchanges are one flight each as implemented in `worker.rs`
and `pool_worker.rs`. Registration is driver-mediated and listed separately: today 3 steps (describe,
register, commit); with commit-before-reveal 4.

| Option | Per-wallet ceremony | First signature after boot | Later signatures | Deviations from Silence's flow | Executed inside audited protocols | Custom or unaudited pieces | Persistence |
|---|---|---|---|---|---|---|---|
| O-A v0.4: native DKG once, encrypted package, native signing | DKG 4 flights (random key) | 1 agreement + 4 signing | same | None cryptographic; package encryption, storage, activation are new | DKG, DSG, OT (README: audited) | Package envelope; pin gap (O6) | Encrypted package |
| O-B Spike A per wallet, package persisted | Registration 4 steps + refresh 4 flights | 1 agreement + 4 signing | same | Root-derived contributions (B1 fixed by commit-before-reveal); migration wrapper; deterministic chain code | Refresh core, DSG, OT | Migration wrapper (~40 lines, README: not audited); registration ceremony; pin gap | Encrypted package |
| O-C' Spike A per attempt with a warm native keyshare kept in RAM (new, see §12) | Registration 4 steps | 1 reservation + 4 refresh + 1 ready + 4 signing = 10 | 1 agreement + 4 signing = 5 | As O-B, plus RAM cache lifetime policy; OT seeds reused within the cache lifetime exactly as in Silence's flow | Refresh core, DSG, OT | As O-B | Roots only |
| O-C Spike A per attempt, nothing cached | Registration 4 steps | 10 | 10 | As O-B; OT material single-use by construction | Refresh core, DSG, OT | As O-B | Roots only |
| O-E Spike B per attempt (Direct route) | Registration 4 steps | 1 reservation + 2 coin + 2 base OT + 1 ready + 4 signing = 10 | 10 | Contributions; coin flip; base OT and PPRF through exported functions with PairKey sids over PairKey's channel; patched constructor | DSG; OT primitives individually | Constructor; exported OT composition; coin flip; registration; pin gap | Roots only |
| O-D Spike C with commit-before-reveal | Registration 4 steps | Offline 5 flights per entry (2 coin, 2 base OT, 1 ack); online 1 reservation + 4 signing = 5 | 5 online | As O-E plus wallet-independent preprocessing, consumption binding, RAM ownership | DSG; OT primitives individually | As O-E plus pool and offline binding (O4) | Roots only |

Possible flight reductions, not implemented: the reservation and readiness exchanges in O-C, O-C' and
O-E can be folded into the native instance id and the signing R1, since a disagreeing peer already fails
authentication; O-E's coin commit can ride with the reservation. That brings O-C' later signatures to
4 flights, the same as Silence's flow, and O-E to about 7.

Measured medians at 0 ms injected delay (REVIEW.md): A wall 147 ms (setup 110, signing 13); B wall
190 ms (setup 111); C online 25 ms with 119 ms idle refill. O-C' later signatures should track C's
online figure minus the pool overhead, since they run only the native signing flights; this has not
been measured.

Reading of the table: O-E has no latency or round advantage over O-C and moves the OT setup and
keyshare construction out of audited code; it is only preferable if Silence will bless the exported OT
API and an import constructor but not the migration wrapper. O-C' keeps everything O-C keeps and
removes the per-signature refresh cost after the first signature per boot, at the price of adopting
Silence's own OT-seed reuse model, which the quarantine logic already handles. A wallet-independent pool additionally hides setup
latency for the first signature on a cold wallet, which O-C' pays once per wallet per boot; per-attempt
migration also refreshes OT, so freshness is not unique to the pool.

## 12. Additional suggestions

1. **Warm native keyshare in RAM (O-C').** Run the per-wallet refresh on first use after boot, keep the
   resulting native `Keyshare` in memory for a bounded lifetime or until any incident, and sign with it
   repeatedly. Nothing secret is persisted, no custom OT composition exists, and signatures after the
   first cost only the native flights. Reuse of OT seeds across signatures is Silence's audited model;
   an abort discards the cached keyshare and quarantines the pair, which is what Protocol 3.6 step 8 and
   TOB-SILA-12 require. The cache needs a lifetime policy and must be dropped on restart, epoch change
   or incident; it adds the random share and OT seeds to what lives in RAM beside the root.
2. **Overlap setup with authorization.** For O-C, start the refresh as soon as a request is being
   authorized, since it depends only on the wallet, and run `sign::run` once the prehash is fixed. This
   is ordinary setup-before-message, not presigning: no nonce exists before the message is known, so
   the GS22 caveat in DKLs23 section 3.3 does not apply. Do not use the library's `pre_signature` and
   `finish` split; that is presigning and the architecture already excludes it.
3. **Ask Silence for a supported additive-share import.** The migration entry point already does this
   over the audited refresh core; a documented contract and audit extension for it would make O-B, O-C
   and O-C' fully supported paths. The existing `key_import` module is not usable here because it
   imports a complete singleton key, which no party holds.
4. **Registration commitment design.** Use the same folklore commitment the native code uses, a hash
   of a domain label, the ceremony id, the ordered identities, the role, the `Hello` bytes and a salt of
   at least 2λc bits, journaled with create-new and fsync before release, with both commitments
   acknowledged before either reveal. Reuse the existing `Prepared` journal and endorsement flow so the
   change stays inside `registration.rs` and the driver.
5. **Malicious-peer test harness.** `sl-mpc-mate` ships `coord::adversary` with message dropping and
   injection, used by the native DKG tests. Build PairKey's negative tests on it and add a deviating
   peer that runs a modified `run_inner`: wrong polynomial degree, inconsistent `pk_i`, inconsistent
   RVOLE rows, replayed R1 session ids across attempts. Assert quarantine scope and that no honest
   randomness repeats across attempts.
6. **Differential tests against native DKG.** Generate a key with native DKG, sign natively, then run
   the same inputs through the chosen PairKey path and compare partial values where the API allows and
   signatures where it does not. This pins the registration and conversion to native semantics.
7. **Reduce native patches to one.** Upstream the duplicate party-id fix and the migration abort
   preservation as a pull request; keep the fault hook test-only; remove the constructor patch
   entirely under O-A, O-B, O-C or O-C'.
8. **Pin and release hygiene.** Ask Silence for a tagged release or coverage statement covering the
   post-audit refactors, pin to it, and record the mapping in SECURITY-REVIEW.md. Track the 2026/976
   question separately as upstream reference.
9. **Write the short composition note for the chosen option.** For O-C or O-C' it is three
   statements: registration with commit-before-reveal realizes Functionality 3.2 under the PRF
   assumption on the roots; the refresh core and signing are Silence's audited protocols; Theorem 4.1
   then applies per wallet, with the shared Functionality 5.1 question listed as the open assumption.
