# Spike D output-fixing lemma

2026-10-12. Analysis base `7669f7d` on `codex/spike-d`; native pin `af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`, `sl-oblivious 1.0.0-beta`. This is a conditional proof draft and executable correspondence evidence. It changes no signing code, parameters or dependencies. The [dossier](SPIKE-D-PROOF-DOSSIER.md) supplies the attacker model; the [registration lemma](REGISTRATION-MAPPING-LEMMA.md) handles separate programmable oracle domains.

**Result:** fixed-input determinism, the packed-matrix identities and a conditional row-collision bound can be proved. The native primitive probe reproduces these facts. **Online extraction/binding of effective outputs against an arbitrary malicious signer remains unproved.** Consequently this draft does not restore the full DKLs23 theorem, prove donor reuse, or close the 2026 dimension question.

## 1 The premise that needs to be established

In the selected 76-page [2023/765 edition](https://eprint.iacr.org/2023/765), Claim 6.7 uses ordered OT outputs fixed before the challenge oracle response. Its row comparison is a nonconstant affine equation in the challenge when the inconsistent coefficients are fixed. The [2026/976 analysis](https://eprint.iacr.org/2026/976), section 4.5, gives an endemic-OT hybrid counterexample that chooses the OT inputs after seeing the challenge. This is a counterexample to unrestricted late input selection, not an executable attack against this compiled realization.

The compiled RVOLE sender helper expands its OT material before constructing correction rows and computing theta. That gives a deterministic-function lemma. It does not constrain an arbitrary corrupt peer, which can skip the helper, alter local state, make early public-oracle queries, and send any authenticated protocol frame. Attestation and immutable local donor storage at the honest signer do not turn that peer into honest code in our chosen threat model.

The proof must distinguish:

- **Call order:** what an honest helper computes first.
- **Fixed-input values:** what is determined given a specified complete seed state, SID and matrix.
- **Malicious prefix binding:** which effective values a successful deviating peer is constrained to, and when a simulator can extract them.
- **Correlation and distribution:** whether those values realize the selected ideal OT/multiplication service, with the required leakage and randomness.

Only the first two are established directly by the source and the algebra below. The latter two require a realization argument.

## 2 Directions, data and challenge inputs

The type names refer to the earlier seed protocol and can obscure the signing roles:

| Current invocation role | Seed type used | Extended output |
| --- | --- | --- |
| VOLE receiver / extended-OT receiver | `SenderOTSeed`, containing all leaf keys | Fresh choice bits `beta`, selected pads, and the round-1 message |
| VOLE sender / extended-OT sender | `ReceiverOTSeed`, containing punctures and other leaves | Ordered pairs of randomized pads after checking round 1 |

Each signer plays both directional roles during native signing. Thus both corrupt-role arguments are needed. `mta_session_id` hashes the final native SID, ordered sender/receiver IDs and labels; a statement about one direction cannot silently reuse the other direction's effective inputs.

The round-1 struct is `(U,x,t)`. At the pinned dimensions, `U` occupies 5,120 bytes, `x` 16 bytes and `t` 4,096 bytes. The extension matrix digest hashes the SID and every row of **U**. The subsequent challenge fields are derived from this digest and their indexes. **It does not hash x or t.** These fields are checked later against the computed matrix and secret puncture bits. This is a source fact, not an exploit: proof obligations must account for their adaptive selection after learning the U-based challenge.

RVOLE theta hashes the SID and the **raw bytes of every correction entry** in `a_tilde`; it omits U, x, t, the donor transcript, eta and the final mu hash. The row-difference argument below legitimately eliminates a common eta; that does not justify dropping an OT-binding argument. Correction encodings are reduced modulo q for arithmetic but hashed before reduction: different raw encodings of the same scalar are different challenge candidates and must be counted separately.

## 3 Fixed-input determinism: Ldet

Let `F(R,S,U,x,t)` denote the compiled `SoftSpokenOTSender::process`, for a fixed valid-range receiver seed R, SID S and complete round-1 message. Its result is either an error or a unique ordered pair array. There is no RNG parameter. The function checks the matrix relation before returning randomized pad pairs.

Fix the public challenge/expansion/randomization functions, including their complete transcript semantics. The expansion, XOR matrix operations, checks and pad conversion are deterministic. Therefore equal complete inputs have equal outcomes and, on success, identical pad pairs. For accepted check fields the returned pairs depend on R,S,U; x,t affect acceptance. They supply no additional randomness to the pair computation.

Let `alpha_b[j,i] = Reduce_q(F(...).v_b[j][i])`. With these values fixed, the sender helper's subsequent choice of input a, correction rows and eta cannot rewrite alpha in an already evaluated F call. Repeating the same input is **reuse**, not fresh OT. This conclusion is about a deterministic helper under fixed inputs. It is not an import validator or a binding guarantee for untrusted code.

The honest VOLE receiver computes selected pads from its all-leaf matrix before sending round 1. Those selected pads are retained in its private state; later changes to the peer's local seed struct cannot rewrite that retained state. Relating retained pads to one globally consistent effective pair array is the separate malicious realization problem.

## 4 Packed-matrix lemma: Lmatrix

Work over XOR vectors. For block i, let `K[i,z]` be the all-leaf expansions at the SID, and `D[i,z]` the punctured-side expansions for z other than its fixed puncture `delta_i`. Set the missing expansion to zero as the actual helper does. Let X be the honest receiver's packed choice vector, including padding.

For a round-1 message honestly formed from K and X:

`U_i = XOR_z K[i,z] XOR X`.

For bit position b of a puncture block, the compiled matrices are:

`V[i,b] = XOR_{z:bit_b(z)=1} K[i,z]`,

`W[i,b] = XOR_{z:bit_b(delta_i XOR z)=1} D[i,z] XOR bit_b(delta_i)*U_i`.

Write `W0[i,b]` for the latter expression at X=0. It follows by distributivity that

`W[i,b] = W0[i,b] XOR bit_b(delta_i)*X`.

This identity needs no correlation between the two leaf arrays, only that they and the punctures are fixed. If `D[i,z]=K[i,z]` for every non-punctured z, then `W0[i,b]=V[i,b]`. The punctured term's coefficient is zero, so the unavailable leaf cancels from that sum. Thus in the correctly correlated case:

`W[i,b] = V[i,b] XOR bit_b(delta_i)*X`.

After transposition, for column j and the concatenated puncture vector Delta:

`w_j = w0_j XOR X_j*Delta`.

The unordered pair `{H(S,j,w_j), H(S,j,w_j XOR Delta)}` is therefore fixed independently of X_j. Its **order may swap with X_j**. In the correlated case `w0_j=v_j`, so the honest selected pad equals the pair member indexed by X_j. Hash conversion here means the compiled three-output transcript expansion, not a scalar hash with an assumed fresh key.

For fixed malformed dec keys the unordered-pair identity still holds, but `w0_j` need not equal `v_j`. This illustrates why fixed pairs alone do not establish correct OT correlation. If a malicious sender can equivocate its punctures or leaf knowledge, this fixed-state algebra alone does not constrain it.

Nor does the unordered-pair identity immediately supply Claim 6.7's ordered alpha premise. Order, secret choices, accepted transcripts and prior oracle queries must be coupled in the simulator. Sampling the honest random tape earlier may help such a proof, but that coupling has to be written.

## 5 Conditional challenge lemma: Lrow

For the native single-check case `rho=1`, define effective rows over the curve-order field:

`A[j,i] = alpha_1[j,i] - alpha_0[j,i] + C[j,i]`, for i=0,1,2,

where C is the reduced correction matrix. For two rows j,r with nonzero difference in at least one of the first two coordinates, put

`e = (A[j,0]-A[r,0], A[j,1]-A[r,1]) != (0,0)`

and `d = A[j,2]-A[r,2]`.

The equality of their check projections is precisely

`e_0*theta_0 + e_1*theta_1 + d = 0`.

**Conditional statement.** If e,d are fixed before a fresh candidate's challenge answer, and that answer consists of independent uniform field elements, this equation holds with probability 1/q. Condition on one coordinate and solve uniquely for a coordinate with nonzero coefficient. If instead each coordinate is the reduction of independent uniform 256-bit strings, the bound is the maximum residue mass

`p_max = ceil(2^256/q)/2^256 = 2^-255`

at the secp256k1 order. This is a direct anti-concentration bound, not the much larger total-variation reduction bound. It is conditional on the ideal challenge distribution; native Merlin is a fixed implementation, not an oracle we have proved to realize that model.

For Q fresh candidate queries, the union bound is at most `Q*p_max` per specified nonconstant row comparison, plus the probability that fixing/extraction or the challenge model fails. An additional union bound can count J specified row comparisons. The statement includes adaptively chosen candidates based on earlier answers **provided** each current candidate's coefficients are fixed before its own fresh answer. Repeating an existing query gives its existing answer and cannot be treated as another independent trial. Changing un-hashed effective inputs for that same query is exactly the binding gap this condition excludes.

If e=0 and d!=0, there are no roots. If both vanish, there is no inconsistency for this comparison and every challenge satisfies it. The bound is not a whole-protocol acceptance probability, leakage bound or security margin. Applying it to the paper's Delta sets still requires the rest of that simulator and its conditional-distribution arguments.

## 6 Missing malicious-prefix realization: Lbind

A sufficient interface would provide a causal simulator/extractor which, from the accepted setup, its simulated honest state and the adversary's current view/oracle queries, fixes the effective output relation needed for each challenge candidate **before** disclosing the corresponding answer. It may include the permitted selective-abort leakage. It must simulate views and errors faithfully and prevent later reinterpretation of that answer under different effective inputs, except with a stated error probability.

This interface is not a runtime API in PairKey. The model checker contains a small binding-interface definition to make its sequencing requirement executable; it does not claim that the compiled protocol implements it.

| Situation | Required argument; current status |
| --- | --- |
| Corrupt VOLE sender changes local dec seeds/punctures or skips the helper | Extract or fix a consistent effective relation from the actual setup and honest retained pads, rather than trusting the peer's local struct. **Open.** |
| Theta prequeried before honest round 1 arrives | Cover early candidate queries and the eventual honest choices. SID may already be known; theta does not include U. A final-transcript-only extractor is insufficient. **Open.** |
| Same SID/correction query considered against different U candidates | Explain whether setup fixes the needed relation independently of U, or charge any equivalent equivocation/grinding to a proved bound. Local one-attempt journals do not constrain the peer's private offline queries. **Open.** |
| Corrupt VOLE receiver grinds U or selects x,t after its U-based challenge | Use the malicious SoftSpoken correlation/extraction proof with its hidden punctures and allowed leakage. Do not assume the complete statement was hashed. **Open.** |
| Accepted setup leaks a choice bit | Preserve the actual acceptance-conditioned view. Do not replace it by an unconditional honest setup or assert that later retirement erases it. **Open as a compiled realization.** |
| Repeated extensions, wallets, directions and donor generations | Account for accumulated knowledge and all candidate queries. Fresh SIDs separate inputs; they do not prove independence. **Open as reusable L1.** |

### Proposed simulation game and accounting

Run the real setup against a static corrupt role, exposing the permitted transcript/leakage and preserving rejected setups. On each admitted signing attempt, the simulator controls the honest coins and observes the adversary's challenge/output-conversion queries and messages. At a first relevant theta query it must provide a causal effective-input handle or classify that query as incapable of becoming an accepted execution with those coefficients, with an explicit error bound. The handle must reproduce the real selected-pad correlation and the adversary's view; assigning arbitrary pairs merely because they fit a completed transcript is insufficient. A later accepted response under the same theta input must use that same effective relation. Early and repeated queries and all interleavings remain in the game.

If this game has an unconditional whole-transcript failure bound `eps_bind`, and challenge-domain simulation error is `eps_challenge`, the conditional row argument yields at most

`eps_bind + eps_challenge + J*Q*p_max`

for the specified nonconstant row-collision events. This is a proposed reduction accounting identity, not a value for either epsilon. Conditioning on a rare accepted setup can increase a conditional failure bound; uniform security over every accepted view must be proved, or use an unconditional experiment including rejection and quantify the conditioning explicitly. The model's selective-abort leakage must not be silently conditioned away.

Here Q counts **adversarial oracle candidates**, not the 100 admitted attempts. Per-attempt journals, ten-minute rotation and permanent quarantine do not cap private oracle queries, nor erase the history across donor generations. The required generation/session composition is still the reusable lemma R.

The [SoftSpokenOT chapter](https://crypto.iacr.org/2022/papers/530630_1_En_23_Chapter_OnlinePDF.pdf), Theorem 6.2, supports commitment/extraction for its PPRF construction in a specified affine-leakage hybrid. Theorem 5.1 has distinct output-conversion assumptions. Neither theorem can be cited as the missing entire compiled lemma without mapping the actual expansion, one-message challenge, randomization, reused seeds and accepted leakage.

In particular, `S=128` denotes the compiled check field dimension. A `Q/2^128` grinding estimate would require a relevant nonzero equation fixed before a fresh uniform check challenge, plus the hidden-puncture and post-challenge response argument. The unchecked inference “matrix hashed, therefore malicious receiver advantage negligible” is not established here. No receiver-side attack is demonstrated by observing this obligation.

Ldet and Lmatrix therefore explain why the 2026 late-input hybrid counterexample is not reproduced by an ordinary call to the compiled helper. Lrow supplies the conditional algebra needed after Lbind. They do not prove Sender Random OT, the RVOLE output distribution, the original Theorem 6.1, or the revised statistical margins.

## 7 Code map

Paths below are relative to `sl-oblivious 1.0.0-beta/src` except where noted; the checker records absolute paths and SHA256 hashes.

| Fact | Code anchor |
| --- | --- |
| Punctures and leaf-key storage | `soft_spoken/soft_spoken_ot.rs:48`, `ReceiverOTSeed` |
| Honest choice/padding and U construction | `soft_spoken/soft_spoken_ot.rs:124-156` |
| Honest V and selected-pad conversion | `soft_spoken/soft_spoken_ot.rs:161-176,235-245` |
| Punctured expansions and W construction | `soft_spoken/soft_spoken_ot.rs:294-340` |
| Challenge hashes U; derived GF check coefficients | `soft_spoken/soft_spoken_ot.rs:316-318,340,355-371` |
| x,t response check before pair conversion | `soft_spoken/soft_spoken_ot.rs:376-409` |
| Ordered pad conversion | `soft_spoken/soft_spoken_ot.rs:413-441` |
| Honest receiver fixes beta and retained pads | `rvole.rs:93-131` |
| Receiver theta from raw correction entries | `rvole.rs:141-161` |
| Sender extension before correction and theta | `rvole.rs:256-328` |
| Retained selected pads and final mu verification | `rvole.rs:167-228` |
| Directional SID | Native `src/sign/dsg.rs:1061`, `mta_session_id` |
| Donor extraction/transplantation boundary | PairKey `src/d/material.rs:62-113`; seed provenance/distribution is a separate obligation |

## 8 Executable evidence and limits

`review-evidence/output-fixing/checks.py` checks:

- All 336 nonconstant affine predicates over the toy field q=7, across 16,464 challenge points: exactly seven roots each.
- All 1,320 nonconstant biased two-coordinate predicates over q=11 with four-bit raw challenges: the maximum-atom bound holds. Computes the exact conditional secp256k1 256-bit bound.
- An abstract post-challenge-OT negative control with four inconsistent effective rows: all 16 choice vectors pass the check projection. This deliberately models the weak hybrid and **is not a compiled-stack exploit**.
- Packed-matrix and fixed-unordered-pair identities across all 256 packed choice vectors, with correlated and fixed malformed seed arrays.
- A model binding-interface control that rejects late replacement and unfixed challenge queries. This model is an assumption boundary, not a new protocol enforcement mechanism.
- Pinned source order/labels and the actual primitive report.

`review-evidence/output-fixing/native_probe.rs` runs an isolated copy of the experiment with its unchanged lockfile/native dependency. It uses **public deterministic test fixtures** and the library's honest correlated-seed generator; it does not run native DKG or exercise malicious setup. Across four fixture generations and four SIDs each it verifies:

- 8,192 selected pad matches and 8,192 deterministic same-context replayed rows.
- 8,192 complementary-choice row swaps with unchanged selected pads under the same SID.
- 6,144 observed row-pair differences between successive SIDs. This is an observed difference, not an independence test.
- 32 native multiplication identities and deterministic repeated RVOLE responses.
- 16 native refusals each for x-field and t-field mutations leaving U unchanged, and 16 simple correction-mutation refusals with successful unchanged controls.

Repeated SIDs and deterministic entropy are intentional primitive fixtures, outside the signer's admission path. No real root, wallet secret or production nonce is used or read. The fixture RNG must never be connected to workers. The probe has no finding about nonce safety.

Evidence is saved under ignored `.local/spike-d-output-fixing-20261012/`, including the isolated manifest, native report, exact checker report and source/provenance hashes. Only the copied crate's manifest changes to select an example and its absolute native dependency path. The experiment's manifest, lockfile and native code remain unchanged.

Example reproduction after generating `native-probe.json` with the isolated crate:

```sh
python3 experiments/silence-dkls23/review-evidence/output-fixing/checks.py \
  --native-evidence .local/spike-d-output-fixing-20261012/native-probe.json \
  --output .local/spike-d-output-fixing-20261012/checks.json
```

## 9 Questions for independent review

1. Can an online simulator extract the effective ordered relation from this compiled setup/extension for either corrupt role, including early theta queries, without assuming the corrupt peer follows `process`?
2. Can the fixed-unordered-pair coupling supply the needed ordered-output hybrid, or does that step require changing the modeled OT service? What leakage and error terms apply?
3. Does the published malicious extension proof cover this exact U-only one-message challenge with adaptively selected x,t and the pinned randomization function?
4. How does that realization extend across fresh SIDs with the same donor leaves, accepted selective aborts, directions and wallet-derived packages?
5. After resolving those premises, which parts of Claim 6.7 survive in this variant, and what separate revised distribution/dimension bound is applicable?

**Closure:** Ldet and the finite-field identities are established; Lrow is proved under its stated fixing/challenge assumptions. Lbind and reusable malicious realization remain open. Further successful primitive or signing tests cannot replace them.
