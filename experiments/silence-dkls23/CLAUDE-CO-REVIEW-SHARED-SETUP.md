# Claude co-review: derived shares with shared native setup across wallets

2026-10-11. Answers to the six co-review questions on the design evidenced in
`review-evidence/direct-derived-integration` and `review-evidence/ot-cross-wallet-reuse` at
commit `2b1cfb8`, read with [SHARE-FLOW-AND-OT-REUSE.md](SHARE-FLOW-AND-OT-REUSE.md). Native pin
`af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`, `sl-oblivious 1.0.0-beta`, DKLs23 eprint 2023/765 as
the theorem source, 2026/976 as reference only. Every statement about code below was checked against
the pinned source; the harness sources were read in full; both harnesses were rerun independently,
see section 7. No exploit is asserted. No code, parameter or dependency change is proposed.

## 0. What the evidence establishes, and the construction it tests

The construction: each party derives its additive contribution from its root with the existing KDF,
`src/lib.rs:64-75`; the parties register `A`, `B`, `Q = A + B` and a chain code as a public record;
one native DKG run per pair acts as a setup donor whose OT seeds and masking seed are taken through a
test accessor and shared by every wallet; each signing attempt rebuilds a native keyshare with the
research constructor, shares `a/2` and `-b` at coordinates 1 and 2, a package id hashing the record
digest with the donor's session id, and the record digest as extra data; native `sign::run` then runs
with a fresh seed and a random instance id. Stage 1 used a donor per wallet, stage 2 one donor for all
twenty wallets. Both stages passed 500 verified signatures with four concurrent lanes, mixing same-wallet
and different-wallet sessions, root and child paths, fixed and random prehashes. Mixed wallets and mixed
setup generations fail with `InvalidFinalSessionID`.

What it establishes: the native signer accepts this representation; shared setup material across
wallets and concurrent sessions is functionally sound; the package id separates wallets and setup
generations at the native round-2 check; packages are deterministic from roots, record and setup.
What it does not establish, as both reports say: malicious-security of the registration, any
distributional property of setup, or the failure policy. The two misuse probes are correct and I
reproduced them; their meaning is explained under questions 2 and 4.

One observation the reports do not draw out: because the donor is a native DKG run, the shared OT and
masking material comes from the audited key-generation code, not from the exported-primitive pool.
That removes the code-equivalence half of O3 that the pool needed and leaves the constructor, the
cross-wallet reuse rule and the registration contract as the custom surface. The price relative to the
per-wallet migration route is that the setup secrets must be persisted, so this is not roots-only
secret persistence; it is roots plus one setup blob per pair, about 66 KB, plus public records.

## 1. Deterministic contributions and the signer's key-generation assumptions

Not yet, and the gap is the same one identified for Spike C. Theorem 4.1 takes its key from
Functionality 3.2, which receives the corrupt contribution before the honest polynomial is sampled.
Native keygen realizes that order by committing in round 1 and revealing in round 2. The tested
registration exchanges `A` and `B` in the clear through the manifest, and today's `Hello` and
`Describe` reveal the point, so a corrupt peer chooses `b` after seeing `A`. In the honest-party
model this is harmless because an honest peer derives `b` from its root; the malicious model needs
the ordering.

Required beyond the honest-party model:
- Commit before reveal: a salted, binding commitment to the contribution, journaled with create-new and
  fsync and acknowledged before either reveal, as Mode 1 in
  [DERIVED-SHARES-VIA-MIGRATION.md](DERIVED-SHARES-VIA-MIGRATION.md); or the native initial mode of
  [MODE-2-MINIMAL-SPEC.md](MODE-2-MINIMAL-SPEC.md), which lets the audited round-1 commitment do it.
- Retry rules: once an honest contribution for a wallet id has been revealed, that id is completed only
  against the peer's already committed value or retired; no fresh peer contribution is ever accepted
  for it; attempts are serialized per root, role and wallet id; a different peer, ceremony id or
  version does not make the contribution fresh.
- The PRF assumption on HKDF-SHA512 with the documented salt and info, which gives independent uniform
  contributions per wallet and makes the honest side of the functionality's sampling step sound.
- A written mapping before Theorem 4.1 is invoked: the commitment functionality, the simulator that
  programs the honest point from the functionality's key and the corrupt contribution, prior
  disclosures, and concurrent wallets. Section 7 of the paper shows no proof of knowledge is needed, so
  the endorsements stay as identity binding and nothing more.
- No change to the setup side: the paper's one-time initialization in section 8.4 is key generation per
  key plus two RVOLE instances and zero-seed exchange per pair, so sharing setup across wallets does
  not interact with the key-generation obligation.

## 2. Reuse of OT setup and the masking seed across wallets and concurrent sessions

Yes, under one condition that the design must make structural: every extension invocation uses a
session id that has never been used with that setup. The paper's cost model assumes exactly this
reuse, setup once per pair of parties and reused in all instances, section 8.2, and Functionality 5.1
requires a fresh session id per instance. The pinned implementation keeps the seeds read-only during
signing, keys the SoftSpoken expansion, correlation check and output hash by the MtA session id, and
derives that id from the final session id, which hashes both parties' round-1 session ids and the
package id, `sign/dsg.rs:162-167` and `1061-1075`. The honest party's round-1 session id is drawn
from the ChaCha RNG seeded by the per-run seed, `sign/dsg.rs:75-99`. So the uniqueness of the MtA
session id rests entirely on the honest party supplying a fresh seed to `sign::run`, whatever the
peer does. Concurrency changes nothing: sessions on one keyshare are already concurrent in the native
model, and sessions on different wallets with the same seeds are the same situation with different
package ids.

The choice-XOR probe is the demonstration of what the condition protects. The receiver's public matrix
is the per-session expansion of the seeds XOR the choices, `soft_spoken_ot.rs:117-227`; with the same
seed and the same session id the expansions cancel and the XOR of two matrices is the XOR of the two
choice vectors. That is a property of every OT extension, not of this one, and a fresh session id removes
it, as the probe shows.

The masking seed may be shared as well. The masks are `±Reduce(H(label, seed, digest_i, label))`,
`sign/dsg.rs:876-914`, with `digest_i` hashing both parties' round-1 session ids and nonce commitments,
so they differ per session; for two parties they are negatives of each other and hide nothing from the
peer; the 2026 reference notes the zero-sharing functionality is unnecessary in this setting. Keep the
seed secret from third parties as setup material, but its sharing across wallets is not a security
boundary.

Rules the integration must enforce, all of which the harness already follows:
- A fresh OS-entropy seed for every `sign::run`; never derived from a root, wallet id or counter.
- No resumption of an interrupted signing run, no cloning of RNG state, no snapshot of an in-flight
  signer.
- One setup generation at a time per pairing, with its generation id agreed by both parties and bound
  into the package id, as the harness does with the donor's session id.
- The audit covered reuse per keyshare, not across wallets. There is no known degradation with the
  number of extensions per setup given unique session ids, but the formal statement is part of the open
  O3 lemma, and periodic rotation through a fresh native donor is cheap insurance.

## 3. Session domains, freshness and rollback

The domains are sufficient. Wallet binding sits in the MtA domain through the package id and in the
message ids through the instance id; attempt binding sits in both round-1 session ids. The masking
digest is attempt-bound but not wallet-bound, and that is acceptable because the mask is a public
function of the session that both signers compute; a collision between two sessions' masks would
require an honest round-1 session id to repeat, which is an RNG failure, not a domain gap. Adding the
wallet or attempt to the masking digest would require a native change and would buy detection, not
safety.

What the integration must guarantee, because the native code cannot:
- Freshness of the honest party's seed per attempt. Its failure is fatal independently of OT: the same
  seed replays the instance key share and the nonce commitment blinding, which is ECDSA nonce reuse,
  and replays the session id, which is the choice-XOR condition.
- Instance ids unique per attempt, journaled, and refused if seen before. A rolled-back peer that
  re-presents an old instance id is then refused; a rolled-back honest party is protected by its own
  fresh seed in any case.
- No restore of a running signer from a snapshot, and no restart of a failed transcript. A failed attempt
  is abandoned and any new attempt gets fresh randomness and a new instance id.
- `InvalidFinalSessionID` is a context disagreement, burned without attribution, as the lifecycle already
  does; it is also the signal that two peers hold different setup generations, so the generation agreement
  belongs before `sign::run`.

## 4. Failure policy under selective-abort leakage with shared setup

The leakage target is the correlation secret of the shared setup and the quarantine target is the peer,
and both are shared by every wallet of the pairing. The policy therefore spans every wallet sharing the
setup and every concurrent session with that peer, which is what Protocol 3.6 step 8 and the audit's
TOB-SILA-12 require per key, applied to the pairing.

| Failure | Attribution | Required action across the shared setup |
|---|---|---|
| `AbortProtocolAndBanParty`, `InvalidMessage`, `InvalidCommitment`, `InvalidDigest` in signing; decode, proof or commitment failures during setup | peer | Quarantine the peer for the pairing, cancel every concurrent session with it, retire the setup generation and never reuse it; a new setup with that peer only after the incident is cleared by the incident authority, never by a wallet change or a fresh donor |
| `FailedCheck` and other aggregate checks | unattributed | Freeze the pairing configuration for all wallets, stop concurrent sessions, investigate before any new generation |
| `InvalidFinalSessionID`, channel context mismatch | none | Burn the attempt; reconcile setup generation and record state; no setup retirement |
| Timeouts, disconnects, peer abort messages | none | Burn the attempt; rate-limit; a cluster of unexplained aborts is grounds to rotate the setup even without attribution |

Why retirement of the setup on any attributable failure: a wrong selective-abort guess is always visible
as one of the attributable failures above, and the guesses that succeed are invisible. Retiring the
setup after the first visible failure caps what an adversary can accumulate against one correlation
secret, which is the same discipline the native model applies per keyshare when the keyshare is
abandoned with the peer. Single-use material limits a lucky guess to one extension; shared setup
accumulates lucky guesses across wallets until retirement, which is the trade this design makes for
one-time setup, and it is the argument for a rotation period in addition to retirement on failure.

## 5. Binding the derivation

Bind explicitly. The KDF info today is the digest of `(role, key_id)`, so the same root, role and
wallet id reproduce the same contribution with any peer, which the harness confirms. That couples
wallets across pairings and breaks the first-disclosure premise of question 1 the moment a root is used
with a second peer. A strictly enforced one-root-per-pairing policy is sufficient in principle, but the
enforcement would live in the root authority, outside anything the protocol checks. Explicit binding
costs nothing: a versioned info covering the derivation version, a pairing identifier such as the ordered
identity pair or a pairing namespace, a tenant or namespace label, a root epoch, the role and the wallet
id. Changing the derivation changes keys, so this is a new derivation version for new wallets, never a
retrofit of funded ones. A fixed root cannot provide proactive security whatever the binding, as both
reports state; rotation of setup does not change the contributions.

## 6. Audit and concrete-security claims for this pin and its parameters

What applies: the Trail of Bits review of February 2024 targeted `dkls23 1510c2f` and `sl-crypto
a6b0147` and covered key generation, signing, refresh and the OT stack; 14 of 15 findings were
resolved and TOB-SILA-13, on combining aspects of different protocols, was partially resolved; the
RVOLE replacement was separately reviewed against Protocol 5.2 in Appendix F. The pin `af5ada2a`
carries post-audit refactors that the README documents without a new review. Migration, import,
export and quorum change are outside the audited list. Nothing in the audit addresses a custom
constructor, this registration, or sharing setup across wallets; the paper's section 8.2 supports the
sharing as a model, not as a certification.

Parameters: `KAPPA = 256`, `LAMBDA_C = 256`, `LAMBDA_S = 128`, `S = 128`, `L_BATCH = 2`, `RHO = 1`,
`OT_WIDTH = 3`, `K = 4`, 64 trees, `XI = 512 = KAPPA + 2·LAMBDA_S`. These satisfy Protocol 5.2's
dimension rules, and the audit recommended 128 for `LAMBDA_C` where the pin uses 256. The 2026/976
preprint argues that the Impagliazzo-Naor step in the paper's Lemma 6.2 does not give the claimed
statistical margin for the correlation-check dimension and that a 512-row check yields far fewer
statistical bits than 128 under its analysis. That is an upstream question; no parameter change is
proposed, and no concrete-security bit count for the compiled stack exists in writing today.

What would close the gaps, in order of value:
1. Silence's answer to the O3 lemma in [O3-O4-DEEP-DIVE.md](O3-O4-DEEP-DIVE.md): that the compiled
   setup-and-extension stack, with its permitted selective-abort leakage, realizes the OT service the
   RVOLE proof assumes for fresh session ids and inputs chosen after setup, with concrete bounds for
   these parameters and for multi-session use, outside the DKG wrapper.
2. Silence's reconciliation of 2026/976 with the pin's parameters.
3. The registration mapping of question 1, written and reviewed.
4. Tests, all cheap: session-id and instance-id uniqueness under concurrency and restart; a simulated
   RNG replay that is refused by the instance-id journal; cross-wallet propagation of quarantine, freeze
   and setup retirement; the choice-XOR negative control and the selective-abort probe kept as permanent
   regression tests; KDF binding across peers once the derivation is versioned; a differential test of
   the constructor path against a native-generated wallet with the same inputs, which the layout test in
   `review-evidence/` already does for the constructor's layout.

## 7. Independent rerun

Both runners were exported from commit `2b1cfb8` and executed with `python3 -I`, patched only to
point `root` at the repository, to create their scratch trees and Cargo target under my scratch
directory, and therefore to write nothing into the repository. They build from the cached upstream
archive, whose hash the runners assert, with `--offline --locked --release`; the derived-share runner
copies the working-tree research sources, which are identical to HEAD. Filtered log with provenance:
`review-evidence/shared-setup-claude-rerun.output.txt`.

- OT reuse harness: the same-seed same-session-id negative control exposes the choice XOR and both
  per-extension checks accept; a fresh session id removes the cancellation and a wrong id or altered
  message is rejected; selective-abort reproduction 12 of 32 accepted, all on the unmodified branch,
  20 decode rejections; 20 native controls; 500 sequential and 500 concurrent signatures verified with
  the OT state unchanged; mismatched OT states rejected with `AbortProtocolAndBanParty` on both sides;
  mixed-wallet packages rejected with `InvalidFinalSessionID` on both sides. Exit 0.
- Derived-share harness: KDF determinism, role and wallet separation and wrong-root refusal; the
  cross-peer repetition finding reproduced; constructor accepts the valid input and rejects seven
  malformed cases; registration mutations rejected; public stores reload; stage 1 and stage 2 each
  500 verified signatures; mixed wallets and mixed setup generations rejected with
  `InvalidFinalSessionID`; packages deterministic from roots, record and setup. Exit 0.

These reruns confirm the functional claims and the two leakage mechanisms. They add nothing to the
security questions above, which is the point the reports themselves make.

## 8. Paste-ready TL;DR

Reviewed the shared-setup design and both evidence packages against the pin; both harnesses rerun
independently. Answers: (1) deterministic contributions do not yet meet the signer's key-generation
assumption in the malicious model; commit-before-reveal or native initial mode, binding retry rules,
the PRF assumption and a written mapping are required. (2) Reusing OT setup and the masking seed
across wallets and concurrent sessions is within the paper's model and the native mechanics, on the
single structural condition that every extension has a fresh session id, which the honest party's
fresh seed guarantees; the choice-XOR probe is what failure of that condition looks like. (3) Domains
are sufficient; the masking digest needs no wallet binding; freshness and rollback protection belong
to the signer, with instance-id journals as the detector. (4) Any attributable failure quarantines the
peer, cancels concurrent sessions and retires the shared setup for every wallet; aggregate failures
freeze the pairing; timeouts burn only the attempt; add a rotation period because shared setup
accumulates lucky guesses until retirement. (5) Bind the derivation explicitly to pairing, namespace,
epoch and version in a new derivation version. (6) The audit covers the native protocols at an older
commit, not this constructor, registration or cross-wallet sharing; parameters satisfy Protocol 5.2;
no written concrete bound exists; Silence's answer to the O3 lemma and to 2026/976 would close most of
it. Note the donor trick makes the shared material audited-DKG output, which removes the pool's
code-equivalence question but requires persisting setup secrets per pair.
