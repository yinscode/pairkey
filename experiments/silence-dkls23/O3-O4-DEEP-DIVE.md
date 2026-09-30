# O3/O4: proof-boundary check and adversarial probes

2026-10-11. Follow-up to the [focused composition review](FOCUSED-OT-POOL-COMPOSITION-REVIEW.md).
Same native pin and original Spike C construction. Documentation and review-only
scratch probes; registration, application/native source, parameters and locked
dependencies are unchanged. No independent audit or complete UC proof is claimed.

## Result and revised scope

**O3 stays open at a specific inherited proof boundary. O4's local binding,
ordering and ownership requirements are supported; full cryptographic closure
remains conditional on O3, admissible key inputs and the required failure policy.**

There is no newly identified pool-specific forgery or share-recovery attack.
There is new adversarial evidence that accepted native preprocessing can have
biased hidden choices. Thus a claim of equality with the all-honest setup
distribution would be false. The appropriate target is a malicious-security
functionality with its permitted leakage/abort behavior.

## 1. O3: the exact implementation and proof boundary

| Boundary | Checked evidence | Assessment |
|---|---|---|
| Base OT to all-but-one setup | Same native EndemicOT and PPRF functions, directional SIDs and validation; fresh honest randomness | No pool-specific primitive substitution found |
| PPRF proof and admitted choices | Native proof check can reject altered proofs, but selective acceptance can bias a base choice; new probe below | “Proof accepted” does not imply all-honest output distribution |
| All-but-one seeds to extended OT | Online expansion, matrix check and output hash use native code, per-session SIDs and per-row indices | Exact compiled malicious-security mapping still required |
| Extended OT to RVOLE | Native RVOLE preserves its theta/mu checks; historical supplemental audit reviewed the replacement | Does not discharge the OT functionality assumed by that RVOLE proof |
| Zero masks | Common seed fixed before fresh signing randomness; both masks are opposite evaluations at the same digest | Two-party mask argument below; not an unbiased-completion claim |

### What the sources actually establish

The [published SoftSpokenOT paper](https://crypto.iacr.org/2022/papers/530630_1_En_23_Chapter_OnlinePDF.pdf)
uses endemic functionalities and explicitly permits a restricted class of
selective-abort leakage. Its PPRF consistency result is Theorem 6.2; output
conversion is a separate result, Theorem 5.1, with its own hash assumptions.
These are not a single “PPRF verifies, therefore OT is secure” implication.

The compiled code uses `all_but_one.rs` for the tree/proof, and
`soft_spoken_ot.rs` for seed expansion, a finite-field matrix check and output
randomization. The output hash includes online SID and row index; proof, expansion,
randomization and RVOLE challenges have separate native labels. These are useful
correspondences, not an automatically applicable theorem for their combination.
In particular, the paper's proof/output PRG separation must be mapped to the
implementation's stored leaves and later domain-separated expansion.

The [DKLs23 paper](https://eprint.iacr.org/2023/765), section 5.1, gives a
Fiat–Shamir adaptation. Theorem 6.1 and Claim 6.7 rely on the endemic OT
functionality and its fixing order. Hashing the setup transcript does not by
itself establish that order for every deviating peer.

The local Trail of Bits report's fix review is explicit: TOB-SILA-13 was
**partially resolved**. The old DKLs18 changes were removed, but the combination
of Roy22, KOS15 and DKLs23 still needed an explicit specification. Appendix F
separately reviewed the RVOLE replacement. See printed pp. 58–63 in
[the bundled audit](../../.local/silence-dkls23/sources/dkls23-af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/docs/ToB-SilenceLaboratories_2024.04.10.pdf).
This is a historical assurance gap, not evidence that the current pin is broken
or that no later private analysis exists.

**The precise remaining O3 lemma:** for the compiled setup/extension realization,
including its allowed setup leakage, show how a malicious party's effective OT
outputs are fixed/extracted in the order needed by the RVOLE proof, with a bound
for the actual parameters and random-oracle instantiation. Include both corrupt
roles and polynomially many sessions with fresh identifiers. Public API comments
and honest function execution order do not supply that simulator.

This is shared with native Silence use, with an additional question whether
the exported setup boundary may be used independently as PairKey does. I did
not find a native DKG proof tying an OT seed to the signing scalar that PairKey
would need to reproduce. That absence is supporting evidence for modularity,
not a substitute for the missing realization argument.

### New adversarial probe: selected-branch failure

The test runs actual native EndemicOT/PPRF. A malicious sender constructs a valid
reply and PPRF proof, then replaces only branch 0's curve point in the first
base OT with an invalid encoding. Native `EndemicOTReceiver::process` decodes
only the selected branch (`endemic_ot.rs:239–269`).

- Honest base choice 0: `Decode error`.
- Honest base choice 1: the native PPRF proof still verifies. The corresponding
  bit of the punctured index confirms that every accepted trial had choice 1.

Independent local trials observed one accepted setup and four decode rejections.
This is an executable counterexample to *unconditional honest-distribution*
claims about accepted setup. It is not a signing attack or a way to bypass
PairKey's incident authority. The trials were fresh isolated experiments, not
repeated requests to a quarantined production peer.

The real pool maps that decode error to `QuarantinePeer`
(`pool_worker.rs:168`, `lifecycle.rs:96–107`). That mapping was source-checked;
this new primitive test does not execute the worker's incident publication.
Native DKG also calls the same receiver function. The protocol therefore needs
the allowed-leakage argument even without the pool. Do not “fix” this by editing
native parameters or by assuming that freshness makes denylisting unnecessary.

Source and output:
[probe](review-evidence/o3_selective_abort_probe.rs),
[log](review-evidence/o3_selective_abort_probe.output.txt).

## 2. Two-party zero-mask argument

The pool fixes the common seed sigma before the honest worker creates signing
randomness. Native signing computes a digest D from ordered R1 SIDs and nonce
commitments, then produces masks `-Reduce(H(label, sigma, D, label))` and its
positive counterpart. Their sum is exactly zero regardless of seed bias.

A narrower **mask-distribution argument in the random-oracle model** is available:

1. Treat the zero-mask hash domain as an independent random oracle, distinct
   from setup, commitments and MtA. Allow the corrupt party to know sigma.
2. For each previously unqueried `(sigma, D)`, the oracle answer is fresh uniform
   bits. The scalar has the native reduction distribution; replacing it by a
   uniform field element incurs the native reduction bias.
3. The fresh honest R1 SID prevents efficient advance enumeration of the actual
   D before signing, subject to RNG/hash assumptions and query/collision bounds.
   A corrupt party may query candidate digests after learning honest R1 and
   choose which to use; the argument must preserve those adaptive queries.
4. In two parties, the corrupt party's FZero output already determines the
   honest party's opposite mask. Sampling candidate masks and withholding an
   invocation is therefore not extra secrecy leakage merely because sigma is
   shared. Aborting can still bias the distribution of completed sessions.

This explains why an arbitrary previously fixed seed need not be an unbiased
coin or secret from either signer. It narrows the old zero-seed concern to the
oracle/invocation mapping and its query bounds. It does **not** prove that every
adaptive mask-selection strategy is harmless in the complete signing protocol,
nor replace a composable proof with fixed hashes. The full argument must map
native D to the signing/FZero session and preserve adversarial query visibility.

The package SID is not directly inside D, but both coins are in the completed
setup digest, and the package-bound MtA SID commits to that transcript. Fresh
honest R1 randomness separates D across attempts. I found no missing-mask-binding
attack; adding another hash field is not justified by this review.

## 3. O4: check each transition, not just the final digest

The following argument assumes collision-resistant/domain-separated hashes,
authenticated channels, fresh honest RNG and the stated honest local authority.
It does not assume a corrupt peer erases or follows its own reservation rules.

| Transition | Why the checked honest endpoint cannot silently switch contexts |
|---|---|
| Setup context to stored entry | Channel key binds I; phase/sender are authenticated; validated bodies bind T; equal authenticated T ACK precedes admission |
| Ready entry to request | Atomically removed and retired before consumption agreement; provenance checks bind I/T/entry |
| Request to native invocation | Agreement channel key binds C; C covers wallet record, path, prehash, policy and attempt; package SID and native InstanceId derive from C |
| Invocation to online OT | Package fixed before fresh native R1; final/MtA SIDs include it; no second honest reservation can reuse the entry |
| Abort to retry | Reserved entry cannot return; command failure destroys that worker generation; fresh entry/setup/signing randomness required; incident rules remain effective |

Thus changing the wallet **before reservation** is an allowed choice of online
input. Changing it **after the honest reservation** cannot change that honest
invocation without disagreement or breaking a binding assumption. A corrupt peer
can always choose bad private state or messages; the underlying malicious OT and
signing guarantees must address those deviations.

For concurrent entries/workers, disjoint authenticated contexts and irreversible
honest reservations supply the local separation argument. Carrying that through
arbitrary adversarial scheduling requires the underlying primitives' composable
security and the required cross-session failure cutoff. The research worker is
sequential; these new probes do not exhaust interleavings or establish cross-host
authority. Those limits remain explicit.

### New channel mutation matrix

A scratch child module runs the actual `SetupChannel::bound/exchange` code with
two crossed Frame queues and fresh DH keys. Two matching-context controls pass.
All 20 mismatches fail on both sides with typed `Burn/Context` errors:

- Eleven consumption fields: version, input, completed digest, entry, wallet,
  scheme, path, prehash, receipt, policy version and attempt.
- Eight setup fields: version, recipe, each peer, each boot, configuration and entry.
- One phase mismatch under an otherwise identical context.

This checks actual AEAD rejection, not just digest inequality. It is a channel
boundary test: it does not perform enrollment, durable reservation, incident
publication or native signing. The earlier worker demo and ownership tests are
separate evidence for those paths. Corrupt choices of an internally consistent
context are not tested as mismatches; policy/key-admissibility rules govern them.

Source and output:
[probe](review-evidence/o4_setup_channel_probe.rs),
[log](review-evidence/o4_setup_channel_probe.output.txt).

## 4. What can now be marked satisfied

| Obligation | Result |
|---|---|
| O3 role/field/call correspondence | Satisfied as checked implementation correspondence |
| O3 equality to all-honest output distribution | Wrong target; explicit selective-acceptance counterexample |
| O3 common zero mask and fresh invocation separation | Supported under explicit two-party/RNG/RO assumptions; full protocol mapping remains conditional |
| O3 compiled malicious OT realization | Still open, with the exact remaining lemma identified above |
| O4 local provenance, late binding and honest at-most-once use | Requirements supported under the declared authority/crypto assumptions; no counterexample found |
| O4 full adaptive/concurrent security | Conditional on the O3 primitive contract, O1/O2 key inputs and O5 failure obligations; not an unconditional closure |

The concrete question for Silence is now: **does this compiled setup/extension
stack, including its permitted selective-failure leakage, realize the required
OT/RVOLE service for fresh online SIDs and inputs selected after setup, outside
the DKG wrapper?** Request the specification/argument and concrete bounds, not
merely confirmation that the functions are the same.

Audit-to-pin correspondence remains O6. The 2026 paper remains supplementary;
this review changes no parameter or dependency. The two new probes passed in
the scratch experiment. Their provenance and the examined source hashes are in
[the follow-up manifest](review-evidence/o3_o4_followup_manifest.json).
