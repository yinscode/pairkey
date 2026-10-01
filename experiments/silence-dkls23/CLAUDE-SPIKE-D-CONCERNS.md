# Spike D concerns with severity and fix

2026-10-12. Scope: the donor route as implemented at `0f6e0557` on `codex/spike-d` with the proof
dossier at `3b065e5`, read against the pinned native source, `sl-oblivious 1.0.0-beta`, DKLs23
eprint 2023/765 and 2026/976. Sources: [CLAUDE-REVIEW-SPIKE-D.md](CLAUDE-REVIEW-SPIKE-D.md),
[CLAUDE-REVIEW-SPIKE-D-0f6e055.md](CLAUDE-REVIEW-SPIKE-D-0f6e055.md),
[CLAUDE-REVIEW-SPIKE-D-PROOF-DOSSIER.md](CLAUDE-REVIEW-SPIKE-D-PROOF-DOSSIER.md), the shared-setup
harnesses at `2b1cfb8` and the dossier's closure list. No exploit is asserted anywhere. Line
references are to Sol's worktree and the native crate.

## Severity scale

| Level | Meaning |
|---|---|
| S1 | Open proof obligation. No malicious-security claim exists without it. Closable by written lemmas and Silence's answers, not by tests. |
| S2 | Concrete exposure under a plausible operational failure, or an unguarded path. Fix before any pilot. |
| S3 | Bounded or unlikely impact, or a property shared with native production. Fix before scale-out. |
| S4 | Hygiene, availability or documentation. Schedule. |

## A. Concerns specific to the donor route

| # | Concern | Severity | Fix | Status |
|---|---|---|---|---|
| A1 | One correlation secret per direction is reused across wallets and up to 100 sessions. The reuse lemma, the output-fixing premise of Claim 6.7 for the SoftSpoken realization, and the transplant of donor seeds under a different package id are unproven. Within the paper's section 8.2 model and native per-keyshare practice, but no written argument. | S1 | Write the fixing-order lemma: the sender's extended outputs are computed at `rvole.rs:256` from donor-time base-OT material and the receiver's round-1 matrix, before the correction rows and theta at 289-317. Write the transplant lemma: the seeds are a correlation independent of the DKG session that produced them. Ask Silence to confirm the compiled realization of Functionality 5.1 and a reuse contract. No code change. | Open; dossier states lemma R and a counterexample to the stronger claim |
| A2 | Pad reuse. The same donor seeds, the same honest round-1 id and a replayed peer id reproduce the extension pad and expose the XOR of two choice vectors. Demonstrated only under forced identical seed and session id. Spike D draws fresh OS entropy per attempt at `src/d_worker.rs:467-471`, so the condition needs the OS RNG itself to repeat, as after a restored image with an unreseeded guest RNG. | S2 | Platform rule: no snapshot, restore or clone of a signer. Verify the guest RNG reseeds on restore. Mix a sealed or hardware monotonic counter into the hedged seed at `src/d.rs:288-305`. Keep per-attempt OS entropy. | Entropy per attempt landed; platform controls open |
| A3 | Bounds and incident state are per process and per filesystem. A cloned process holds its own donor, use counter and abort markers, so the 100 bound is hygiene per process and an operator reset or rollback reopens a quarantined pairing. | S2 | Mirror the per-generation use counter on the peer side, keyed by pairing and generation, so both parties enforce the bound and a clone cannot exceed it unseen. Anchor quarantine outside the signer: peer mirror plus an append-only log, lifted only by a two-party ceremony. One attested instance per pairing. | Open |
| A4 | Admission is the only integrity check for package fields native ignores. The tamper matrix shows native accepts altered public share, key id and extra, while coordinate and aggregate-key tampering freeze and session tampering burns. | S2 | After `Donor::package` at `src/d/material.rs:124-161`, recompute public shares, key id and extra from the registered record and compare, failing closed. Property-test admission against the record. | Owed |
| A5 | Research-fault paths exist in the binary behind a cargo feature, including environment-variable fault injection at `src/d_worker.rs:305-314` and seed faults at 467-477. | S2 until guarded | CI assertion that release artifacts are built without the feature. Runtime refusal to start a production configuration if the feature is compiled in. Move environment-variable faults into test-only code. | Owed |
| A6 | Every failure discards the donor, including non-attributable timeouts and duplicate deliveries that the round-1 guard treats as replay. Three transport events in 60 s then refuse every command at `src/d/journal.rs:199-215`. A flaky link stalls all wallets of the pair and forces repeated four-flight donor DKGs. | S3 availability | Dedupe frames by id in front of the guard. Pre-generate the next donor generation in the background as a warm standby. Keep the discard rule. Do not count the signer's own age cancellation as a peer transport event. | Open |
| A7 | Age expiry cancels an in-flight attempt at `src/d_worker.rs:597` and the peer sees a timeout. | S4 | Refuse to start an attempt when remaining age is below the 30 s command timeout at 598. | Open |
| A8 | Wall-clock regression refuses all operations at `src/d/journal.rs:207`, and age is wall-clock based. An NTP step backwards stalls the service until the clock catches up. | S4 | Use a monotonic clock for windows and age, the wall clock for records only, with a small tolerance. | Open |
| A9 | Round-1 guard journals and abort markers grow per signature with no pruning. | S4 | Retention policy: compact acknowledged instance ids into a bounded ledger, keep only abort markers inside the live window. | Open |
| A10 | Prehash equivalence modulo the group order. A raw 32-byte prehash at or above the order reduces to the same scalar as the prehash minus the order, so journals and claims keyed by raw bytes can disagree with what was signed. Only adversarially chosen requests reach this case. | S4 | Reject a prehash at or above the order at request validation. Key message claims by the reduced digest. Test with a value and the same value plus the order. | Owed |
| A11 | Mode 1 registration has no written mapping to Protocol 7.1 and the relaxed key-generation functionality in the programmable random-oracle model. The reserved-only retry rule and immutable first disclosure are part of that argument. | S1 | Independent review of the dossier's registration simulator draft. Keep retire-on-reserved-only. Alternatively obtain Silence's derive mode, which removes PairKey registration entirely. | Implemented; proof open |
| A12 | The research constructor is retained. Its algebra is proved; provenance and admissibility rest on A4 and A11. | S3 | Nothing beyond A4 and A11. Silence's derive mode would remove it. | Design |
| A13 | Joint KDF assumption. Identity keys at `src/lib.rs:77-83` and wallet contributions at `src/d.rs:66-93` derive from one root under different salts. | S4 | State it as HKDF-Extract under distinct salts being a dual PRF of the root, or split the root into two sub-roots with one expand step before any funded wallet exists. Changing it later changes identities. | Assumption stated in the dossier |
| A14 | Derivation v2 binds pairing, namespace, epoch and version. Any later change produces different wallet keys. | S4 | Freeze v2 and its version field before the first funded wallet. Document that no retrofit is possible. | Landed |
| A15 | The native split signing API has a copyable presignature and a finish step that borrows it. Spike D uses only combined `sign::run` at `src/d_worker.rs:480`. | S4 | Wrap the native crate so the split API is not re-exported, with a test that fails if it reappears. | Open, trivial |
| A16 | A donor in memory covers every session of its lifetime, so one memory disclosure exposes material for all wallets of the pair. The roots live in the same memory, so this adds little. | S4 | Zeroize on discard, already done through the clearing wrappers. Keep the bounds. | Landed |

Verified with no action needed: donor DKG failures map through `src/lifecycle.rs:131-156` so PPRF
and decode errors quarantine the peer; signing failures map through 108-130 with aggregate check
failures freezing the configuration by design; the cross-wallet fence and the sixteen concurrent
identical requests produce distinct sessions; the possession proof binds identity only, and DKLs23
section 7 needs no proof of knowledge for the contributions.

## B. Concerns shared with every route

| # | Concern | Severity | Fix |
|---|---|---|---|
| B1 | Concrete margin. Theorem B.17 of 2026/976 certifies only `s = 12` at `xi = 512`, in the Sender Random OT hybrid. No written bound exists for the compiled stack. The section 4.5 attack does not transfer as stated. | S3 | Ask Silence for its written position and bound. The fixing-order lemma in A1 restores Theorem 6.1 in the paper's own hybrid. Do not change parameters. |
| B2 | Public-tweak signing for child paths. Non-hardened derivation makes related keys, and the related-key unforgeability game is unproven for this signer. | S3 | Write the additive public-tweak reduction for the actual child-key oracle, or restrict to one key per wallet without child paths. |
| B3 | Known-seed zero mask for two parties. Both parties know the seed. | S4 | Write the lemma: for two parties the honest mask is the negation of the corrupt one, which Functionality 3.4 already leaks; 2026/976 section 2.2 says the functionality is unnecessary for two parties. |
| B4 | Audit-to-pin gap. The audit covers the native protocols at an older commit, not this pin or this composition. | S3 | Obtain Silence's coverage statement for the pin. Diff the audited commit against the pin on the DKG and signing paths. Keep the pin fixed. |
| B5 | Fixed roots regenerate the same keys. Sequential compromise of both roots exposes every wallet in the namespace, and rotating OT material gives no proactive security. | S2 as a deployment property | Seal roots in the TEE with independent backup custody. Treat an epoch change as new wallets. Document that no refresh preserves the key under roots-only persistence. |
| B6 | Identity keys are pinned at enrollment but not bound to attestation evidence inside Spike D. | S3 | Bind the enrollment pins to attestation at the deployment layer, and refuse a peer whose evidence changes without a ceremony. |

## C. Basis recorded from the discussion

**Route comparison.** Under no audit budget, the dominant criterion is how much unaudited
cryptographic logic sits on the signing path. Spike C has PairKey run the base OT, the PPRF and the
zero-seed coin flip with exported primitives over a bespoke channel. Spike D has the audited DKG
produce that material and PairKey only moves bytes and manages lifetime. Reuse with fresh session ids
is native per-keyshare practice and the paper's section 8.2 model, and D's bounds are stricter than
native's unbounded reuse. D also has the deeper evidence: more adversarial tests, a proof dossier
whose checks reproduce, an obligation-to-code map and independent reruns. C's genuine advantage is
single-use freshness, a structural backstop against pad reuse, which is an operational failure rather
than a reduction in unaudited crypto. Between C and D as built, D. O-C' remains the cleanest route if
its per-wallet first-signature cost is acceptable, because it removes the constructor entirely.

**Leakage arithmetic behind the severities.** A selective-abort guess confirms k bits with probability
one in two to the k, and a wrong guess is terminal: donor discarded, pairing quarantined. Only
zero-positions of the correlation secret can be confirmed silently, since a one-position aborts. The
expected number of bits learned before the first abort is about one, independent of the use cap. Even
100 known bits of the 256-bit secret leave a 2^-156 guess, because sender privacy needs the whole key.
The cap therefore limits attempts, blast radius and the exposure window, not bits learned. The setup
probe's pooled acceptance rate across 448 recorded trials is 50.4 percent, consistent with a uniform
choice bit; the leak is conditioning on acceptance, not bias.

## D. Leaky-donor amplification experiment, 2026-10-12

Isolated probe against the unmodified `sl-oblivious 1.0.0-beta` consistency check, no native,
dependency or honest-source change, no signature or key formed. It measures how well the honest
SoftSpokenOT sender detects a receiver that injects one inconsistency after learning all but `j`
bits of the per-setup correlation secret. Evidence and provenance:
[review-evidence/leaky-donor-amp-claude.output.txt](review-evidence/leaky-donor-amp-claude.output.txt),
harness [review-evidence/leaky-donor-amp-probe.rs](review-evidence/leaky-donor-amp-probe.rs).

| Unknown bits `j` | Accepted of 8192 | Rate | `2^-j` |
|---|---|---|---|
| 0 | 8192 | 1.000000 | 1.000000 |
| 1 | 4151 | 0.506714 | 0.500000 |
| 2 | 2060 | 0.251465 | 0.250000 |
| 3 | 1018 | 0.124268 | 0.125000 |
| 4 | 507 | 0.061890 | 0.062500 |
| 6 | 135 | 0.016479 | 0.015625 |
| 8 | 35 | 0.004272 | 0.003906 |

Findings, backing concern A1 and the arithmetic in section C:

1. **The detection probability is `1 - 2^-j`**, where `j` is the number of correlation-secret bits
   the receiver has not learned. The measured accept rates sit on the `2^-j` curve within binomial
   noise. Knowing bits from the setup selective-abort leak lowers `j`, so the two leakage surfaces
   compose exactly as the amplification analysis predicted.
2. **Detection is always the typed ban.** `SoftSpokenOTError` has one variant,
   `AbortProtocolAndBanReceiver`; the compiler reports the second error arm unreachable. There is no
   silent-failure or untyped path, so every miss reaches Spike D's classifier and quarantines.
3. **`j = 0` accepts every tamper, and this is the model, not a new defect.** The check's soundness
   rests entirely on the secret staying hidden; a receiver that already holds all 256 bits is one that
   already defeated the setup, which the `1 - 2^-j` detection is what prevents.
4. **No compounding across donors.** Repairing with a different donor's secret accepted 0 of 8192.
   Bits learned against one donor give zero advantage against the next, so a detected miss both ends
   the current donor and resets the attacker to zero knowledge. This is the cryptographic basis for
   discard-on-failure with a fresh donor, and it is why the 100-use bound caps blast radius rather
   than bit accumulation: accumulation against one secret is already self-limiting at about one
   expected bit before the first detected, terminal miss.

## E. Signing-layer amplification, accumulation and donor-burn, 2026-10-12

Follow-on to section D, at the exact RVOLE call site signing uses. `sign/dsg.rs:303` calls
`RVOLESender::process`, whose first step is the same consistency check. Honest endpoint is the
unmodified pinned `sl-oblivious`; the adversary is the harness. Evidence:
[review-evidence/leaky-donor-signing-claude.output.txt](review-evidence/leaky-donor-signing-claude.output.txt),
harness [review-evidence/leaky-donor-signing-probe.rs](review-evidence/leaky-donor-signing-probe.rs).

| Unknown bits `j` | Accepted of 2048 | Rate | `2^-j` | Bits/attempt `j·2^-j` |
|---|---|---|---|---|
| 1 | 1044 | 0.5098 | 0.5000 | 0.510 |
| 2 | 488 | 0.2383 | 0.2500 | 0.477 |
| 4 | 133 | 0.0649 | 0.0625 | 0.260 |
| 8 | 11 | 0.0054 | 0.0039 | 0.043 |

Two facts beyond section D:

1. **No incremental oracle.** Flipping `x` alone, or one `t`-row alone, accepted 0 of 16384 each. The
   extension check hands out no bits: any accepted injection presupposes the attacker already accounts
   for all but `j` bits of the secret. There is no cheap per-bit probe to bootstrap from.
2. **A detected miss is attributable and quarantines the pairing.** The gate's single failure variant
   maps through `dsg.rs:303` to `AbortProtocolAndBanParty` and through `lifecycle.rs:121-124` to
   `QuarantinePeer`, which is pairing-wide.

**Accumulation conclusion.** `j` stays near 255 to 256 for a donor's whole life and `j = 0` is
unreachable. The only bit source is the setup selective-abort, about one bit per accepted donor,
one-shot and itself quarantine-risking. From that one bit the only available extension probe is
`j ≈ 255`, accepted with probability about `2^-255`. Reuse across up to 100 signatures does not help,
because there is no incremental oracle and the first attributable miss quarantines the pairing. This
refines the earlier "accumulate until the first wrong guess" to its precise form: at most one
attributable extension-cheat shot per pairing, at a knowledge level the attacker cannot improve.

**Donor-burn arithmetic.** Because a miss quarantines the pairing, each cheat shot costs one fresh
pairing, which costs a new authenticated enrollment. For a `~50%` chance of one accepted shot at a
given knowledge level, the attacker needs about `0.69·2^j` fresh pairings:

| Known bits | `j` | Fresh pairings for ~50% |
|---|---|---|
| 248 (counterfactual) | 8 | about 177 |
| 240 (counterfactual) | 16 | about 45,000 |
| 1 (achievable from setup) | 255 | about `2^254` |

The 100-use and 600-second bounds and the 3-per-60-second transport limit do not gate this. Quarantine
already caps attributable attempts at about one per pairing; the bounds cap the pad-reuse exposure
window and availability instead. The counterfactual rows assume knowledge the attacker has no path to
acquire, and are shown only to bound the favorable regime.

**Caveat, unchanged.** This measures the detection gate, not secrecy. Whether a surviving lucky
acceptance leaks anything about the honest share beyond the bits the attacker bet on is the simulator
question in A1 and is not settled by any test.
