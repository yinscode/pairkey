# Spike D donor reuse security argument

2026-10-12. Implementation under examination: `0f6e0557555b73aafa15ce0b590067dad0a747d1` on `codex/spike-d`. Native pin: `af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`; `sl-oblivious` and `sl-mpc-mate`: `1.0.0-beta`. Native sources, parameters and dependencies are unchanged.

**A complete malicious-security proof and a concrete system-security bound are not established.** The algebraic share conversion, child-offset reconstruction and mask cancellation below are proved identities. Registration has a conditional distribution argument. The reusable compiled preprocessing lemma, its RVOLE instantiation, and related-child signing composition remain proof obligations. The 100-attempt/600-second policy is operational hygiene.

## 1 Attacker and target security claim

Use a probabilistic polynomial-time adversary that statically corrupts either role before initialization. The corrupt signer controls its root, identity key, messages, setup inputs, alleged package state and randomness. It may deviate from the library, retain every secret indefinitely, choose wallet domains and messages through the request interface, delay/reorder/replay traffic, influence donor establishment, interleave sessions in the proposed broader model, and abort after observing any prefix. It observes every public registration record, signature and public control file. Treat both corrupt-role cases separately because base OT and online OT reverse roles. An authenticated corrupt message is still malicious.

The adversary cannot read the honest root or honest RAM, replace the honest executable, restore an honest process from a snapshot, or modify/roll back honest authoritative journals. These restrictions define this analysis; the local prototype does not implement real TEE enforcement. The ideal execution must preserve visible aborts, completed signatures and all allowed preprocessing leakage.

**Signing integrity game.** Maintain an authorization set when the honest endpoint admits a matching registered request to its signing execution. Its entries identify the immutable root record, actual derived public key and digest scalar. The adversary wins if it outputs a valid ECDSA signature for a covered key/digest that was never admitted by the honest endpoint. A corrupt party may obtain a signature from an admitted attempt even if the honest endpoint later aborts after releasing its contribution; final-result receipt is not the authorization boundary. No fairness, guaranteed completion or retroactive revocation of already released contributions is claimed. Production policy/controller authorization is a separate obligation.

**Digest and key equivalence matters.** This interface accepts arbitrary prehashes. ECDSA verification reduces the digest modulo the group order `q`; therefore prehashes `1` and `q+1` accept the same signature. A game that labels different raw 32-byte prehashes as different messages is false. Record queries by `(actual child public key, prehash mod q)` for this arithmetic interface, or define a message-level game with an explicitly assumed hash. Different path spellings or different records that yield the same key must not create artificial fresh-key challenges. This is a claim-definition counterexample, not a demonstrated remote attack on PairKey or a hash-preimage attack against a destination chain.

**Honest-share privacy.** The target is simulation of the protocol view from the public records, the corrupt party's state, permitted ideal-functionality outputs and signing authorization/abort history. Separately, require infeasibility of recovering an honest contribution or root beyond what these interfaces permit, under discrete-log and joint KDF assumptions. Public `aG` mathematically determines `a`; secrecy is computational, not information-theoretic entropy conditioned on that point. Scalar recovery must be checked against the pinned public contribution. Mobile corruption of both roots at different times, external revelation of a related child secret and physical memory attacks are outside this target.

### Necessary assumptions

| Assumption | Meaning and code boundary |
| --- | --- |
| Honest roots | Independently generated high-entropy roots with no adversary-supplied honest root; `Root::load` only checks file shape. |
| Joint KDF security | Domain-separated identity and contribution derivations from the same honest root are jointly pseudorandom in the presence of identity public keys/signatures and public contribution points. A PRF assumption for one isolated HKDF call is insufficient to state that whole claim. |
| Fresh entropy | Every honest DKG/signing/proof attempt receives fresh unpredictable entropy. `fresh`, `Endorsement::new` and `hedged_seed` use OS randomness; this prototype has no protected hardware entropy proof. |
| Hash and authentication | Explicit domain-separated random-oracle/PRG assumptions for the proposed proof, collision resistance for binding, Ed25519 authenticity, X25519/AEAD security, and canonical encodings. Programmable commitment/proof oracles must be distinguished from the non-programmable global oracle used in the DKLs VOLE theorem. Domain labels alone do not prove those models for SHA2/Merlin. |
| Authority and storage | Honest cooperating filesystem, correct lock/write/sync behavior, confidential root storage, persistent incident/instance/session journals, and no rollback/deletion. Process-death tests do not establish power-loss behavior. |
| Process scheduling | The current service serializes commands and does not clone donor RAM. Multiple processes may use distinct generations. Arbitrary overlapping sessions sharing one donor need the stronger reusable lemma; native concurrency tests do not provide it. |
| Fault controls | Cryptographic claims require research fault commands disabled, or a trusted controller that cannot request them. Those commands deliberately permit unsafe entropy/tampering experiments. |

Predictable entropy is not repaired by the hedge: context, counter, role and operation are public. The seed controls native nonce shares, blindings, session IDs and encryption randomness. Distinct seeds or journaled SIDs do not imply unpredictability. Rotating donor preprocessing also does not refresh root-derived wallet contributions.

## 2 Reusable preprocessing lemma

### Proposed statement R

Let `Setup` be the pinned native EndemicOT/PPRF setup as embedded in donor DKG, and `Extend` the pinned SoftSpokenOT/RVOLE calls. Against either corrupt role, for each honest donor generation and at most `u <= 100` admitted uses, there should exist a simulator that reproduces the **joint** setup/extension/signing-prefix view while replacing each directional multiplication by the required ideal service. Its advantage is at most

`epsilon_R(u, Q_RO, Q_PRG, setup_history, leakage_history)`.

The simulator must support adaptively chosen online inputs and fresh distinct online SIDs; permitted aborts; both successful and failed invocations; and the service's retirement rule. Registered wallet points may already be public before donor setup, as in the stress fixture; allow that auxiliary information when the malicious peer chooses its setup behavior. For the stronger concurrent target it must support arbitrary permitted interleavings and contributions queued before an incident cutoff. It must preserve the order in which effective OT outputs and multiplication inputs become fixed. `u` alone does not bound adversarial random-oracle queries.

The ideal service must specify allowed leakage rather than assuming it away. Setup acceptance/rejection can reveal membership in an affine set of hidden base choices, as modeled in the published SoftSpokenOT work. Leakage cannot be defined as arbitrary honest wallet data; that would make the statement vacuous. The required connection is from that leaky setup functionality through non-leaky online OT conversion to the multiplication functionality used by signing, with an explicit accumulated-leakage/simulation bound. If the conversion requires a particular minimum uncertainty or no later reuse after a failure, establish those conditions for the actual history.

Evaluate security over the whole experiment, including setup failure. Conditioning on acceptance can amplify a statistical error by `1/Pr[accept]`, and acceptance can be rare under a malicious strategy. A useful unconditional simulation statement does not imply that every rare accepted setup has all-honest hidden randomness.

### Counterexample to a stronger false statement

In the native regression, a malicious base-OT sender alters only branch 0's point encoding after constructing an otherwise valid reply and PPRF proof. `EndemicOTReceiver::process` decodes the selected branch. Choice 0 rejects; choice 1 accepts, and the PPRF consistency proof can still pass. Accepted runs therefore reveal one hidden choice bit. The accepted distribution is not the all-honest unconditional distribution. The attacker retains that bit after acceptance; later retirement cannot erase it.

This refutes the perfect-hidden-choices premise. It does **not** refute malicious security under a correctly specified endemic/leaky functionality, prove key recovery, or supply an accumulated-reuse bound. The existing wrong-SID/XOR regression separately refutes reuse of the same expansion context.

### Correspondence and remaining simulator steps

| Layer | Checked correspondence | Remaining proof requirement |
| --- | --- | --- |
| Native donor DKG | `Service::prepare` calls native `keygen::run`; directional OT and PPRF setup use native generation labels. | Establish the malicious joint distribution, including correlations with the rest of DKG and its accepted transcript. |
| EndemicOT | Selected-branch point decoding and directional session domains are implemented. | Map the concrete curve/hash construction to the endemic base functionality with its admitted leakage. |
| PPRF | `build_pprf` and `eval_pprf` correspond to the published all-but-one construction. | Map PRG/consistency domains and the ideal affine-leakage sets; extraction/fixing order must hold for deviating peers. |
| SoftSpokenOT | Expansion includes SID; matrix check uses `GF(2^128)`; output conversion includes SID and row index. | Prove output conversion under the paper's TCR/almost-uniform-hash assumptions and repeated use of the same leaves. PPRF acceptance alone is insufficient. |
| RVOLE | Early `b`, correction rows, theta/eta and mu consistency checks are in the compiled code. | Establish the needed ideal OT output-fixing order and reconcile the revised VOLE analysis. |
| Retirement | Local failure discards donor RAM and incidents fence the pairing. | Account for accepted leakage before a visible failure and any already released concurrent outputs. |

**Status: R is not proved for this compiled stack.** The historical audit's TOB-SILA-13 fix review left the combined protocol specification partially resolved; Appendix F reviewed the RVOLE replacement separately. The published PPRF theorem and OT-output conversion theorem have different premises. A full simulator or a verified applicable realization theorem is still needed. Repeating 100 successful signatures cannot replace that step.

## 3 Transplantation and registration

### Proved algebraic representation

Let `a,b` be the two registered scalar contributions and use native coordinates 1 and 2. The constructor stores `s0=a/2`, `s1=-b`. The interpolation coefficients at zero are 2 and -1, hence

`2*s0 - s1 = a+b`.

These are evaluations of the degree-one polynomial

`p(t) = a+b + t*(-a/2-b)`.

Thus the public shares interpolate to `Q=(a+b)G` without either honest worker reconstructing `a+b`. Constructor checks reject invalid coordinates indirectly by constructing fixed coordinates/ranks, zero local shares, inconsistent local public shares, aggregate identities and equal public shares. The latter rejects a negligible special case even if the aggregate is nonzero.

Let `delta` be the library's total public child offset and `z` the two-party mask. Native signing uses

`sk0 = a + delta/2 - z`, `sk1 = b + delta/2 + z`.

Their sum is `a+b+delta`, and their public points sum to `Q+delta*G`. These are exact field identities, checked symbolically as coefficient vectors in the accompanying script. They prove arithmetic compatibility, not an ideal key-generation realization.

### Conditional registration argument

1. Replace the honest root's joint KDF outputs by a lazily sampled random function at distinct wallet domains. This step is conditional on the joint PRF assumption, including public identity outputs. Repeat use of the same domain returns the same value; it is not a fresh draw.
2. For a first-disclosed domain, the honest contribution is a reduction of a fresh 512-bit string. Its distance from a uniform scalar is computed below; zero causes refusal.
3. A hiding, binding commitment prevents a corrupt peer from choosing its point based on the honest point before fixing its own commitment. The acknowledgment fixes the ordered pair before reveal. For each fixed nonzero peer point, `Q=A+B` is uniform before any selective abort, apart from reduction/refusal error.
4. The immutable record binds the domain, configuration, openings, aggregate key and chain code. Exact preparation/endorsement checks bind recovery to the previously prepared record. Reserved but incompletely prepared domains retire on restart; changed ceremony IDs cannot give the peer a fresh contribution after disclosure.
5. Successful completion can be deliberately selected based on public points. The target must allow that selective abort; uniformity of the *accepted-only* public-key distribution is not claimed.

For a fresh uniform `a` and fixed nonzero peer scalar `b`, the local forbidden cases `a=0`, `a=-b` and `a=-2b` have total probability at most `3/q`. This observation does not bound the adversary's decision to abort for any other public reason.

### Mapping to the selected theorem

The local 76-page edition of [DKLs23](https://eprint.iacr.org/2023/765) uses **Functionality 3.2, FRelaxedKeyGen**, then proves signing in its ideal-building-block model in Theorem 4.1. Section 7 explains why corrupt key shares need not be extracted during registration; RVOLE extracts the effective signing inputs later. Theorem 7.2 concerns the paper's polynomial commit/release protocol.

PairKey commits additive points and constructs a special degree-one sharing. It does not execute that polynomial protocol. The algebra above does not establish equality of all internal functionality interfaces or their distributions. Two-party threshold access is sufficient for reconstruction, but the ideal simulator still needs a precise registration interface and a mapping into the signing theorem's key input. Resolve that with a specialized two-party registration lemma or a justified replacement functionality; do not cite Theorem 7.2 as automatically proving this registration.

The ordinary Schnorr endorsement establishes its verification equation and identity context. It is not automatically a straight-line UC extractor. Conversely, demanding a stronger knowledge extractor just because it is present would impose an assumption the relaxed theorem deliberately avoids. Its extra transcript also needs simulation if claiming UC security.

### Local admission lemma

Within an honest authoritative journal, an honest `Service::sign` can construct a package only for the exact active certificate whose digest matches the request, whose local opening matches `Root::derive_v2`, and whose agreed donor/instance matches that execution. To see this, follow `Journal::active` and certificate validation, the record-digest equality, the generation and instance exchanges, irreversible reservations and finally `Donor::package`/`Record::local`. A conflicting stored certificate or changed request fails one of those checks, unless the canonical hash/authentication assumptions fail. This establishes local admission consistency; it does not constrain a corrupt peer's private package or prove native multiplication security.

### Transplantation contract

Native `dkg.rs` separately stores the signing scalar, directional OT seeds and shared mask seed. Native `dsg.rs` passes the OT seeds to RVOLE and combines the local signing scalar later; no donor signing scalar is read by the extracted-material API. This establishes a source-level separation of fields. It does not establish that arbitrary maliciously accepted donor distributions are independent of their discarded scalar or of all public setup information.

**Conditional transplantation lemma:** given R, an admissible registered key-sharing distribution and a valid two-party zero-mask realization, copying exactly the honest party's directional correlations into the constructor preserves the required multiplication service for online inputs selected after setup. The constructor must keep party ordering, coordinates/ranks, public-key/share consistency, chain code and session context consistent. Its public metadata checks cannot authenticate the corrupt peer's secret correlations.

The native package-tamper matrix confirms this boundary: unused public-share/key-ID/extra metadata can be changed in a raw package while native signing still produces a correct original-key signature. Local record/constructor validation must establish those fields. Arbitrary externally supplied serialized packages are outside this constructor contract.

**Status:** arithmetic proved; pre-reveal pseudorandomness and record binding conditional on stated cryptographic/authority assumptions; registration simulation and malicious transplantation remain conditional.

## 4 Wallet and session composition

### Actual context trace

| Value | Definition and fixing point | Peer influence |
| --- | --- | --- |
| Wallet domain | Ordered identities, namespace, epoch, version and key ID; fixed at registration reservation. | Can choose admitted domains, not silently change an honest reserved record. |
| Donor input | Pair, both boot generations, configuration, limits and attempt; fixed before native DKG. | Can refuse or deviate during DKG. |
| Donor generation | Native DKG `Keyshare.final_session_id`; both parties acknowledge it before admission. | Can influence the native transcript; freshness needs honest entropy and reservations. |
| Signing instance `I` | Hash of wallet digest, record digest, generation, path, prehash and attempt; fixed before generation/instance agreement. | Can propose requests and a disagreeing context; an honest endpoint refuses disagreement. |
| Package SID `P` | Hash of record digest, generation and `I`; fixed before native signing. | Cannot change honest `P` without changing an admitted context or breaking binding. |
| Honest R1 `S_h,C_h` | Fresh RNG produces a native SID and nonce commitment. Guard journals the authenticated SID before release/admission. | Corrupt R1 may be chosen after observing honest R1. |
| Native final SID `F` | `SHA256(S0 || S1 || P)`, ordered by native participant index. | Corrupt party controls its own SID; hash-collision assumptions still needed. |
| Mask digest `D` | Native hash of the ordered party indices, R1 SIDs and nonce commitments. | It does not directly contain `P`, wallet, path or message; honest R1 freshness supplies separation. |
| Directional MtA SID | Native hash of `F`, sender/receiver roles and labels. | Context disagreement is checked before using peer contributions. |
| Mask | `-Reduce(H(label,sigma,D,label))` and its opposite. | Both signers know `sigma`; no hidden-seed argument is available. |

### What the zero-mask argument proves

For identical `sigma,D`, the two masks sum to zero even if the peer biased `sigma`. In an independent random-oracle domain, a first query at an unqueried `(sigma,D)` yields a fresh uniform bit string, with the scalar-reduction distribution below. This lazy-sampling fact does not require `sigma` to be secret.

A corrupt peer can query candidate digests and choose its R1 or completion behavior accordingly. A simulator must preserve these queries and selections, for example through an explicitly specified oracle/FZero invocation mapping. It must not simply replace each *completed* mask by an independent uniform scalar. Native donor DKG has the lower-index party supply the mask seed; this is also not the paper's two-party commit-and-combine seed ceremony. A two-party adaptive simulation can potentially tolerate a known/biased seed, but it must actually be supplied.

### Related child keys and concurrent sessions

Public derivation exposes known differences `Q_child=Q_root+delta*G`. Child keys are related, not independent fresh keys. A uniform-root statement alone is insufficient to infer security for an oracle signing under many public tweaks. Require a public-tweak/multi-key extension of the selected signing security game or a reduction that simulates all child signing oracles consistently. The common chain code is derived from public registration data; native BIP32-style arithmetic does not establish an independently sampled extended-key security distribution. The chain code is public, so a secret-key HMAC PRF assumption cannot simply be invoked for that derivation.

The sequential worker and journals support local request/SID at-most-once behavior under the honest-filesystem assumption. They do not supply UC security, guarantee globally unique hashes, or prevent all already-started sessions from leaking additional information when a different process publishes an incident. Any reusable lemma that relies on stopping after the first failure must define exactly which in-flight extensions are still allowed in its transcript. Per-generation use limits do not bound total pair lifetime or the number of separately created generations.

For expected, authenticated, well-formed R1 frames at the pinned layout, `R1Guard::observe` reserves `(observer role, sender role, SID)` before the checked handoff/native admission. Within the honest persistent journal, an existing reservation cannot be admitted again. This is an at-most-once property of those frames; differently formatted input remains the native parser's responsibility, and exact transport duplicates currently cause a burn. The age timer is also a runtime cancellation mechanism, not an atomic wall-clock check on every handoff: blocking computation and scheduler delay can postpone observing expiry. It supplies the tested hygiene behavior without proving a strict deadline for every byte already queued or currently being computed.

### Conditional composition theorem

Assume a registration realization that supplies the required two-party key inputs, R for the exact schedule/leakage model, a valid native RVOLE realization, a zero-mask oracle realization, and a signing theorem that covers the intended public tweaks. Replacing these modules by their ideal counterparts yields a multi-wallet signing experiment to which the selected signing theorem applies, subject to authentication/binding and the declared authority assumptions. A hybrid/triangle bound sums their distinguishing advantages.

This is a conditional theorem schema. The reusable OT/RVOLE, registration, zero-mask simulation and public-tweak premises are not all discharged. No unconditional composition theorem is claimed.

## 5 Concrete bounds and implementation correspondence

### Exact compiled dimensions

| Parameter | Value | Interpretation |
| --- | --- | --- |
| `KAPPA` | 256 | Scalar representation bits in this code. |
| `LAMBDA_C` | 256 | Base-choice/seed dimension; not a claim of 256-bit system security. |
| `LAMBDA_S` | 128 | Configured RVOLE statistical parameter. |
| `L` / `XI` | 512 | RVOLE gadget vector / online OT rows. |
| `S` | 128 | Binary-field correlation check width. |
| `L_PRIME` | 640 | Online rows including check padding. |
| `L_BATCH`, `RHO`, `OT_WIDTH` | 2, 1, 3 | Product vector, extra masking column, OT payload width. |
| SoftSpoken `K`, trees | 4, 64 | 16 leaves per all-but-one tree. |

### Small bounds that can be derived

For `N` independent uniform honest 256-bit R1 SIDs, a birthday union bound is `N(N-1)/2^257`. This concerns raw honest SID collision only; add entropy/PRG advantage, and include the adversary's hash queries in separate binding bounds. The monotonic guard refuses repeats within its authoritative journal boundary; it does not make a predictable SID secret.

If a uniformly sampled `k`-bit integer is reduced modulo `q`, write `2^k=t*q+r`. There are `r` heavy residues and `q-r` light residues, giving exact total variation distance

`r*(q-r)/(q*2^k) <= q/(4*2^k)`.

At the secp256k1 order, the exact 512-bit reduction distance is approximately `2^-258.08`; the 256-bit reduction distance is approximately `2^-127.65`. This accounts for idealized sampling of root contributions and native reduced masks/challenges respectively. It does not establish entropy of arbitrary malicious distributions or a complete protocol bound. A zero-contribution refusal adds a separate at-most-`1/q` term for uniform inputs. Count every applicable reduction in a final hybrid; one cannot quote a single scalar's bias as the entire stack's security.

### Reconciliation with 2026/976

The [2026 analysis](https://eprint.iacr.org/2026/976), section 4.4, treats the early-gadget variant corresponding to the ordering in the current code. `RVOLEReceiver::new` derives `g` from the SID and outputs `b` before receiving the correction matrix. The paper also changes the OT hybrid to **Sender Random OT** and explains an output-fixing problem for the weaker endemic OT model in section 4.5. The compiled code's theta hash includes SID and correction rows; it does not explicitly append the online OT transcript. An upstream or new argument must establish effective-output fixing through the compiled SoftSpoken realization; no practical attack against that realization follows merely from the weaker-hybrid counterexample.

Theorem 4.4 / B.17 supplies this sufficient dimension condition for its early-gadget Variant III:

`m >= log2(q) + 7*s + 2*log2(s+1) + 2*s*log2(e*m/s)`

with `log2(q) >= kappa + 2*log2(m)` and the paper's separate OT/oracle premises. Here `kappa` denotes a computational budget, unlike the compiled `KAPPA` scalar-bit name. Illustratively selecting `kappa=128`, `log2(q)≈256`, `m=512`, `s=128`, the dimension RHS is about **2047.35**, so 512 does not satisfy it. The implicit minimum integer `m` is about **2656**. At `m=512`, this dimension criterion holds for `s=12` but fails for `s=13`.

**Those numbers are not a 12-bit security assessment of Silence or PairKey, an exploit probability, or a proposal to change parameters.** The theorem's Sender Random OT premise has not been established for our compiled endemic stack, and its sufficient condition is not a security upper bound. They establish that this theorem cannot certify a 128-bit statistical margin at our dimensions. Substituting the code's `LAMBDA_C=256` for the paper's computational `kappa` also fails its separate `log q` inequality; names must not be equated across papers.

The original DKLs proof assumes ideal multiplications at the signing layer, and its VOLE realization uses the early-gadget sampling argument challenged by the 2026 paper. Keeping audited parameters unchanged preserves implementation identity, but does not resolve this proof applicability. A complete concrete RVOLE bound is therefore unavailable here.

### Whole-experiment bound that remains conditional

With `W` registered domains, `N` admitted signing attempts, `G` donor generations and explicit oracle-query budgets, a justified hybrid could take the form

`Adv <= Adv_ECDSA_public_tweak_family + eps_joint_KDF + eps_registration`

`       + sum_g eps_reusable(g, u_g, leakage_g, Q_g)`

`       + eps_RVOLE + eps_zero_mapping + eps_auth_binding + eps_sampling`.

Each term must be uniformly bounded for the prior adversarial history. Summing standalone per-session bounds without that condition is invalid under shared setup. The protocol's visible failure policy must be included in `eps_reusable`; fresh generations do not erase observations about unchanged wallet roots. **No numerical total is supplied because several terms have no established bound for this realization.**

## 6 Code map and evidence

The accompanying `checks.py` reads source anchors and hashes from the implementation and exact Cargo registry package, verifies linear coefficient identities and exact reduction distances, compares the 2026 sufficient inequality, and constructs an unfunded toy ECDSA digest-equivalence example. Structural source assertions are not semantic extraction proofs.

| Obligation | Implementation anchor |
| --- | --- |
| Root domains, commitments, immutable records, endorsements, instance, entropy hedge | [d.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d.rs:66): `Root::derive_v2`, `Opening::commitment`, `Record`, `Endorsement`, `Request::instance`, `hedged_seed`. |
| Registration, donor creation, generation/instance agreement, seed creation, combined signing | [d_worker.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d_worker.rs:105): `Service::register`, `prepare`, `sign`, `run`, `discard`. |
| Pinned extraction, use/age checks, transient construction | [material.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d/material.rs:57): `Donor::extract`, `reserve`, `package`, `Limits`. |
| Imported-share algebra and constructor checks | [research-keyshare.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/patches/research-keyshare.rs:7): `pairkey_research_two_party`. |
| Before-release R1 replay journal and native SID observation | [guard.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d/guard.rs:58): `R1Guard::observe`, `final_session`. |
| Immutable record retries, counters and persistent transport accounting | [journal.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d/journal.rs:120): `Journal`, `Counter`. |
| Pairing incident classification and queue-release ordering | [lifecycle.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/lifecycle.rs:224): `Failure`, `ReleaseGate`. |
| Native DKG seed origin | [dkg.rs](/Users/user/.codex/worktrees/spike-d/pairkey/.local/silence-dkls23/sources/dkls23-af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src/keygen/dkg.rs:445): EndemicOT, PPRF and `seed_i_j` storage. |
| Native contexts, rerandomized shares, mask and multiplication calls | [dsg.rs](/Users/user/.codex/worktrees/spike-d/pairkey/.local/silence-dkls23/sources/dkls23-af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src/sign/dsg.rs:162): final SID/digest, child offset, `get_zeta_i`, `mta_session_id`, RVOLE calls. |
| Native public child-key derivation | [keyshare.rs](/Users/user/.codex/worktrees/spike-d/pairkey/.local/silence-dkls23/sources/dkls23-af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src/keygen/keyshare.rs:371): `derive_with_offset`. |
| Exact OT primitives | Registry package `sl-oblivious-1.0.0-beta`: `endemic_ot.rs`, `soft_spoken/all_but_one.rs`, `soft_spoken/soft_spoken_ot.rs`, `rvole.rs`, `params.rs`; absolute paths, line anchors and SHA256 values are emitted by the checker. |

Existing tests cover honest functional execution, replay refusal, constructor mutations, corruption/error classification, cross-wallet incident fences and use/expiry/rotation. The [bounded review report](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/SPIKE-D-REPORT.md) records the 1,000-signature run and the rate-limit/timeout findings. These tests do not establish R or a simulator.

Reproduce the public arithmetic/source checks:

```sh
python3 /Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/review-evidence/donor-proof/checks.py --output /Users/user/.codex/worktrees/spike-d/pairkey/.local/spike-d-proof-20261012/checks.json
```

Primary sources: [DKLs23](https://eprint.iacr.org/2023/765), selected local 76-page edition; [SoftSpokenOT](https://crypto.iacr.org/2022/papers/530630_1_En_23_Chapter_OnlinePDF.pdf), the published 31-page chapter, especially Theorems 5.1 and 6.2; [2026 VOLE analysis](https://eprint.iacr.org/2026/976), local 55-page edition, sections 4.4–4.6 and Theorems 4.4/B.17; the bundled Trail of Bits audit, fix review of TOB-SILA-13 and Appendix F. Source PDF hashes and primitive rerun evidence are recorded in the ignored proof evidence directory. The bundled seven-page `dwtss.pdf` is dynamic secret-sharing material, not the DKLs23 paper, and is not used as its theorem source.

## 7 Closure requirements

1. A complete compiled-stack setup/extension simulator or a verified realization theorem with the actual leakage and fixing order for both corrupt roles.
2. RVOLE reconciliation at the pinned dimensions and hash/OT instantiation, yielding a concrete bound or an explicit inability to certify one.
3. A two-party registration simulator that covers deterministic roots, immutable first disclosure, real commitments and the extra endorsement transcript.
4. An adaptive known-seed zero-mask realization and a public-tweak signing reduction covering the actual child-key oracle.
5. A composition argument with the intended sequential/concurrent failure schedule, total generation/invocation/query budgets and concrete accumulated advantage.

The attacker model, algebra, code correspondence, false stronger-premise counterexamples and partial numerical bounds are available for independent review now. Cryptographic approval remains open. No upstream request is sent, and no native parameter change is made.

## 8 Assessment of Claude review of 0f6e055

The independent [Claude review](/Users/user/000/_COOL/pairkey/experiments/silence-dkls23/CLAUDE-REVIEW-SPIKE-D-0f6e055.md) reports isolated reproduction of 78 default runtime tests and 109 fault-enabled runtime tests, with two compile-fail checks in each configuration. It inspected rather than reran stress and expiry evidence. Its registration/constructor/lifecycle observations agree with this dossier's implementation-bound conclusions. The original review is retained unchanged.

### Concrete margin corrections

Theorem B.17 says **if** the dimension inequality and OT/oracle premises hold, **then** the protocol realizes its functionality. Solving that sufficient inequality at `m=512` gives a largest integral `s=12` *for this bound*. It neither proves that the optimal statistical margin is at most 12 bits nor constructs an inconsistent-input attack with probability `2^-12`. A statistical-distance upper bound is also not automatically a consistency-check forgery probability. In B.17's last hybrid, the relevant replacement concerns the distribution of `b=<g,w>` under adversarial constraints; consistent accepted outputs may still have a distributional distinction.

The claimed 35-bit alternative drops the term `2*s*log2(e*m/s)`. That term is present in the complete Table 1 Variant III row; it wraps onto the next line. For `s=35`, the truncated RHS is about 511.34, but the complete RHS is about 883.28. The truncated condition has no support from that theorem. The review's statement that every Silence signature has a 12–35-bit margin is therefore not established by this calculation.

The correct conclusion is that the reviewed sufficient bound does not certify the intended 128-bit statistical margin at the compiled dimensions, and the compiled EndemicOT/SoftSpoken realization still needs mapping to the revised theorem's Sender Random OT premise. A concrete construction or tighter proof is required to establish an actual vulnerability or a security-bit estimate.

### Additional qualifications

- Full malicious security is not reduced solely to A7/A8 before registration, zero-mask simulation and public-tweak composition are also supplied. The review's A7 is a substantial realization assumption, not a conclusion from passing structural tests.
- Field separation in a donor package does not supply literal joint statistical independence of scalar and OT material. The native donor derives both from one seeded PRG. The useful hybrid is computational pseudorandomness of the joint stream, including public auxiliary information and the malicious setup transcript.
- Fresh SIDs do not make shared-seed sessions literally independent. A uniform conditional-on-history simulation bound is the required reusable property. Earlier successful transcripts and setup leakage remain in that history.
- At the mask-context boundary, a peer can select its own R1 and grind candidate digests. In the complete protocol it also controls setup choices, requests, OT/RVOLE inputs and later messages. An exclusive claim that its only adaptive effect is choosing a public mask requires a simulator, not just the context trace.
- Permanent pairing quarantine supports the failure model but cannot retroactively prevent a successful first forgery. An actual non-negligible attack probability would require a cryptographic fix or a narrower security claim; quarantine cannot turn it into a negligible bound. Generation rotation does not erase accumulated information about unchanged wallet keys.
- A deterministic hedge cannot guarantee nonce freshness after simultaneous restoration of context, counter and entropy. It maps identical inputs to the identical seed. Fresh unpredictable entropy and a non-restored honest authority are premises. Native replay guards and differing contexts supply the tested local controls, not snapshot security.

### Experiment design

Before a scratch cheating-RVOLE experiment, specify the corrupt role, its information at every round, the allowed messages it can choose, and an executable attack algorithm. Preserve the honest compiled endpoint, including the OT realization's output-fixing order. Editing honest seeds or choosing hidden outputs after the challenge would test a different protocol. Use separate control cases for correlation-check failure and a valid honest execution.

Separate two experimental questions. **Consistency:** can this admissible malicious algorithm make honest verification accept inconsistent products? **Distribution:** can adaptively selected constraints produce an efficiently observable deviation in accepted `b=<g,w>`? A plain mutation-and-rejection loop addresses the first question for that mutation class; it does not measure the statistical-distance step in B.17. A reduced-parameter exhaustive reproduction of the paper's distribution experiment can check its mechanism, but cannot certify or estimate the production-size compiled stack's optimal security.

Even if an explicit algorithm had success probability `2^-12`, 4,096 independent trials would have about a **36.8%** chance of observing no success. Approximately **12,270** such trials give a 95% chance of at least one observation. One observation is not an accurate rate estimate. With zero successes, a binomial upper confidence bound applies only to the tested algorithm and trial model; it does not establish cryptographic security against every adversary. The arithmetic checker records these hypothetical calculations without attributing that rate to the paper or code.

The next useful proof work is the written registration simulation and the compiled-stack output-fixing/parameter correspondence. The leaky-donor amplification, process-clone and rollback probes remain useful focused experiments, provided their honest-endpoint and authority boundaries are explicit. No inferred `2^-12` attack rate is used as an experimental prediction.
