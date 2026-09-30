# Spike D registration mapping lemma

2026-10-12. Proof draft for the unchanged registration code at `3b065e5799c76240c7d9f14920636fe3003dfb6a` (implementation introduced at `0f6e055`). Scope: a static corrupt signer, hidden honest root, programmable random oracles and honest persistent authority. The [proof dossier](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/SPIKE-D-PROOF-DOSSIER.md) supplies the broader attacker model.

**Result:** a point-only public-registration simulator can extract the corrupt committed point, equivocate the honest commitment and simulate the honest endorsement without either scalar witness. A key-preserving polynomial normalization connects the native `a/2,-b` representation to the selected relaxed key-generation distribution. Its signing connection is a change of variables in the **ideal FZero hybrid**. This is a conditional mapping draft for independent review, not a proof for the fixed SHA256/HKDF implementation or the compiled OT/zero-mask stack.

## 1 Observable interface and ideal registration

The honest interface admits a wallet domain `w=(version,ordered identities,namespace,epoch,key ID)` and a ceremony attempt. The domain identifies the persistent slot; a new attempt is not a new wallet. Observable outputs include authenticated channel messages, every public journal record, public contribution points and openings, endorsements, certificates and errors. The honest root, derived scalar, proof nonce and private pre-reveal opening remain inaccessible. Static corruption excludes a later request to reveal the honest root or its RAM. One honest worker serializes registration commands; distinct-domain oracle histories may interleave. Cloned workers, hostile storage and power-loss semantics are outside this lemma.

Use an ideal registration service with these requirements:

1. Before first disclosure for a domain, fix a valid corrupt contribution point `B` through an extractable commitment. The corrupt scalar `b` need not be given to the simulator.
2. Sample the hidden honest contribution `a` uniformly; derive `A=aG` and `Q=A+B`. In a signing-security simulation with an externally supplied fresh ideal public key `Q*`, use the equivalent point relation `A=Q*-B`. The simulator receives points rather than the honest scalar.
3. Construct the canonical public record and retain a hidden honest key handle with the native weighted representation. Neither the simulator nor the public caller may request that handle's scalar or root preimage. This is a registration **public API**, not an interface that exposes the honest key share to the environment.
4. Permit selective abort after disclosure. Such a domain cannot receive a fresh peer commitment later. Reserved-only or revealed-but-not-prepared recovery retires it; complete prepared records can resume only with the same record and exact saved local endorsement. Preserve asymmetric recovery refusal and all revealed public records, including prepared records that never become active.
5. Release a certificate only after valid ordered endorsements and exact local preparation; an activation acknowledgment may be withheld. No fairness or simultaneous activation is promised.

This service defines the public interface needed by the simulator below. It is not an assertion that it is literally Functionality 3.2. Section 5 gives the normalization and the precise additional interface condition needed to apply the paper.

## 2 Cryptographic and oracle assumptions

### Root and identity hybrid

Assume joint pseudorandomness of the domain-separated contribution and identity derivations from an independent high-entropy honest root, in the presence of allowed public identity keys/signatures and earlier public contribution points. Replace distinct eligible contribution domains by a lazy random table. Repeat domains retain the same entry; disclosed/retired domains cannot be sampled again. The 512-bit reduction incurs the distance in section 6.

The actual derivations are well-founded: `Root::identity` uses HKDF-SHA256 with public salt `pairkey/dkls-research/identity/v1` and the role byte; `Root::derive_v2` uses HKDF-SHA512 with public salt `pairkey/d/root/v2` and wallet info containing the already established identity public keys. No wallet is needed to define those identities. This removes a definitional circularity concern, but not the joint-security assumption.

One explicit sufficient assumption is joint indistinguishability of the two Extract outputs from independent random keys for an independent uniform secret root `R`:

`(HMAC_SHA256(salt_identity,R), HMAC_SHA512(salt_contribution,R)) ~= (U_256,U_512)`.

Combine that with the appropriate Expand PRF assumptions under the resulting keys, including adaptively selected wallet info containing identity-derived public values, and account for public info-hash collisions. The salts are public HMAC keys in Extract; an ordinary PRF statement with a secret HMAC key is not itself this statement. Separate dual-PRF claims for each hash family also do not automatically prove the joint cross-family tuple. This is an explicit sufficient hybrid assumption, not a new theorem about HKDF or a requirement to reveal the Extract outputs. The actual target remains indistinguishability of the allowed public protocol view with hidden key handles.

The simulator has an honest authentication key or access to the simulated authenticated-channel/signature functionality. Under a simulated PKI it can sample that key independently in the joint-KDF hybrid. Externally fixed PKI, real attestation or a later honest-root export requires a separate interface argument. The simulator **does not find a real root whose HKDF output equals an arbitrary target point**, and it does not program HKDF. It simulates a hidden key handle after the PRF hybrid.

### Oracle domains

| Oracle | Actual encoding | Simulator capability |
| --- | --- | --- |
| `H_commit` | `digest("pairkey/d/registration-commit/v2", (wallet,role,Opening))`, SHA256 of length-prefixed label and canonical serde JSON. | Observe adversarial queries; lazily answer; program previously unanswered honest opening input. |
| `H_proof` | `pool::hash("pairkey/d/possession-proof/v2", [record digest,role byte,compressed R])`, version 1 and length-prefixed fields. | Observe queries; program a previously unanswered honest proof input. |
| Record, wallet, chain-code and endorsement-message digests | Existing canonical helpers and distinct labels. | Ordinary evaluation; require binding/collision resistance. No equivocation of an existing record. |
| Native RVOLE oracles | Native labels and transcripts. | No programming by this registration simulator. Preserve the selected paper's separate non-programmable-global-oracle assumption. |

The abstract model treats these domains as independent appropriately exposed oracles. Shared SHA2 implementation and domain labels do not by themselves supply that ideal model. The commitment-family encoding starts with a four-byte short-label length; the proof-family encoding starts with version `u16(1)`, so these specified preimages are distinct as well as labelled. No oracle answer already visible to the adversary can be overwritten. The code has no programming hook; programming is exclusively an ideal-proof operation.

Both oracles return **256-bit strings**. A proof challenge is reduced modulo the curve order. The simulator samples a raw 256-bit answer and reduces it; sampling a uniformly distributed scalar directly would miss the implementation's small reduction bias.

## 3 Simulator for one first registration

Let `h` be the honest role, `c=1-h`, and maintain an oracle table, an index of correctly parsed corrupt commitment queries, and a persistent domain-to-transcript table. Queries must decode the exact canonical commitment input for `w,c`, with the byte-array shapes accepted by the native types. A point is not a scalar witness. Oracle collisions, successful guessed openings and premature queries at programmed inputs are explicit bad events.

1. **Reserve.** Match the actual state exchange. If the slot is retired or recovery is asymmetric, refuse at that phase. For a fresh slot, reserve the domain and sample a uniform digest `C_h`. Publish/store it as the honest commitment. Do not reveal an honest point yet. A premature crash preserves reservation and causes retirement on recovery.
2. **Extract the corrupt commitment.** On receiving `C_c`, find a previously observed query `H_commit(w,c,B,s_c)=C_c`. Extract the point encoding and salt, not `b=log_G(B)`. A digest that has multiple different valid preimages is a binding bad event. Queries from another role, domain or encoding do not count.
3. **Acknowledge.** Store `C_c`, form the ordered commitment pair, and require the identical peer acknowledgment before releasing the opening. The peer may have chosen `C_c` after seeing `C_h`; extraction still occurs before the honest point is revealed.
4. **Bind the ideal key.** For a valid extracted point, obtain the ideal `Q*` and set `A=Q*-B`. Choose a fresh 32-byte salt `s_h`, require that `(w,h,A,s_h)` is unqueried, and program its answer to `C_h`. Store the reveal-release acknowledgment, then emit that opening. A programmable commitment is necessary because the honest commitment was already sent.
5. **Handle invalid or unqueried commitments at the correct time.** The real worker still releases its own opening before learning whether the peer decommitment is valid. Do not skip this frame. For an invalid/no-query commitment, emit a uniform fallback honest point under a programmed salt, then reject the peer opening/point at its actual validation phase. A subsequently valid opening without a matching earlier query is a negligible late-opening bad event. No successful certificate is produced in this branch.
6. **Validate and build.** Require the actual peer opening to match the extracted commitment, valid point encodings and the admitted domain. Reject the same point/aggregate exceptions as the honest code. Build the exact ordered record and public chain code. Record/configuration hashes are evaluated normally. Any raw commitment/record journal already published remains immutable.
7. **Simulate the honest endorsement.** Let `A` be the honest public contribution and `d` the record digest. Choose `Y` uniformly in `{0,1}^256`, put `e=Reduce_q(Y)`, and choose `z` uniformly in `Z_q`. Compute `R=zG-eA`. For nonidentity, previously unqueried `R`, program `H_proof(d,h,R)=Y`. Then `(R,z)` verifies because `zG=R+eA`, without knowing `a`. Sign the exact endorsement-message digest with the simulated honest identity key. Store the record and **this exact endorsement** before release. Identity/proof-nonce exceptions are included in the bad-event bound.
8. **Validate the corrupt endorsement and commit.** Check its role, record digest, identity signature and Schnorr equation as the code does. The simulator never relies on extracting its scalar witness. If validation succeeds, activate only the exact locally prepared record/endorsement with both ordered endorsements. Match the final acknowledgment and any failure timing. After preparation, exact resumption reuses the saved proof, response and signature; it does not create a new simulated proof.

For a valid extracted `B` fixed before disclosure, uniform `Q*` makes `A=Q*-B` uniform independently of `B`, conditioned on the prior history in the PRF/ROM hybrid. This remains true for either role. Selective abort after learning `A` may bias the *completed-only* key distribution and is allowed by the ideal service.

For an honest proof with an ideal uniform nonzero nonce `k`, its response is `z=k+ea`. The simulator's inverse relation is `k=z-ea`. For each challenge answer, translation is a bijection on the field. Thus the real and simulated `(R,z,Y)` distributions match except for nonce reduction, identity and prior-query events. Using genuine Ed25519 signatures over simulated statements adds no scalar witness requirement. This zero-knowledge simulation is not a claim that ordinary Schnorr proofs are straight-line extractable in UC.

## 4 Persistent state and prior disclosure

The simulator caches the domain's honest point, commitment, openings, record, endorsement and activation status. It retains all oracle answers across restarts. The journal abstraction does not allow rollback or adversarial edits. The ceremony attempt is channel context, not the root-derivation or slot key.

| Existing state | Required simulated behavior |
| --- | --- |
| Reserved, no complete prepared record | Retire on recovery, even if reveal was never observed; no new commitment. |
| Revealed, no complete prepared record | Retire; the disclosed point never meets a new corrupt contribution. |
| Complete prepared record on both sides | Require identical records; resend the exact saved local endorsement, then commit the same certificate. |
| Active record | Validate and resync the exact certificate; resumption returns the same record/endorsement. |
| Prepared/active versus missing/conflicting/retired peer state | Refuse; do not replace the record or regenerate the contribution. |
| Incomplete/conflicting bytes or failed durability operation | Preserve the failure/refusal observed in actual code. The ideal-store lemma assumes correct successful writes and does not replace the separate durability tests. |

The point-only model tests interleaved domains in one shared oracle, both honest roles, changed epoch/role extraction, exact recovery, asymmetric/conflicting refusal, invalid commitments and refusal to overwrite an answered oracle input. This is model-consistency evidence, not an exhaustive asynchronous UC proof. Actual queue/crash tests remain separate evidence for the concrete journal/channel implementation.

## 5 Mapping the native representation to Functionality 3.2

The selected 76-page [DKLs23 edition](https://eprint.iacr.org/2023/765) uses `FRelaxedKeyGen` in Functionality 3.2 and Theorem 4.1. It accepts an adversarial polynomial contribution before sampling a fresh honest polynomial. It supplies the simulator with the honest polynomial's scalar value at the corrupt coordinate. Theorem 7.2 concerns the paper's polynomial commitment protocol, which PairKey does not run verbatim.

### Why the identity mapping is insufficient

Let coordinates be `1,2`, with interpolation weights `lambda_1=2`, `lambda_2=-1`. Put `gamma_i=1/lambda_i`, so a committed additive contribution `b` corresponds to native share `gamma_c*b`. A naive embedding sets the adversarial contribution at the honest coordinate to zero and at the corrupt coordinate to `gamma_c*B` as a point.

The functionality then adds a fresh honest polynomial `hat p(t)=u+vt`. Its **raw total corrupt point** is `gamma_c*B + rho*G`, with `rho=hat p(c)`. The real package's corrupt public share is fixed as `gamma_c*B`. They coincide only when `rho=0`. An unmodified identity mapping of all key-share fields is therefore not supplied by commitment equivocation alone. This is an interface/distribution mismatch of that proposed mapping, not a signing attack or a proof that every possible realization is impossible.

### Key-preserving normalization

Use the following proof transformation, restricted to these two coordinates:

`p'(t) = p(t) - (rho/c)*t`.

It preserves `p'(0)=p(0)` and gives `P'(c)=gamma_c*B`. The honest share becomes `p'(h)=p(h)-(h/c)*rho`. For the chosen adversarial polynomial with zero value at `h`,

`p'(h) = hat p(h) - (h/c)*hat p(c) = (1-h/c)*u = gamma_h*u`.

Consequently the normalized distribution is exactly our representation: honest contribution `a=u`, corrupt contribution point `B`, native share points `gamma_h*A, gamma_c*B`, and aggregate `Q=A+B`. This requires no corrupt scalar extraction. A linear polynomial over group points is specified by its two coordinates, and the adversarial scalar sent at the honest coordinate is exactly zero.

For independent uniform `(u,v)`, the map `(u,v) -> (u,rho=u+cv)` is a bijection because `c` is nonzero. Thus `rho` is an independent uniform auxiliary scalar even given `u`, its public point and `B`. The simulator receives `rho` from the functionality's `hon-poly` interface and can compute every needed normalization point with group operations. It still need not recover `u` or the honest root. The executable check enumerates all 10,201 polynomials over a small field for each role and verifies this bijection, as well as the identities at the actual curve order.

| Honest role | Honest coordinate `h` | Corrupt coordinate `c` | Scalar shifts `(Delta_1,Delta_2)` | Weighted shifts |
| --- | --- | --- | --- | --- |
| 0 | 1 | 2 | `(-rho/2,-rho)` | `(-rho,+rho)` |
| 1 | 2 | 1 | `(-rho,-2*rho)` | `(-2*rho,+2*rho)` |

### Conditional signing connection

Native effective signing shares have the form `lambda_i*s_i + delta/2 + zeta_i`. Let `Delta_i=-(i/c)*rho`. Then

`lambda_i*(s_i+Delta_i)+delta/2+zeta_i = lambda_i*s_i+delta/2+zeta'_i`,

where `zeta'_i=zeta_i+lambda_i*Delta_i` and `sum_i lambda_i*Delta_i=0`.

In an **ideal FZero** execution, a fixed translation by a zero-sharing vector preserves the uniform zero-sharing distribution. The normalization is fixed during key generation before that signing invocation. This supplies a coupling between normalized and raw effective signing inputs at the same aggregate key. It does not require the paper to extract the corrupt registration scalar; effective signing inputs are handled later by the ideal multiplication interface.

This scheduling condition matters. The paper's simulator permits FZero sampling at arbitrary times; translating an output already shown to an adversary is not an available operation. A joint simulator must preserve such early queries, or show that the actual target mask context is unqueried until after normalization. Native code determines that context from fresh honest R1 data after registration, but the full early-query/adaptive argument belongs to L4. This coupling alone does not cover every schedule permitted by the abstract functionality.

This transformation is a proof coupling, **not a new message or runtime normalization step**. An unmodified black-box Functionality 3.2 does not directly give the honest caller `rho`; it gives that value to the ideal adversary. A fully formal module-composition proof must therefore define the normalized private key-handle interface or verify the coupling inside the joint key-generation/signing simulator. It must not pretend the real worker receives `rho`. Public record points and the additional endorsement transcript are simulated as above. The original signing theorem's unmodified public/private interface is not invoked by name alone.

The actual shared-seed mask calculation is not an ideal FZero call. Proving its adaptive realization remains L4. The compiled multiplication realization and concrete margins remain L1/L3. Related-child signing security remains part of the wider composition obligation. This section establishes the registration representation and a conditional ideal-hybrid route, not those separate primitives.

## 6 Hybrid argument and partial error accounting

Let `W` be the number of first eligible domain registrations, `P` the number of newly created honest endorsements, and `Q_C,Q_P` the adversary's relevant commitment/proof oracle queries. Let `Q` conservatively cover all oracle inputs and `delta_512` be the exact distance of a uniform 512-bit reduction from a uniform scalar.

1. Replace joint root-derived outputs by the lazy PRF/identity hybrid. Cost: the explicit joint-KDF advantage.
2. Replace newly sampled contribution and proof-nonce reductions by uniform field samples, preserving zero refusal. Cost at most `(W+P)*delta_512` plus negligible degeneracy terms.
3. Replace fresh honest commitments by independent random digests, extract the corrupt point from prior queries, and program a fresh salted opening. Divergence requires an early salted-opening query, a binding collision, or a successful late guessed opening.
4. Replace the honest known-witness proof by the `(Y,z,R=zG-eA)` construction and fresh programming. Divergence requires a prior query at that nonce point, an identity exception or an authentication/codec failure.
5. Couple the ideal registration points and normalized private representation as in section 5. Mirror the exact state transitions, disclosures and selective aborts; no claim of uniformity conditioned on successful completion is used.

Useful conservative terms are `W*Q_C/2^256` for early salted-opening queries, `W*Q_C/2^256` for late-opening guesses, a birthday/preimage term on at most `Q+W+P` relevant hash answers, and `P*Q_P/(q-1)` for previously queried honest nonce points. Identity/zero/reconstruction exceptions have order `O((W+P)/q)`; for a fixed nonzero peer scalar the package exclusions are bounded by `3/q`. These are deliberately partial, loose bounds rather than a claimed tight cryptographic margin. Include authenticated-channel, signature, encoding and joint-KDF realization advantages separately when leaving the ideal model.

Fixed SHA256 cannot be programmed. The lemma's ROM conclusion does not imply a concrete proof for this particular hash, and observing SHA256 calls in the simulator model is not an implementation feature. The proof-oracle answer must remain a raw 256-bit value, not be silently replaced by a uniform scalar. Previous disclosures, oracle queries and cached statements must persist across retries.

## 7 Code mapping and reproducible checks

| Proof step | Exact implementation anchor |
| --- | --- |
| Domain and contribution consistency | [d.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d.rs:66), `Root::derive_v2`; fields are pairing, namespace, epoch, version, role and key ID. `Record::local` checks the public point. |
| Canonical commitment | [d.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d.rs:101), `Opening::commitment`; [lib.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/lib.rs:38), `digest`. |
| Reserve, ordered acknowledgment and reveal boundary | [d_worker.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d_worker.rs:105), `Service::register`; reservation precedes commitment, peer commitment precedes acknowledgment, reveal-release journal precedes opening. |
| Record and chain code | [d.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d.rs:116), `Record::new/validate/digest`. |
| Proof challenge and identity endorsement | [d.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d.rs:185), `Endorsement::challenge/new/validate`; [pool.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/pool.rs:20), versioned `Encoding` and `hash`. |
| Preparation before endorsement release and exact recovery | [journal.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d/journal.rs:163), `Journal::prepare/commit`; `Service::register` status comparison and existing-record branch. |
| Channel attempt and phase binding | [wire.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/wire.rs:312), `SetupChannel::exchange`; context, sender and phase label are authenticated. Commitment/root slot remain wallet-bound rather than attempt-bound. |
| Normalized native representation | [material.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/src/d/material.rs:124), `Donor::package`; [research-keyshare.rs](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/patches/research-keyshare.rs:7), fixed coordinates/ranks, local consistency and aggregate checks. |
| Ideal-hybrid effective-share coupling | [dsg.rs](/Users/user/.codex/worktrees/spike-d/pairkey/.local/silence-dkls23/sources/dkls23-af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src/sign/dsg.rs:233), weighted scalar, child offset and mask. No `rho` wire field or runtime step is added. |

The [simulator model](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/review-evidence/registration-mapping/simulator.py) uses secp256k1 group arithmetic, a programmable-oracle table and real Ed25519 signatures. It produces 12 model certificates across both roles without passing the honest witness into `Simulator`. It checks interleaved domains, exact endorsement reuse, conflicting/asymmetric records, invalid/unqueried commitments, role/domain extraction separation and refused oracle overwrites. The model state machine does not execute native worker transports or filesystem fault schedules.

The [Rust encoding probe](/Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/review-evidence/registration-mapping/native_encoding_probe.rs) uses an isolated copy of the actual library to emit public, unfunded vectors for wallet/commitment/record/challenge/endorsement-message encodings and successful `Endorsement::validate`. The Python fixed-hash verifier checks those vectors independently. The isolated manifest changes the probe's configuration digest; that value is read from the emitted record. Core source and lockfile copies are identical. This fixed-hash check is separate from oracle programming; it does not turn the simulated proof into a SHA256 forgery.

Evidence is saved under `.local/spike-d-registration-lemma-20261012/`, with source hashes, model results, native vectors and selected actual registration regression logs. There are no native-source, runtime-protocol, parameter or dependency changes. Run the model using the bundled Python with `cryptography` available:

```sh
/Users/user/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 /Users/user/.codex/worktrees/spike-d/pairkey/experiments/silence-dkls23/review-evidence/registration-mapping/simulator.py --native-vectors /Users/user/.codex/worktrees/spike-d/pairkey/.local/spike-d-registration-lemma-20261012/native-vectors.json --output /Users/user/.codex/worktrees/spike-d/pairkey/.local/spike-d-registration-lemma-20261012/simulator.json
```

## 8 What independent review must decide

Review the point-only simulator, simultaneous commitment extraction/equivocation, extra endorsement simulation and persistent disclosure state. Verify the normalized private-key-handle interface and the ideal FZero change of variables inside the joint signing simulator; do not infer this from scalar interpolation alone. Check the joint-root/PKI hybrid and separation of programmable commitment/proof domains from non-programmable native oracles. Assess the bad-event accounting and expand it to the intended concurrent service/authority model if that model changes.

L2 now has a concrete simulator and normalization argument to review. It remains a conditional proof draft; full malicious signing security, real hash instantiation, compiled donor reuse and production TEE guarantees remain separate open obligations.
