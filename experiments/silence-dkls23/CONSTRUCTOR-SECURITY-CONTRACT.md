# Draft Spike C constructor security contract

Draft version 1, 2026-10-10. This contract describes the PairKey replacement
boundary around Silence DKLS23 signing. It separates implemented checks from
environmental assumptions and unresolved cryptographic obligations. Finding C1
(custom key generation and preprocessing composition) remains **OPEN**.

The reference is PairKey commit `5a6c05ad0bbc24d4ed51b36f00d82ff3055c6280`,
with collector and worker shutdown fixes in
`f0331a85b28c331018b0e31d1fac22bf74be0432`, described in [REVIEW.md](REVIEW.md).
Those fixes improve failure observation and
local shutdown behavior; they do not discharge the obligations below. This draft
changes no registration ceremony, constructor code, dependencies or parameters.

## Baseline and intended security claim

Use the pinned Silence implementation and its applicable DKLS23 security argument
as the native baseline. The pin is
`af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`, with `sl-oblivious 1.0.0-beta`
and `sl-mpc-mate 1.0.0-beta`. The exact constants and source hashes remain in
[SECURITY-REVIEW.md](SECURITY-REVIEW.md#exact-otvole-realization).
The [local patch script](patch-source.py) adds the research constructor,
corrects participant-ID duplicate checking, preserves the original migration
failure if abort delivery fails, and adds a feature-gated fault fixture.
None of those changes supplies a proof for imported key/setup material.

The [Trail of Bits Silent Shard audit](https://github.com/trailofbits/publications/blob/master/reviews/2024-02-silencelaboratories-silentshard-securityreview.pdf)
provides positive evidence for its reviewed implementation. Its target table
lists DKLS23 `1510c2fafe3cd6866581ce3e2c43c565561b929b` and sl-crypto
`a6b014722a29027d813bcb58720412da68f63d07`; Appendix F reviews replacement
RVOLE commits `7422762` and `d760a6a` against DKLS23 Protocol 5.2, with two
specification typo corrections. These are different revisions from the pin.
The pinned upstream README marks key generation, signing, refresh and OT as
audited, but import/export, quorum change and migration as unaudited. Audit-to-pin
correspondence and the custom adapter's coverage require an explicit assessment
(O6), rather than treating the audit as certification of every later revision.

The intended claim to evaluate is threshold signing security with one statically
malicious participant and one honest participant, allowing adaptive wallet,
public child-path and message selection. A malicious participant may choose a
known scalar after seeing the honest public contribution, and may abort. It is
**not assumed to follow PairKey's root KDF**. The argument must state its allowed
multi-wallet and session interleavings. One pooled worker serializes native
attempts; cooperating processes can overlap. Local concurrency tests do not
establish a concurrent or UC cryptographic proof.

Adaptive corruption, guaranteed completion, hostile host snapshots, proactive
share refresh and resistance to sequential compromise of both unchanged roots
are outside this claim. One root compromise exposes that party's namespace of
contributions; learning both roots at different times can expose aggregate keys.

The [2023 DKLS paper](https://eprint.iacr.org/2023/765) is the relevant protocol
reference. The review did not obtain its full proof text; no exact theorem-to-
constructor correspondence is asserted. Obtain the applicable definitions and
proof passages under O1–O6. The [2026 paper](https://eprint.iacr.org/2026/976) is
supplementary reference only. Matching its sufficient bounds is not an acceptance
condition here, and this contract proposes no changes to Silence's parameters.

## Status definitions and trusted environment

- **Implemented:** a concrete property is enforced by the inspected PairKey code,
  with the cited tests where applicable. Its scope is the honest implementation.
- **Assumed:** a property of provisioning, primitives or the environment; runtime
  checks and tests do not establish it.
- **Open:** a native precondition or composition argument still needs a written,
  qualified assessment. Implemented supporting checks do not close it.

The current local experiment assumes independently provisioned high-entropy
honest roots, working OS randomness, trusted peer enrollment and driver policy,
authenticated identities, and cooperating processes sharing an honest filesystem
and stable authority lock files. Root loading checks length, not entropy or
independence. Source/configuration digests identify approved bytes under that
trust assumption; they are not remote attestation. Receipt/policy fields bind
the request but do not implement a production authorization service.

Primitive assumptions include the required security of HKDF, the hashes,
signatures, AEAD, DH and the pinned native OT/signing protocols. The exact
random-oracle/extraction assumptions at the replacement boundary remain open.
Filesystem controls provide no cross-host consensus or hostile rollback defense.
Memory clearing remains best effort, as inventoried in SECURITY-REVIEW.md.

## Local constructor contract

The interface is [pairkey_research_two_party](patches/research-keyshare.rs).
It returns `None` unless all of these predicates hold:

1. `party` is 0 or 1 and its supplied secret scalar is nonzero.
2. `Q`, `S0` and `S1` are nonidentity group points, and `S0 != S1`.
3. `2*S0 - S1 = Q` and `secret*G = S_party`.

On success it constructs `n=t=2`, IDs 0/1, coordinates 1/2 and ranks zero. It
copies the supplied key ID, chain code, setup SID and extra data; it stores the
common zero seed in `EachParty[0]` for both roles and the directional sender and
receiver OT seeds in the opposite party's slot, as required by native accessors.

For PairKey inputs `A=aG`, `B=bG`, `Q=A+B`, the caller supplies `s0=a/2`,
`s1=-b`, `S0=A/2`, `S1=-B`. Interpolation at zero has coefficients 2 and -1,
so `2*s0-s1=a+b`. Rejecting equal shares excludes the constant polynomial that
would destroy this threshold representation. Canonical public-point decoding
and manifest consistency checks are supplied by [lib.rs](src/lib.rs).

These predicates establish representation consistency. They do not establish
knowledge of the remote scalar, its distribution, secure generation of the OT
correlations, acceptable zero-mask distribution, freshness, or safe composition.
The constructor itself accepts caller-provided identifiers and seed structs
without authenticating their provenance. It must be used only through the
reviewed admission/reservation path. Native `Keyshare` supports cloning and byte
access; the worker's ownership discipline supplies single use within this path.

## Requirements and existing PairKey enforcement

The native security requirements in this table are a **proposed caller contract**
for confirmation by Silence, not a claim that the native theorem has already
been shown to require exactly these conditions. O1–O6 identify unresolved rows
of the security argument; E1–E5 below identify implementation evidence.

| Requirement | PairKey supplier and enforcement | Established property and residual assumption | Evidence |
|---|---|---|---|
| Honest contribution generation | `Root::derive` and `Root::identity` in [lib.rs](src/lib.rs) | Implemented deterministic, separated domains and nonzero refusal. Root entropy/independence and joint multi-output pseudorandomness are assumed; suitability for the selected model is O1. | E1; source |
| Agreed, authenticated wallet and remote contribution witness | `WalletRecord`, `Endorsement`, `WalletStore` in [registration.rs](src/registration.rs); worker admission | Implemented final-record proof/signature binding, immutable preparation/commit, local root match and admission before OT reservation. Required extraction and allowed adaptive contribution selection are O1. Trusted enrollment/policy and honest filesystem remain assumed. | E1 |
| Correct threshold representation and derived public key | `Manifest`, restricted constructor, native `derive_with_offset` | Implemented equations, fixed coordinates/ranks, chain-code rule and final derived-key verification. Admissibility of this key distribution and related public children is O2. | E1, E2, E4 |
| Correct directional OT/PPRF correlations | `preprocess` in [pool_worker.rs](src/pool_worker.rs), pinned base-OT/PPRF checks | Implemented authenticated setup and role-specific IDs, native proof checks and completed transcript agreement. Required joint correlation distribution/secrecy versus native keygen is O3. Seed types alone do not prove it. | E2, E4; native source |
| Appropriate common zero material | `preprocess` commitments/reveals and native `get_zeta_i` | Implemented both commitments before reveals, checked openings and ordered seed derivation; opposite masks cancel algebraically. Required distribution, permitted knowledge and selective-abort effects are O3. | E2, E4; native source |
| Wallet-independent preprocessing safely bound to one later request | `SetupInput`, `Transcript`, `Consumption`, `ReservedEntry` in [pool.rs](src/pool.rs), worker agreement | Implemented separated setup/completion/consumption bindings and propagation to native identifiers. Adaptive consumption, challenge ordering and composability are O4. | E2, E4 |
| No reuse after reservation, failure or restart | `RamPool::reserve`, consuming `into_package`, public retirement records and worker generation invalidation | Implemented remove-before-fallible-use and no restoration. Effective across cooperating processes under the local authority assumptions; hostile snapshots are excluded. Required cryptographic failure scope is O5. | E2, E3, E5 |
| Private fresh signing randomness and agreed message | worker's fresh seed per `sign::run`, authenticated consumption agreement | Implemented independent OS RNG call per combined signing attempt and exact prehash/path agreement. RNG quality and authenticated peer/policy enrollment are assumed. | E4; source |
| Validated result and preservation of security failures | derived-key ECDSA, low-S and recovery checks; native error mapping, shared release gate and collector drain | Implemented result validation and local incident cutoff. Unexpected late failures cannot be accepted merely because a result exists. Native denylisting obligations and cross-session scope require O5/O6 confirmation. | E4, E5 |

### Honest KDF and registration details

`Root::derive` uses HKDF-SHA512 with salt `pairkey/dkls-research/root/v1`;
its info is the application digest under `pairkey/dkls-research/contribution/v1`
of `(role, key_id)`. It reduces 64 output bytes modulo the curve order and
refuses zero. This is negligibly biased wide reduction, not exact uniform
sampling; there is no retry to select another contribution for the same input.
Identity derivation uses HKDF-SHA256, salt `pairkey/dkls-research/identity/v1`
and the role byte. Joint use of the same root for identity and multiple wallet
contributions needs the stated PRF assumption. A scalar proof does not certify it.

The record's namespace labels the existing key-ID KDF; it is not an additional
KDF input. Both parties endorse the canonical final record, including ordered
identities, contributions, aggregate key, chain code, configuration and supported
versions. The Schnorr challenge binds record digest, role and proof commitment;
the identity signature also binds the response. Each worker persists its exact
prepared endorsement before release, then commits only with both endorsements
and its matching preparation. Conflicts and partial files fail closed.

This establishes concrete transcript binding and local non-equivocation under
the filesystem assumption. It does not establish concurrent extraction. There
is no contribution commit-before-reveal phase. A malicious signer can select
known `b` after seeing `A` and grind public predicates of `A+bG`. That fact alone
is not a key-recovery or forgery attack; O1 must determine whether the selected
functionality permits it. Merely presenting `B=xG-A` without knowing its discrete
logarithm is a different case, for which the knowledge proof is relevant.

### Setup secrecy and native identifier trace

Both directional OT/PPRF setups run before wallet/message selection. Each party
retains its local sender and receiver seeds; cross-party consistency and the
secrecy required by native RVOLE are O3. The constructor copies these opaque
structs without an independent remote-correlation check. In native signing the
local `SenderOTSeed` feeds `RVOLEReceiver`, and `ReceiverOTSeed` feeds
`RVOLESender`; the reversal reflects the extension roles, not swapped peers.

Both signers intentionally learn the common zero seed. The authenticated
encrypted setup channel hides reveals from an external relay under the channel
assumptions; it does not hide the seed from either participant. Commitments
prevent changing a committed coin after seeing the other reveal. A last revealer
can still abort based on that reveal, so unbiased output conditioned on completion
is not established. Native opposite-sign masks cancel, but whether this seed
generation and knowledge pattern meets native signing assumptions remains O3.

The implemented identifier trace is:

1. `SetupInputDigest` binds ordered identities, configuration, entry, boots and
   recipe. Directional base-OT IDs order receiver/sender; PPRF IDs order
   sender/receiver. No wallet, path or message is present.
2. `CompletedSetupDigest` binds the input and all eight exact validated setup
   bodies in canonical stage/role order. Both peers acknowledge the same digest
   before availability. ACKs themselves are outside the hashed transcript.
3. Version-2 `Consumption` binds input/completion/entry, committed wallet-record
   digest, scheme/path, prehash, receipt/policy version and attempt. The pooled
   worker requires a registered digest before reservation; later validation or
   agreement failures burn the reserved entry.
4. Its digest becomes package `extra_data` and native `InstanceId`. The package
   final SID hashes the completed digest and consumption digest under
   `pairkey/pool/package/v1`.
5. Native signing hashes ordered round-1 SIDs with that package final SID, then
   derives directional MtA SIDs using sender/receiver IDs. The pinned extension
   and RVOLE code retain their own challenge/transcript logic unchanged.

This trace establishes propagation, not that a hash of earlier setup includes
future native online messages or that every Fiat–Shamir dependency is sufficient.
O4 must assess the actual native challenge order and adaptive consumption.

## Native key generation properties and open obligations

| ID | Replacement boundary and unresolved obligation | Required closure evidence |
|---|---|---|
| **O1** | Native keygen uses a polynomial/commitment/proof ceremony. PairKey supplies root-derived honest contributions and final-record-bound Schnorr proofs. Specify the required witness extraction, corruption model, multi-wallet/concurrent setting and admissibility of adaptive known-scalar malicious contributions. | Applicable native input definition/theorem and a reviewed mapping of this ceremony, including the honest KDF assumption. Explicitly select the registration decision below. |
| **O2** | Native keygen creates its coordinates, shares and chain code through its own protocol. PairKey fixes coordinates 1/2, converts additive shares, and uses public `H(key_id,Q)` as chain code. Establish admissibility of this distribution and public non-hardened child offsets. | Confirm fixed coordinates/ranks and public chain-code semantics, with the required related-key argument. Algebra alone is insufficient. |
| **O3** | PairKey uses the exported EndemicOT/PPRF APIs and a separate common-coin setup in place of native keygen's joint output. Establish the required joint distribution, correlation/secrecy, zero-seed knowledge and abort behavior. | Property-by-property native-keygen output contract, precise role mapping and an argument for the replacement setup, including selective abort. |
| **O4** | PairKey prepares material before wallet/message selection and binds a single later consumption. Establish security under adaptive choice, concurrent setup/consumption and the concrete identifier/challenge ordering. | Written composition argument for this offline/online split, naming any restrictions. Functional signing and identifier tracing alone do not close it. |
| **O5** | PairKey burns failed material and locally fences the signer pairing. Determine which failures require stopping simultaneous and future sessions, and over which identity/wallet/configuration scope. | Upstream failure-to-action contract plus an assessment that the local scope satisfies the claimed deployment model. State restrictions beyond cooperating local processes. |
| **O6** | Historical audit evidence must be connected to the exact pin and dependencies, and its native guarantees separated from imported material. | Source-linked audit/revision/patch coverage matrix; current disposition of TOB-SILA-13 and combined OT specification; explicit supported/unsupported import assumptions. |

The public child offset `delta` produces native weighted contributions of the
form `a + delta/2 - z` and `b + delta/2 + z`, which sum to `a+b+delta`.
The deterministic public chain code supplies neither secret entropy nor a BIP32
master-key generation ceremony. O2 concerns the resulting signing-key family.
The separately reported upstream `IL > n` versus `IL >= n` invalid-child check
is a known boundary-condition limitation; it remains deferred, with no dependency
patch in this contract work.

The audit's caller duties include fresh private randomness, message consensus,
safe key/presign storage and single use, and stopping concurrent/future sessions
with an offending peer after relevant protocol-check failures. PairKey's local
controls support these duties; O5 determines their exact required scope. Invalid
unauthenticated traffic, context mismatch and peer abort do not by themselves
prove a peer cheated. The two-party attribution argument must not be generalized
to more parties or another native revision without review.

### Registration decision remains pending

- **A: adaptive known-scalar contributions are admissible.** Keep the current
  ceremony if a reviewer establishes the required extraction and composition
  properties for it.
- **B: contributions must be fixed before reveal.** Design a separately versioned,
  authenticated commitment/opening ceremony binding ceremony/wallet IDs, ordered
  enrolled identities, role, contribution and protocol version. Require both
  commitments before revealing the honest contribution, retain final-record
  endorsements and durable preparation, and specify replay/restart/abort behavior.
  A commitment phase alone does not prove concurrent extraction or prevent
  selective-abort bias.

Neither option is selected by this draft. No existing records are reinterpreted
or rewritten. A protocol change requires the supported contract and a separate
implementation review; if neither option has an argument, C1 remains open.

## Verification evidence and closure

- **E1 — Registration and representation:** [registration_tests.rs](src/registration_tests.rs)
  covers metadata binding, final-record proofs, authenticated proof failures,
  exact retry behavior and request substitution. [registration_process_tests.rs](src/registration_process_tests.rs)
  covers process death and write/sync failures. [invariants.rs](tests/invariants.rs)
  covers conversion and native package invariants.
- **E2 — Binding and ownership:** [pool_tests.rs](src/pool_tests.rs) covers canonical
  encoding, setup/consumption binding, transcript completeness, reservation
  ownership, expiry, incidents and restart. Synthetic seed fixtures establish
  metadata/ownership behavior, not valid malicious-secure correlations.
- **E3 — Reservation transitions:** [reservation_tests.rs](src/reservation_tests.rs)
  covers injected I/O failures, process death and construction cancellation, with
  positive controls and compile-fail ownership examples in [pool.rs](src/pool.rs).
- **E4 — Protocol execution:** [native_process_tests.rs](src/native_process_tests.rs),
  [pooled_process_tests.rs](src/pooled_process_tests.rs) and
  [extended_process_tests.rs](src/extended_process_tests.rs) exercise native
  execution, actual handoffs, positive controls and overlapping local processes.
- **E5 — Failure observation and cutoff:** the collector regressions in
  [pooled_process_tests.rs](src/pooled_process_tests.rs) reject unexpected late
  failures, wrong/missing publication acknowledgments, duplicate replies, reader
  failures and incomplete drain. Real worker cases cover idle/active typed
  cutoffs; [lifecycle.rs](src/lifecycle.rs) tests preserve original failure causes.

The prior remediation validation recorded 83 distinct tests across default and
fault-feature configurations, plus formatting, Clippy and a release build; see
[REVIEW.md](REVIEW.md). This is implementation evidence, not a security reduction.

PairKey owns this mapping, enforcement of the agreed contract and any subsequent
registration changes. Silence is asked to clarify native assumptions and coverage
in [SILENCE-REVIEW-QUESTIONS.md](SILENCE-REVIEW-QUESTIONS.md). A qualified reviewer
must assess the exact replacement composition. Close C1 only when O1–O6 have
supported answers adequate for a stated claim, including explicit residual
assumptions and restrictions. A generic audit statement, successful signatures
or this document's completion is insufficient. Production provisioning,
authorization, authority/rollback protection and recovery/refresh remain separate
deployment gates even after a cryptographic contract is agreed.
