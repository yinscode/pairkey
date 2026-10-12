# Draft Spike C constructor security contract

Draft version 4, 2026-10-11. This contract describes the PairKey replacement
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
public child-path and message selection. The current ceremony allows a malicious
participant to choose a known scalar after seeing the honest public contribution,
and to abort. This behavior is a gap in a direct mapping to the paper's relaxed
key-generation functionality, as detailed below. The malicious participant is
**not assumed to follow PairKey's root KDF**. The argument must state its allowed
multi-wallet and session interleavings. One pooled worker serializes native
attempts; cooperating processes can overlap. Local concurrency tests do not
establish a concurrent or UC cryptographic proof.

Adaptive corruption, guaranteed completion, hostile host snapshots, proactive
share refresh and resistance to sequential compromise of both unchanged roots
are outside this claim. One root compromise exposes that party's namespace of
contributions; learning both roots at different times can expose aggregate keys.

The [2023 DKLS paper](https://eprint.iacr.org/2023/765), revision dated
December 14, 2023, is now available and is the primary theorem reference. The
76-page PDF supplied in the local review packet has SHA-256
`fe41a45db716161472f66c84bb39721c3545000b5515594d7192e894ccbba7e1`.
The passages identified below were checked directly; this update does not claim
a complete independent verification of every proof or cited primitive.
The [2026 paper](https://eprint.iacr.org/2026/976) is
supplementary reference only. Matching its sufficient bounds is not an acceptance
condition here, and this contract proposes no changes to Silence's parameters.

### What the 2023 paper establishes at this boundary

Page numbers here are printed page numbers; PDF page numbers are two higher.

- **Functionality 3.2, p. 14:** `F_RelaxedKeyGen` receives the adversary's
  polynomial contribution before sampling the honest degree-`t-1` polynomial
  uniformly. Its interface includes scalar contributions at honest coordinates,
  group-valued contributions at corrupt coordinates, and release/abort control.
  An aggregate-key equation alone does not establish this interface or joint
  distribution. Release can be withheld after the adversary sees the generated
  key, so uniform generation must not be confused with unbiased keys conditioned
  on successful completion.
- **Theorem 4.1 and Simulator 4.2, pp. 25–27:** the signing result uses the
  `F_Com`, `F_Zero`, `F_RVOLE`, `F_RelaxedKeyGen` hybrid. Simulator step 5
  combines the target public key and the received adversarial polynomial to
  construct the honest contribution. PairKey's current reveal-before-commit
  ceremony has not been mapped to this setup interface.
- **Section 7, p. 57:** the signing protocol does not require extraction of
  corrupt scalar shares during key generation; shares are rerandomized and
  extracted through `F_RVOLE` for signing. The relevant key-generation conditions
  concern public-key generation and consistent share distribution. This corrects
  any reading of draft v1 that stronger Schnorr extraction is inherently required
  by DKLS23. Any extraction needed by a proposed replacement simulator must be
  identified separately, including extraction of committed values where relevant.
- **Protocol 7.1 and Theorem 7.2/Simulator 7.3, pp. 58–61:** the proven
  key-generation protocol commits to polynomial data and share contributions
  through ideal commitment functionalities before opening them. This motivates
  commitment ordering for a replacement, but does not prove that adding a hash
  commitment around PairKey's Hello implements that protocol or functionality.
- **Section 3.1/Functionality 3.4, p. 15:** the paper describes pairwise
  committed/revealed seeds and opposite-sign random-oracle masks for zero sharing.
  This supports PairKey's setup design direction; the exact seed combination,
  invocation identifiers, abort behavior and composition still need mapping.
- **Protocol 5.2, pp. 39–41:** its stated dimensions are `xi = kappa + 2*lambda_s`
  and `rho = ceil(kappa/lambda_c)`. The locked values give `xi=512` and `rho=1`
  for `kappa=256`, `lambda_s=128`, `lambda_c=256`. This confirms conformance to
  those stated dimension rules, not a standalone security-level certification or
  proof that the concrete OT stack realizes every hybrid assumption.
- **Theorem 6.1, p. 42, and Claim 6.7, p. 50:** the RVOLE argument uses the
  `F_EOTE` hybrid, and Claim 6.7 uses OT outputs fixed before the adversary
  computes the challenge. Mapping the pinned EndemicOT/PPRF/SoftSpoken stack to
  that interface and ordering remains O3/O6. Inspecting the honest code's order
  alone does not prove the corresponding property against a malicious peer.

The native signing theorem's statistical guarantee is in its stated hybrid
model. Replacing ideal components with HKDF, signatures, DH, commitments and
concrete OT requires their computational assumptions and composition arguments;
the complete PairKey construction does not thereby gain an unconditional
statistical UC guarantee. Distinct session IDs and passing concurrent tests are
supporting checks, not substitutes for those arguments.

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

The requirements below combine the paper's identified conditions with a
**proposed implementation mapping** for confirmation by Silence. They do not
assert that PairKey realizes the hybrid functionalities. O1–O6 identify
unresolved rows of the security argument; E1–E5 below identify implementation evidence.

| Requirement | PairKey supplier and enforcement | Established property and residual assumption | Evidence |
|---|---|---|---|
| Honest contribution generation | `Root::derive` and `Root::identity` in [lib.rs](src/lib.rs) | Implemented deterministic, separated domains and nonzero refusal. Root entropy/independence and joint multi-output pseudorandomness are assumed; suitability for the selected model is O1. | E1; source |
| Agreed, authenticated wallet and admissible key-generation output | `WalletRecord`, `Endorsement`, `WalletStore` in [registration.rs](src/registration.rs); worker admission | Implemented final-record proof/signature binding, immutable preparation/commit, local root match and admission before OT reservation. Mapping the contribution ordering and joint distribution to Functionality 3.2 is O1; keygen scalar extraction is not a native theorem requirement. Trusted enrollment/policy and honest filesystem remain assumed. | E1 |
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
contributions needs the stated joint PRF assumption, covering both HKDF-SHA512
and HKDF-SHA256; a HMAC-SHA512 assumption alone does not justify replacing the
identity outputs too. A scalar proof does not certify these properties.

The record's namespace labels the existing key-ID KDF; it is not an additional
KDF input. Both parties endorse the canonical final record, including ordered
identities, contributions, aggregate key, chain code, configuration and supported
versions. The Schnorr challenge binds record digest, role and proof commitment;
the identity signature also binds the response. Each worker persists its exact
prepared endorsement before release, then commits only with both endorsements
and its matching preparation. Conflicts and partial files fail closed.

This establishes concrete transcript binding and local non-equivocation under
the filesystem assumption. There is no contribution commit-before-reveal phase.
A malicious signer can select
known `b` after seeing `A` and grind public predicates of `A+bG`. That fact alone
is not a key-recovery or forgery attack, but the ordering does not supply the
direct Functionality 3.2 mapping. Retaining this adaptive behavior would require
a separately supported argument under O1. Merely presenting `B=xG-A` without
knowing its discrete logarithm is a different case, for which the knowledge proof
is relevant.

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
is not established. Section 3.1 expressly uses shared pairwise seeds; knowledge
by both signers in the two-party case is not itself a newly identified defect.
Native opposite-sign masks cancel. Mapping this particular seed derivation and
invocation/abort behavior to the paper's realization remains O3.

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

The zero-mask trace is different from the MtA trace: native `dsg.rs:169-183`
computes `digest_i` from the DSG label, ordered round-1 session IDs and nonce
commitments, and `dsg.rs:233-234` passes **that digest**, not `final_session_id`,
to `get_zeta_i`. The latter hashes the pair seed and this digest with its labels.
Thus package/consumption binding must not be described as a direct input to every
native hash. The native instance/envelope and other transcript checks remain
part of the argument. `dsg.rs:139-152` rejects duplicate/out-of-range **party
IDs**; it does not establish rejection of duplicate round-1 session IDs.

## Native key generation properties and open obligations

| ID | Replacement boundary and unresolved obligation | Required closure evidence |
|---|---|---|
| **O1** | Functionality 3.2 fixes the adversarial polynomial contribution before sampling the honest polynomial. PairKey currently reveals the honest contribution first. Establish a replacement mapping for the joint key/share distribution, or a separate argument permitting the current adaptive known-scalar behavior. Native keygen scalar extraction is not required by §7. | Reviewed simulation/composition argument, including both honest KDFs, commitment realization if used, prior disclosure, retries and concurrent wallets. Identify any replacement-specific extraction requirement rather than assuming it. Explicitly select the registration decision below. |
| **O2** | Native keygen creates its coordinates, shares and chain code through its own protocol. PairKey fixes coordinates 1/2, converts additive shares, and uses public `H(key_id,Q)` as chain code. Establish admissibility of this distribution and public non-hardened child offsets. | Confirm fixed coordinates/ranks and public chain-code semantics, with the required related-key argument. Algebra alone is insufficient. |
| **O3** | PairKey uses the exported EndemicOT/PPRF APIs and a separate common-coin setup in place of native keygen's joint output. Establish the required joint distribution, correlation/secrecy, zero-seed knowledge and abort behavior. | Property-by-property native-keygen output contract, precise role mapping and an argument for the replacement setup, including selective abort. |
| **O4** | PairKey prepares material before wallet/message selection and binds a single later consumption. Establish security under adaptive choice, concurrent setup/consumption and the concrete identifier/challenge ordering. | Written composition argument for this offline/online split, naming any restrictions. Functional signing and identifier tracing alone do not close it. |
| **O5** | PairKey burns failed material and locally fences the signer pairing. Determine which failures require stopping simultaneous and future sessions, and over which identity/wallet/configuration scope. | Upstream failure-to-action contract plus an assessment that the local scope satisfies the claimed deployment model. State restrictions beyond cooperating local processes. |
| **O6** | Historical audit evidence must be connected to the exact pin and dependencies, and its native guarantees separated from imported material. | Source-linked audit/revision/patch coverage matrix; current disposition of TOB-SILA-13 and combined OT specification; explicit supported/unsupported import assumptions. |

### Reconciliation of Claude's migration and pool review

Reviewed the notes committed in `f2adfc4` and `74b4564`, and the supplied
`CLAUDE-TLDR-FOR-ASTRA.md`. This section qualifies their closure claims for this
contract. The source mappings below were checked against the local patched pin;
the saved layout-test source and log were inspected, not independently rerun in
this documentation update. No signing/registration code, native parameter or
dependency is changed.

**Confirmed implementation evidence:**

- Native migration passes the additive contribution directly to `run_inner`;
  `dkg.rs:209-210` fixes the polynomial constant to it. The round-1 hash
  (`hash_commitment`, `dkg.rs:752-775`) includes every polynomial commitment
  point, including the constant-term point. This is real commitment ordering
  within an attempt, not a claim that earlier disclosures become hidden again.
- The expected-key check runs before processing the peer OT1 round.
  Local OT1 is already generated and queued at `dkg.rs:294-328` before the R2
  reveal/key check. Do not generalize the check to "before any OT message".
- Pool base-OT IDs order **OT receiver, OT sender**, corresponding to native
  **message sender, message receiver**. PPRF IDs order builder/sender, evaluator/
  receiver. `SenderOTSeed` feeds `RVOLEReceiver`; `ReceiverOTSeed` feeds
  `RVOLESender`. Both two-party keyshares store their common zeta seed in
  `EachParty[0]`. These placement/direction questions are resolved locally.
- Section 8.2 (printed p. 64) explicitly amortizes endemic OT setup per pair
  across extension instances; section 3.1 permits reuse of zero-sharing seeds.
  This supports the modular design direction. Offline preparation is not by
  itself an identified defect. The cost assumption does not supply the missing
  argument for PairKey's concrete adaptive wallet selection and identifiers.
- Migration returns native shares/coordinates and complete native setup state.
  When that state is retained intact, there is no PairKey constructor, fixed
  coordinate conversion, pool coin flip or separate PairKey OT channel.
  Authenticated transport and request/lifecycle responsibilities still exist.

| Obligation | Spike C status after this evidence | Migration route, with complete native output |
|---|---|---|
| O1 | **Open.** Neither proposed registration mode closes the root-input/functionality argument. | **Open.** Commitment-first registration or initial derived-keygen needs the KDF, commitment, first-disclosure and retry argument. |
| O2 | Layout/interpolation supporting checks strengthened; admissibility and public child-key argument **open**. | Custom fixed-coordinate/constructor sub-obligation **not applicable**. Root-input distribution remains O1; public deterministic chain code and child derivation remain **open**. |
| O3 | Direction, storage and primitive-call correspondence established locally. Selective-acceptance probe rules out unconditional all-honest output equivalence; compiled malicious OT realization, permitted leakage and zero-mask invocation mapping **open**. | Separate PairKey preprocessing replacement **not applicable** if all native state is retained. Native OT realization and imported-input coverage remain upstream questions. |
| O4 | Local provenance, request binding, ordering and honest single use supported, including 20 actual channel mismatch checks. Full adaptive/concurrent composition **conditional**, not closed. | Wallet-independent pool boundary **not applicable**. A warm cache still needs agreed generation, lifetime, invalidation and concurrency rules. |
| O5 | Local error-action evidence strengthened; required cross-session/identity/configuration scope **open**. | Native failure duties and local enforcement still apply; cache eviction does not authorize retry after a ban-worthy error. |
| O6 | **Open**, including audit-to-pin correspondence and historical TOB-SILA-13. | **Open**, including explicit migration/derived-input coverage. Shared implementation is not sufficient audit attribution. |

The pool review's statement that all closable rows are closed is accepted only
for the specific checked implementation properties, not as closure of O3/O4.
The same primitive calls and valid signatures do not prove equivalence against
a malicious peer choosing messages, aborts and later wallets adaptively. The
zero seed being known to both parties is expected in two-party signing; this
does not prove every seed-selection/abort strategy immaterial. Withholding a
reveal can appear as a timeout and burn the generation without peer quarantine;
the claim that every such abort incurs quarantine is not supported by the code.
The old coverage-plan test expecting disagreement to return an entry remains
incorrect: reservation precedes agreement and burns the entry.

**Mode 1 remains a candidate construction.** A point commitment plus migration
is not literally Protocol 7.1, which uses committed polynomial data and private
evaluations. Establish the required commitment functionality and joint output
mapping before invoking Theorems 7.2/4.1. Include the joint wallet/identity KDF
assumption, reduction bias, prior disclosures (including ordinary worker startup
Hello, not only pool Describe), and exact retries. Preserve the existing
chain-code rule for this candidate rather than change addresses incidentally.

**Mode 2 needs more than an optional expected-key field.** A first attempt may
reveal the honest constant point and abort before any public record is saved.
A retry with no expected key then permits a newly chosen corrupt contribution
after that disclosure. Concurrent first attempts can likewise choose different
corrupt constants, despite deterministic honest inputs. A supported design must
reserve/serialize the contribution namespace before the first attempt, and
either resume against durably fixed peer commitments or retire the identifier
after any potentially revealing failed/uncertain attempt. Merely persisting one
winning output with create-new does not supply this property. Previously exposed
contributions are ineligible for a fresh-keygen claim under a new ceremony ID.

Prefer an upstream interface that distinguishes initial derived-key generation
from recovery/migration with a required expected key. The native
`KeyRefreshData.expected_public_key` type and validation, not only the wrapper
argument, would change. Chain-code policy also needs an explicit mode: the
existing `H(key_id,Q)` cannot be supplied before an unknown Q is generated.
Changing it to `H(key_id)` is an address/contract change; native fresh chain-code
generation is another upstream design option. Neither is approved here. Fresh
native RNG, durable public records and recovery checks remain required.

**Additive-tweak fallback:** retain only as an unproved research question, not
as a closure route or basis for dropping registration protection. Honest-key
ECDSA unforgeability or public BIP32 offsets alone do not establish threshold
signing for a malicious scalar chosen after seeing the honest point. A proposed
result must cover that key-selection oracle, proof/extraction assumptions if
needed, repeated/concurrent registrations and signing under the resulting key
family. No such reduction is supplied by the reviewed notes.

**Layout-test disposition:** keep the submitted source/log as review evidence;
promote a strengthened version to the automated suite in a separate test-only
change if this constructor remains. It deliberately reconstructs the synthetic
test key and re-shares it at coordinates 1/2, so it is not a distributed import
procedure or a test of pool-generated seed distribution. The excluded fields
are intentional; random native coordinates prevent direct whole-buffer equality
for this fixed-coordinate constructor, not all byte-identical splice tests.
An identity splice preserving native coordinates/shares is still testable.
The version committed in `95d029f` now has bounded completion, exactly two
results, explicit signature/recovery-ID verification, and typed negatives for
mixed OT, zero-seed mismatch and one-sided splice. The helper permits a typed
detecting error plus the other party's received abort; it does not require both
parties to return identical variants. Case 5 (mixed share generations) asserts
only that both results are errors: its logged check-3 failures remain diagnostic
evidence, not an exact error-class regression assertion. Strengthen that case
before automated-suite promotion. Retain independent fresh material and
pin/patch/command provenance; do not add a production secret-state accessor just
for the test. The current source/log were inspected, not rerun in this update.

The option comparisons also need a cold-wallet qualification: a wallet-independent
pool can hide setup latency for the first signature on a newly selected wallet,
whereas O-C' needs that wallet's native package first. Later warm-cache signing
has no corresponding setup cost. Per-attempt migration refreshes OT too, so
freshness is not unique to the pool. O-C' performance is still a projection.
NEAR's different triple/preprocessing architecture is not a contract for stripping
Silence keyshares; the precise "scalar only/per triple" claim is not used to
close any obligation here. The 2026 dimension question stays supplementary and
is not a new acceptance gate for unchanged Silence parameters.

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

Single-use preprocessing prevents reuse of the same correlation material. It
does not by itself prove that every selective-failure risk across attempts is
eliminated, particularly where signing shares persist. Protocol 3.6 step 8
(printed pp. 19–20) specifies concurrent/future-session failure obligations that
must still be mapped to the local incident policy. Fresh material is not
permission to resume with a peer after a
failure that requires refusal under the selected argument.

### Follow-up handoff and shared native setup qualifications

The original handoff's full-polynomial commitment, seed-role mapping and
zero-seed slot are confirmed. Its expected-key-before-first-OT claim is false;
the earlier ordering correction above applies. Neither Mode 1 nor Mode 2 closes
O1 automatically, and random native coordinates exclude whole-buffer equality
for a resharing constructor, not an identity splice. The additive-tweak fallback
remains an unproved research question. See the
[minimal Mode 2 specification](MODE-2-MINIMAL-SPEC.md),
[pool review requirements](OT-POOL-MINIMAL-REVIEW-SPEC.md) and
[native reuse note](SHARE-FLOW-AND-OT-REUSE.md).

The later [shared-setup review](CLAUDE-CO-REVIEW-SHARED-SETUP.md) and evidence in
`2b1cfb8`/`73a5ef0` concern a distinct candidate: a native DKG donor supplies OT
and zero seeds, while PairKey constructs packages for root-derived wallet keys.
That removes PairKey's exported-primitive setup execution, not the constructor,
registration or cross-key composition boundary. Native-origin material does not
make every subsequent splice audited. The committed run logs are functional
evidence; their reported independent reruns are Claude's, not this update's.

Fresh online IDs are a necessary reuse condition, not the only security
assumption. The honest seed supplies fresh R1 randomness under the RNG/PRG and
state-continuity assumptions; hash collision bounds, ordered peers, agreed
package generations, authentication, the compiled OT realization and global
failure handling still matter. A fresh ID blocks the demonstrated same-ID
matrix-cancellation mechanism, not every malicious strategy. Finite masks can
also collide with distinct digests; mask equality alone does not prove RNG
replay. A repeated instance-ID journal cannot detect replayed private RNG state
presented under a new instance ID, nor survive rollback of its own authority.

The split signing API does not enforce presignature single use by type:
`sign/messages.rs:141-143` derives `Clone, Copy` for `PreSign`, and
`sign/dsg.rs:730-747` finishes using a borrowed presignature. Caller-controlled
copies can be supplied again. PairKey uses combined `sign::run`; retain that
restriction, fresh invocation entropy and caller lifecycle enforcement. Do not
claim the unused split API offers no reuse path.

For the donor candidate, O1/O2 remain; O3's native-origin provenance improves but
its compiled realization remains open; O4 becomes a cross-wallet reusable-setup
composition obligation rather than the original single-use pool obligation;
O5 must cover every wallet/session sharing the donor; O6 must cover the pin and
the new composition. The existing incident namespace includes configuration:
cross-configuration continuity and any incident-clearing authority remain
unresolved, not implemented merely by proposing donor rotation.

Do not derive a rotation period or a multi-session leakage bound from the
one-branch selective-acceptance experiment. Repeating the same successful probe
reveals the same base choice; it does not demonstrate one fresh bit per signing
attempt. Counts from independently sampled setups do not measure accumulation
against one fixed setup. Rotation may be an operational policy, but it is not
a substitute for a proof or authorization to resume with a banned peer.

KDF v1 binds role and key ID, not peer. A new derivation version may canonically
bind pairing/namespace and root epoch, but identities used for this binding must
be established independently of the wallet KDF to avoid a circular definition.
An enforced fixed-pair root namespace is an alternative assumption to review.
Neither a new KDF nor a rotation interval is adopted here. Public child-key and
first-disclosure obligations survive any such namespace change.

### Registration decision remains pending

- **A: retain the current adaptive contribution behavior under a separate argument.**
  This is not supplied by the direct Functionality 3.2 mapping. A reviewer must
  establish the required security statement and composition, including related
  keys and repeated/concurrent registration and signing queries.
- **B: pursue the paper's contribution ordering.** This is the leading remediation
  direction for reusing the paper's relaxed-keygen argument. Design a separately
  versioned, authenticated commitment/opening ceremony binding ceremony/wallet IDs, ordered
  enrolled identities, role, contribution and protocol version. Require both
  commitments before the first disclosure of the honest contribution, retain
  final-record endorsements and durable preparation, and specify replay/restart/abort behavior.
  Review the converted-share distribution and a realization of the required
  commitment functionality; adding a hash round does not automatically inherit
  Theorem 7.2. Do not remove the existing Schnorr checks merely because the
  paper's own protocol needs no keygen scalar proofs.

The first-disclosure condition includes `Describe`, earlier failed or aborted
ceremonies, and registrations under any context that exposes the same deterministic
contribution. A new commitment or ceremony ID cannot make a known point hidden
again. The design must define how such wallets are refused, retained under the
older claim, or otherwise handled without silently changing keys or rewriting
records. Exact retries must not enable a fresh adversarial choice after a reveal.
Commitments do not remove selective-abort bias or establish concurrency security
without the corresponding argument.

Neither option is authorized for implementation by this draft. No existing
records are reinterpreted or rewritten. A protocol change requires the supported contract and a separate
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
- **E6 — Submitted layout/mismatch experiment:** Claude's
  [test source](review-evidence/pairkey_research_layout_test.rs) and
  [saved output](review-evidence/pairkey_research_layout_test.output.txt)
  support field-placement and observed mismatch diagnostics, with the limits and
  test-promotion requirements in the reconciliation above. Source/log inspection
  in this update is not an independent runtime reproduction.

The prior remediation validation recorded 83 distinct tests across default and
fault-feature configurations, plus formatting, Clippy and a release build; see
[REVIEW.md](REVIEW.md). This is implementation evidence, not a security reduction.

The collector defect at `5a6c05a` (C2, Claude's Finding 4) is addressed by
`f0331a8`; review that diff separately from the unchanged registration contract.
Deterministic schedule summaries remain useful reproducibility artifacts. The
remediation adds fresh run IDs and terminal diagnostics, but does not convert
every schedule summary into a fresh-run attestation. Nonces, timestamps or host
labels can improve provenance without proving that a run occurred. None of
these evidence improvements closes a cryptographic obligation.

PairKey owns this mapping, enforcement of the agreed contract and any subsequent
registration changes. Silence is asked to clarify native assumptions and coverage
in [SILENCE-REVIEW-QUESTIONS.md](SILENCE-REVIEW-QUESTIONS.md). A qualified reviewer
must assess the exact replacement composition. Close C1 only when O1–O6 have
supported answers adequate for a stated claim, including explicit residual
assumptions and restrictions. A generic audit statement, successful signatures
or this document's completion is insufficient. Production provisioning,
authorization, authority/rollback protection and recovery/refresh remain separate
deployment gates even after a cryptographic contract is agreed.
