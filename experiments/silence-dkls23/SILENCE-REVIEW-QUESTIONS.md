# Draft questions for Silence about the PairKey constructor

Draft version 4, updated 2026-10-11 for Silence maintainers and the PairKey cryptographic reviewer.
**Draft only; not sent.** We seek the native input contract and evidence needed
to assess PairKey's custom two-party key/setup construction. We retain Silence's
DKLS23 implementation and locked parameters. The 2026 paper is optional background;
we are not requesting a parameter change or a proof of that paper's construction.

## Context and supplied artifacts

Native revision: `af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`.
Dependencies: `sl-oblivious 1.0.0-beta`, `sl-mpc-mate 1.0.0-beta`.
PairKey reference: `5a6c05ad0bbc24d4ed51b36f00d82ff3055c6280`, with the
collector/shutdown fixes in `f0331a85b28c331018b0e31d1fac22bf74be0432`,
documented in [REVIEW.md](REVIEW.md).
Any external review packet should identify the final exact tree/patch and hashes.

- [Draft constructor contract](CONSTRUCTOR-SECURITY-CONTRACT.md), including
  implemented-versus-assumed requirements, native-keygen comparison and O1–O6.
- [Exact constructor](patches/research-keyshare.rs) and [native patch list](patch-source.py).
- [Setup and consumption trace](POOLING.md#setup-inputs-completed-transcript-and-consumption),
  [worker implementation](src/pool_worker.rs), [context/ownership implementation](src/pool.rs)
  and [registration](src/registration.rs).
- [Exact parameters and source hashes](SECURITY-REVIEW.md#exact-otvole-realization)
  and [dependency lockfile](Cargo.lock).
- [Migration alternatives](DERIVED-SHARES-VIA-MIGRATION.md) and
  [pool review evidence](OT-POOL-REVIEW.md), subject to the corrections and
  route-specific O1–O6 statuses in the
  [contract reconciliation](CONSTRUCTOR-SECURITY-CONTRACT.md#reconciliation-of-claudes-migration-and-pool-review).
  The proposal that either registration mode closes O1 is not an accepted premise.
- [Focused O3/O4 results](O3-O4-DEEP-DIVE.md),
  [Mode 2 lifecycle](MODE-2-MINIMAL-SPEC.md), and
  [share flow and native OT reuse](SHARE-FLOW-AND-OT-REUSE.md).
  The separate [shared native donor proposal](CLAUDE-CO-REVIEW-SHARED-SETUP.md)
  has functional evidence, not an accepted cross-wallet security contract.

PairKey's honest contributions are root-derived scalars `a,b`; public key
`Q=(a+b)G` is represented as shares `a/2,-b` at coordinates 1,2. An immutable
wallet record has both identity endorsements and final-record-bound Schnorr
proofs. There is no contribution commitment round before revealing public
contributions. Base-OT/PPRF and a common zero seed are prepared independently of
the wallet/message, retained in RAM, and consumed once after authenticated
agreement on the exact request. Native combined `sign::run` receives a fresh
private random seed. Registration and native parameters remain unchanged.

For each answer, please identify **supported, unsupported, or conditional** use;
cite the applicable implementation/specification/theorem and revision; state
remaining assumptions and any minimal PairKey-side requirement. An upstream
implementation contract is useful even where an external composition proof is
still needed. Please distinguish audited native behavior from conclusions about
our adapter.

## Questions and requested evidence

### Q1 Native key input and registration contract O1

We have now checked the [2023 paper](https://eprint.iacr.org/2023/765), revision
dated December 14, 2023: Functionality 3.2 (printed p. 14), Theorem 4.1 and
Simulator 4.2 (pp. 25–27), and §7/Protocol 7.1/Theorem 7.2 (pp. 57–61).
The [contract](CONSTRUCTOR-SECURITY-CONTRACT.md#what-the-2023-paper-establishes-at-this-boundary)
records the supplied PDF hash and precise source scope. The relaxed keygen
functionality receives the adversarial polynomial contribution before sampling
the honest polynomial. Section 7 expressly avoids extracting corrupt scalar
shares during key generation. We no longer frame stronger Schnorr extraction as
an inherent DKLS23 requirement.

Does this relaxed-keygen interface describe the required input contract of the
pinned implementation, or does its implementation impose additional conditions?
What exact simulation/distribution mapping would validate PairKey's two-party
conversion and deterministic honest contributions? Our current ceremony reveals
`A=aG` before a malicious participant must fix its known `b`, so the direct
mapping is missing. Is there a supported separate argument that permits that
behavior, including public-predicate grinding, or should PairKey pursue the
paper's contribution ordering?

For the commitment approach, what remains necessary beyond a salted hash of the
Hello? Please address the required commitment functionality, joint key/share
distribution, and abort/retry/concurrent semantics. Identify any extraction
needed by this replacement simulator separately from native keygen scalar
extraction. A new ceremony must account for contributions already disclosed by
`Describe` or an aborted attempt; re-committing to a known point does not restore
the first-disclosure condition. How should such wallets and exact retries be
handled while preserving existing keys and immutable records?

The malicious party is not assumed to follow the root KDF. For honest parties,
please assess the joint assumption for HKDF-SHA512 wallet contributions and
HKDF-SHA256 identity seeds from the same root, plus modular-reduction bias and
nonzero refusal. State the static-corruption, random-oracle and concurrency
assumptions for multiple wallets and queries. Distinct session IDs alone do not
establish the shared-root composition.

**Requested result:** a source-linked assessment of contract option A versus B,
with an explicit list of remaining obligations. Contribution commitment ordering
is the leading direction for reusing the paper's argument, not a completed
proof that Theorem 7.2 carries over. Existing Schnorr checks remain in place;
any versioned registration change requires a separate implementation review.

### Q1a Native migration and initial derived-key generation O1/O6

The pinned migration wrapper supplies the local additive contribution directly
as `KeyRefreshData.s_i_0`. `run_inner` uses it as the polynomial constant,
commits to the full coefficient-point vector in round 1 (including that constant
point), checks the expected Q, and returns complete native keyshare/OT/zero state.
Can Silence support this as an additive-share import with root-derived honest
inputs, without assuming a previously secure DKG? Please identify whether the
contract is fresh-key generation or imported-key signing, and give the input
distribution and prior-disclosure requirements. Does any review explicitly cover
this use, beyond shared implementation with refresh? The README lists migration
as unaudited.

Ordering precision: local OT1 is prepared/fed before the expected-Q check;
the check precedes processing peer OT1 and generating OT2/PPRF replies. Please
assess that actual flow, not an assumed check before any OT message.

Would you provide a separately typed initial derived-keygen mode, or another
supported API, that fixes supplied local constant terms using fresh protocol
randomness but learns Q inside the first run? Recovery would always require
the recorded expected Q. An optional wrapper argument alone is not sufficient:
the internal expected-key type/validation and chain-code policy also change.

Please address this first-run failure trace: honest A is revealed, the corrupt
peer aborts, no wallet record is produced, and a new first-run attempt lets it
choose a different b after learning A. Concurrent first runs have the same
problem. Is a durable reservation of the root/role/key-ID contribution namespace,
one initial attempt, and permanent retirement after potentially revealing failure
sufficient under the proposed model? Alternatively, what native transcript state
must be durably retained for exact recovery without a fresh adversarial choice?
Previously disclosed contributions cannot be made fresh by changing identities
or ceremony IDs while retaining the same KDF inputs.

The minimal draft retires every reserved failed initial attempt. If a less
conservative retry is supported before local R2 disclosure, what durable evidence
and transport semantics establish non-disclosure across crash/restart and all
earlier contexts? A local message-send flag alone is not an accepted recovery
contract. What namespace binding is required if roots can serve multiple peers?

Which chain-code policy is supported for initial mode: native jointly generated
chain code, or a specified public deterministic rule? Our current H(key_id,Q)
cannot be supplied before Q is known. H(key_id) would change existing child
addresses and needs an explicit versioned contract; it is not a silent substitute.
What final-record agreement and crash-recovery requirements accompany this API?

**Requested result:** a supported API and lifecycle/input contract, with explicit
proof and audit scope, rather than approval of a proposed three-to-five-line patch.
Mode 1 (external contribution commitment plus migration) and Mode 2 (native
initial derived-keygen) remain candidates; neither is assumed to inherit
Theorem 7.2 automatically. The additive-tweak fallback also remains unproved:
if supported, please identify a result covering adversarial b(A), concurrent
queries and the resulting threshold/public-child-key family.

### Q2 Representation and public child derivation O2

Are fixed coordinates `[1,2]`, ranks `[0,0]`, and the converted shares `a/2,-b`
admissible given nonzero/distinct share checks, local public consistency and
`2*S0-S1=Q`? Does the argument require additional distributional properties of
native DKG output beyond those predicates and the Q1 key-generation contract?

May the chain code be the public deterministic hash of `(key_id,Q)` under the
documented domain, with native public non-hardened derivation? Which related-key
assumptions or restrictions apply to adversarially selected paths and known
offsets `delta`, across multiple wallet keys and signatures?

**Requested result:** an explicit admissibility statement for the representation
and key family, not merely confirmation that interpolation and ECDSA verification
work. The separate invalid-child `IL == n` boundary issue remains deferred; no
dependency change is proposed in this draft.

For Q1a's migration route, the custom fixed-coordinate constructor is absent:
we retain the native output without a splice. Please separate this eliminated
representation boundary from the still-relevant root-input and public chain-code/
child-derivation obligations. A native package does not establish the provenance
of its imported secret by its format alone.

### Q3 Imported preprocessing and common zero material O3

What joint distribution, secrecy and correlation properties must native signing's
two directional `SenderOTSeed`/`ReceiverOTSeed` pairs satisfy? Is use of the
exported EndemicOT/PPRF APIs with our authenticated, direction-bound setup enough,
or does native DKG establish additional relations we must preserve? Please
confirm the local SenderOTSeed-to-RVOLEReceiver and ReceiverOTSeed-to-RVOLESender
mapping for this pin.

In particular, please map the compiled EndemicOT/PPRF/SoftSpoken realization to
Functionality 5.1 (`F_EOTE`), as required by the Protocol 5.2/Theorem 6.1 route.
Which argument establishes the OT-output fixing order used by Claim 6.7 for a
malicious sender? The source-level ordering is supporting evidence; we do not
treat it alone as a complete proof excluding every adaptive strategy.

The actual EndemicOT/PPRF probe in the O3/O4 report permits acceptance only for
one selected base choice after a sender corrupts the other branch. This is
selective-acceptance leakage, not a signing exploit. Please map the permitted
leakage to the compiled realization, for both corrupt roles and multiple
sessions, with output fixing/extraction in the required order. Matching
all-honest output distributions is not the target. Distinguish setup leakage
from leakage in repeated online extensions and state the concrete query/use
bounds; repetition of one successful branch probe does not reveal new bits.

Section 3.1 and Functionality 3.4 (printed p. 15) describe pairwise committed and
revealed seeds with opposite-sign random-oracle masks. Both participants know our
common zero seed, derived from committed then revealed coins. Native masks cancel
with opposite signs. This shared knowledge is not itself a claimed defect.
What mapping establishes that our particular seed combination, invocation IDs,
and abort behavior satisfy that realization? What secrecy/freshness conditions
does signing require for that seed and those masks, including knowledge by each
signer and an external relay? Does commit-before-reveal with possible last-revealer
abort meet the needed distribution, or must the argument account differently for
bias conditioned on completion and repeated failed setups?

**Requested result:** the native-keygen output properties actually required by
signing, and a reviewable mapping or identified gap for our setup. Local type
compatibility and cancellation algebra are already checked.

Additional source evidence confirms both base-OT direction order (OT receiver
first), PPRF direction order (builder first), the reversed RVOLE seed roles, and
the two-party EachParty[0] zero-seed slot. The layout test copies native seeds
and checks constructor placement; it does not generate seeds through our pool.
The native lower-indexed party samples the pair seed alone. Please distinguish
the fact that both signers know it from the separate question of selective abort
and adversarial seed choice. Withholding a pool reveal may cause only a timeout
burn, not an attributable quarantine.

### Q4 Offline preparation and later binding O4

Can these base-OT/PPRF seeds and zero material be generated before the wallet,
path and message are selected, then consumed exactly once? Our setup digest binds
peers/configuration/boots/entry; the completed digest binds all validated setup
bodies; consumption binds that setup plus the committed wallet record, path,
prehash and attempt. It enters package extra data, InstanceId and the package
final SID; native round-1 and directional MtA SIDs extend that binding.

Does this satisfy the native transcript/challenge ordering assumptions for
adaptive wallet/message selection? What restrictions apply to overlapping setups,
different wallets, aborted online attempts and fresh-entry retries? Is there a
published or internal argument for this offline/online split that can be cited?

**Requested result:** a supported composition statement, or the exact additional
PairKey binding/order requirement. We are not asking to alter native challenges
or OT/VOLE parameters on the basis of the 2026 reference.

Section 8.2 explicitly amortizes OT setup per pair across extension instances,
and section 3.1 allows zero-seed reuse. We do not consider offline setup or reuse
alone a defect. The remaining question is the exact concrete composition above.
In the pinned implementation, final_session_id binds the package SID and round-1
SIDs for MtA, but zeta is indexed by digest_i (DSG label, ordered round-1 SIDs
and nonce commitments), which does not directly contain the package SID. Please
assess this actual trace together with native envelope/instance checks; do not
assume every hash directly includes the consumption digest. The cited native
duplicate check concerns party IDs, not round-1 SIDs.

If instead PairKey caches the entire native migration package per wallet in RAM,
the wallet-independent pool boundary disappears. What cache generation,
agreement, lifetime and failure/refresh rules preserve the native reusable-seed
contract across repeated signatures and process restarts?

For a separate donor candidate, may one native DKG's directional OT seeds and
zero seed be retained per pair and placed into packages for independently
registered root-derived wallet keys? The tested package SID binds the wallet
record and donor generation, with fresh native signing randomness per invocation.
Please assess cross-key and concurrent composition separately from same-package
reuse, including secret-storage provenance, zero-mask indexing, allowed adaptive
queries, and concrete usage bounds. Native-origin seeds eliminate the custom
setup execution but do not themselves certify this splice.

Please state the complete freshness contract: RNG/PRG assumptions, SID/hash
collision bounds, InstanceId routing, snapshots and package-generation agreement.
Unique InstanceIds alone do not prevent private RNG replay. The split API's
`PreSign` is `Clone, Copy` and `finish` reads it by reference; what external
single-use authority is required? PairKey currently uses combined `sign::run`.

### Q5 Failure handling and session scope O5

Which native failures mandate burning material, stopping concurrent sessions,
or refusing future sessions with the same peer? Does fresh single-use setup
change any selective-failure or retry obligation? Please specify the scope across
wallets, boots, configurations and enrolled identities, and any conditions for
resuming service after an incident.

Protocol 3.6 step 8 explicitly requires stopping relevant concurrent and future
sessions after its check failures. We do not infer that fresh preprocessing
removes every selective-failure risk: the same correlation material is not
reused, but signing shares persist. Which obligations remain even with a new
entry for every attempt?

PairKey clears failed generations and uses a shared pairing-scoped local incident
authority to fence cooperating processes. It preserves original failures and
drains worker output through exit, including failures after a result. Invalid
unauthenticated traffic and context disagreement alone do not establish cheating.
Cross-host authority and hostile rollback protection are outside the experiment.

**Requested result:** a failure-to-required-action matrix and whether the stated
local boundary is sufficient for the claimed research model. Identify any
additional attribution assumptions specific to the two-party case.

The strengthened saved mismatch experiment requires two bounded error outcomes
and a typed detecting error (or a received abort on the other side) for mixed
OT material, zero-seed mismatch and one-sided splice. Its additional mixed-share-
generation case asserts only two errors; the logged check-3 classification for
that case remains diagnostic. These tests do not exercise incident publication.
Please confirm required actions independently, including whether configuration
changes may ever clear a pairing incident and under what authority.

With shared donor material, must every affected wallet and concurrent session
be stopped under one persistent incident authority? Specify when a pure timeout
can retain setup, when to retire it, and whether any restart after a ban is
supported. Neither a fresh donor nor an operational rotation schedule is assumed
to authorize restart. If periodic rotation is useful, supply a rationale and
usage bound rather than an arbitrary daily or signature-count threshold.

### Q6 Audit correspondence and current native specification O6

Please map the audit's DKLS23 target
`1510c2fafe3cd6866581ce3e2c43c565561b929b`, sl-crypto target
`a6b014722a29027d813bcb58720412da68f63d07`, and Appendix F supplemental
RVOLE commits `7422762`/`d760a6a` to our exact pin and locked dependencies.
Which intervening changes, including the current transcript implementation,
have subsequent review evidence? Which guarantees explicitly cover imported
key/setup material, and which assume native keygen output?

What is the current disposition of historical TOB-SILA-13, marked partially
resolved in the audit, and where is the current combined OT specification/security
argument? Please distinguish residual documentation/proof requests from known
implementation defects. We credit Appendix F's review of the replacement RVOLE
against DKLS23 Protocol 5.2 and do not treat missing revision correspondence as
evidence of an exploit.

**Requested result:** a source-linked revision/coverage matrix, explicit unsupported
interfaces and current specification references. A blanket statement that DKLS23
was audited does not establish coverage of PairKey's custom constructor.

Please identify a vouched revision and any review extension covering migration
with independently root-derived inputs or the proposed initial derived-keygen
mode. Keeping the native package intact removes our constructor/pool boundaries;
it does not by itself transfer refresh audit coverage to a different input
contract. A source-linked confirmation is requested before any pin upgrade.

Protocol 5.2's stated dimension rules give `xi=512` and `rho=1` at the locked
values `kappa=256`, `lambda_s=128`, `lambda_c=256`. This is parameter-rule
conformance, not an independent certification of the concrete implementation's
security level. Please keep any discussion of the 2026 reference separate from
the required native-contract and audit correspondence answers. No parameter or
native transcript/algorithm patch is requested.

## PairKey follow-through

PairKey will record each response against O1–O6 as supported, conditional,
unsupported or unresolved, with an owner and evidence link. A qualified reviewer
will assess the replacement composition and its precise allowed model. PairKey
will then propose any necessary wrapper or versioned registration changes in a
separate review. Until the obligations close, Spike C remains research-only and
C1 stays open. These questions do not authorize sending a message, changing
registration, modifying native parameters or upgrading dependencies.
