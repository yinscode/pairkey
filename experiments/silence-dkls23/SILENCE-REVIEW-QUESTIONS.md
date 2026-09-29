# Draft questions for Silence about the PairKey constructor

Prepared 2026-10-10 for Silence maintainers and the PairKey cryptographic reviewer.
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

What exact key-generation functionality or imported-key precondition does signing
rely on? Does it permit a malicious participant to choose a known scalar `b`
after seeing honest `A=aG`, including grinding public predicates of `A+bG`?
If not, what property must be established before the honest contribution is
revealed, and where does the signing argument use it?

For our final-record-bound Schnorr proof plus identity endorsement, what knowledge
or extraction property is required? Please specify the corruption, random-oracle
and concurrency models, treatment of multiple wallets under the same identities,
and whether proof non-malleability or stronger extraction is necessary. The
malicious party is not assumed to follow the root KDF. For the honest party,
are domain-separated HKDF outputs with 512-bit modular reduction suitable under
an explicit multi-output PRF assumption, including identity derivation from the
same root?

**Requested result:** the relevant full DKLS23 definitions/proof passages and a
decision on contract option A versus B, or a precise statement of what remains
unproved. We have not inspected the full original proof and do not infer its
requirements from the abstract. A commitment round would be a later, versioned
PairKey change, only if the selected contract requires it.

### Q2 Representation and public child derivation O2

Are fixed coordinates `[1,2]`, ranks `[0,0]`, and the converted shares `a/2,-b`
admissible given nonzero/distinct share checks, local public consistency and
`2*S0-S1=Q`? Does the argument require additional distributional properties of
native DKG output beyond those predicates and the Q1 witness requirement?

May the chain code be the public deterministic hash of `(key_id,Q)` under the
documented domain, with native public non-hardened derivation? Which related-key
assumptions or restrictions apply to adversarially selected paths and known
offsets `delta`, across multiple wallet keys and signatures?

**Requested result:** an explicit admissibility statement for the representation
and key family, not merely confirmation that interpolation and ECDSA verification
work. The separate invalid-child `IL == n` boundary issue remains deferred; no
dependency change is proposed in this draft.

### Q3 Imported preprocessing and common zero material O3

What joint distribution, secrecy and correlation properties must native signing's
two directional `SenderOTSeed`/`ReceiverOTSeed` pairs satisfy? Is use of the
exported EndemicOT/PPRF APIs with our authenticated, direction-bound setup enough,
or does native DKG establish additional relations we must preserve? Please
confirm the local SenderOTSeed-to-RVOLEReceiver and ReceiverOTSeed-to-RVOLESender
mapping for this pin.

Both participants know our common zero seed, derived from committed then revealed
coins. Native masks cancel with opposite signs. What secrecy/freshness conditions
does signing require for that seed and those masks, including knowledge by each
signer and an external relay? Does commit-before-reveal with possible last-revealer
abort meet the needed distribution, or must the argument account differently for
bias conditioned on completion and repeated failed setups?

**Requested result:** the native-keygen output properties actually required by
signing, and a reviewable mapping or identified gap for our setup. Local type
compatibility and cancellation algebra are already checked.

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

### Q5 Failure handling and session scope O5

Which native failures mandate burning material, stopping concurrent sessions,
or refusing future sessions with the same peer? Does fresh single-use setup
change any selective-failure or retry obligation? Please specify the scope across
wallets, boots, configurations and enrolled identities, and any conditions for
resuming service after an incident.

PairKey clears failed generations and uses a shared pairing-scoped local incident
authority to fence cooperating processes. It preserves original failures and
drains worker output through exit, including failures after a result. Invalid
unauthenticated traffic and context disagreement alone do not establish cheating.
Cross-host authority and hostile rollback protection are outside the experiment.

**Requested result:** a failure-to-required-action matrix and whether the stated
local boundary is sufficient for the claimed research model. Identify any
additional attribution assumptions specific to the two-party case.

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

## PairKey follow-through

PairKey will record each response against O1–O6 as supported, conditional,
unsupported or unresolved, with an owner and evidence link. A qualified reviewer
will assess the replacement composition and its precise allowed model. PairKey
will then propose any necessary wrapper or versioned registration changes in a
separate review. Until the obligations close, Spike C remains research-only and
C1 stays open. These questions do not authorize sending a message, changing
registration, modifying native parameters or upgrading dependencies.
