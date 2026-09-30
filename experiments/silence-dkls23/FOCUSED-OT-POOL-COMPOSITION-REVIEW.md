# Focused review of Spike C's OT pool composition

2026-10-11. Source review and independent local experiments, not an external
audit or a completed cryptographic proof. Reviewed the implemented original
Spike C, not an unspecified migration/Mode 2 splice. Registration is treated as
a separate unresolved input contract. Native parameters and dependencies remain
unchanged. No production or native source was edited.

Follow-up: [O3/O4 proof-boundary check](O3-O4-DEEP-DIVE.md) adds a native
selective-acceptance probe, a two-party zero-mask argument and 20 actual channel
context-mutation checks. It narrows, but does not unconditionally close, O3/O4.

## Verdict

**No concrete pool-specific signature forgery, secret-recovery attack or binding
bypass was found in this review. The offline/online split has a defensible
conditional composition argument, but O3/O4 cannot be declared fully closed.**

The strongest positive result is more specific than “signatures work”: actual
pool provenance and the agreed wallet request reach native MtA challenges; the
honest party fixes and retires its entry before any signing nonce or RVOLE choice
is sampled. Wallet-independent setup does not precompute those online secrets.

The central remaining dependency is the security contract of the compiled
EndemicOT/PPRF/SoftSpoken implementation as a setup-and-extension service with
fresh online identifiers and adversarially selected inputs. Source ordering and
tests support that contract but do not prove the malicious-party realization of
Functionality 5.1. Root-derived key admissibility is a separate prerequisite.

## Scope and evidence

- PairKey HEAD at review: `0b78e58000ca442d11f0c0b943c3ec01c5f709a3`.
  Other reviewers' uncommitted notes/evidence were present and preserved.
- Native pin: `af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`, with the existing
  documented research patches; sl-oblivious and sl-mpc-mate `1.0.0-beta`.
- Primary paper: [DKLs23, ePrint 2023/765](https://eprint.iacr.org/2023/765),
  sections 3.1, 5–6 and 8.1–8.4. The 2026 reference does not drive parameter
  changes or a finding in this review.
- Model: two fixed enrolled identities, at most one statically malicious peer;
  honest worker, fresh OS randomness and honest local reservation/incident
  authority. A corrupt peer may copy its seeds, deviate from the code, choose
  messages adaptively and abort. Single use is enforced at the honest endpoint,
  not assumed of the corrupt peer. Hostile host rollback/clones are excluded.
- Operational limits checked: 300-second entry lifetime, two worker pool slots,
  1,024 admitted-entry generation budget; setup IDs retired before setup exchange;
  sequential commands per worker. These are lifecycle limits, not security
  parameter changes or a bound on all lifetime adversarial attempts.

Source hashes, commands and public run results are in
[the evidence manifest](review-evidence/focused_pool_composition_manifest.json).
Below, native references are relative to the pinned crate's `src`; oblivious
references are relative to the locked sl-oblivious crate's `src`.

## 1. Concrete binding and ordering

Let I be the canonical setup input digest, T the completed transcript digest,
C the consumption digest and P the package session ID. The checked path is:

```text
I = H(version, recipe, ordered identities, boots, configuration, entry)
T = H(I, ordered commitments, coin reveals, OT1 bodies, OT2/PPRF bodies)
C = H(I, T, entry, wallet-record digest, scheme, path, prehash,
      policy receipt/version, attempt)
P = H_package(T, C)
native InstanceId = C
native final signing SID = SHA256(R1_sid_0 || R1_sid_1 || P)
directional MtA SID = H_native(final signing SID, sender, receiver)
```

The notation abbreviates the actual domain-separated encodings; it is not a
new proposed hash. See `src/pool.rs:91–130,177–248,258–285`,
`src/pool_worker.rs:85–222,365–437`, native `sign/dsg.rs:162–183,192–234,283–306`
and `sign/dsg.rs:1061–1075`.

Each honest worker validates both directional OT/PPRF results and requires the
peer's authenticated equal T acknowledgment before admitting an entry. The
transcript records exact validated bodies in canonical stage/role order. This
establishes agreement on public setup messages, not a proof of the peer's secret
state or of correct OT distribution.

Reservation removes the entry before fallible consumption checks and writes an
irreversible tombstone. The worker agrees C over a channel keyed by C before
constructing the package. Only then does it sample the signing seed. Native
signing samples its nonce, nonce commitment blinding and R1 SID; RVOLE samples
fresh beta and extension-check randomness online. The pool has neither a nonce
nor a completed RVOLE correlation (`pool_worker.rs:374–437`, native
`sign/dsg.rs:75–102`, oblivious `rvole.rs:104–143`).

**Assessment:** within the honest-authority model, ordinary substitution of a
wallet, entry, path, message or setup transcript cannot silently select a
different honest signing invocation without breaking the authenticated context,
hash binding or native checks. Invalid requests may burn entries: availability
is not promised. There is no identified missing wallet-to-MtA binding.

## 2. Why later wallet selection is plausible, and what that assumes

The native preprocessing functions take session identifiers, OT messages and
randomness, not signing shares, wallet keys or messages. The pool preserves the
checked call directions and PPRF verification. Native DKG also places these
results in distinct keyshare fields; its final share proofs do not constitute a
joint proof relating OT seeds to the signing scalar. DKG's key-generation checks
still matter for the key-input contract and are not replaced by this observation.

The native extension interface already accepts an online SID distinct from its
setup SIDs. SoftSpoken expansion, correlation checks and output randomization
use that online SID; RVOLE uses it for the gadget, theta and mu. Pooling does not
remove these checks. Fixing P before the fresh honest R1 SID is revealed does
not add an observed post-R1 entry-selection opportunity at the honest worker.
Adversarial grinding of the corrupt R1 contribution must already be handled by
native signing's own contract.

A **conditional argument**, rather than a claimed new theorem, is:

1. Assume the compiled setup/extension stack securely realizes the required
   malicious OT/RVOLE service across distinct fresh SIDs, including arbitrary
   allowed inputs chosen after setup and auxiliary information from key creation.
2. Replace that service with the ideal functionality. Each honest reserved entry
   supplies one pair of directional online invocations, with unique contexts.
3. The later selected key share is then an online multiplication input; setup
   need not know its wallet. Authenticated consumption fixes which invocation
   receives it. Failed attempts consume their entries and follow the required
   incident policy.
4. Invoke native signing security only for admissible key/zero-sharing inputs
   and its stated failure duties. This last condition does not establish O1/O2
   for PairKey's registration/constructor.

The missing step is **step 1 for this compiled stack and API boundary**, plus the
separate zero/key-input contracts in step 4. In Claim 6.7 the OT outputs must be
fixed before the relevant theta query. `RVOLESender::process` computes extended
outputs before a_tilde/theta, but a malicious peer does not have to run that
function. A realization argument must establish the corresponding fixing or
extraction property for deviations; source execution order alone cannot do it.
The existing historical audit-composition question remains relevant, not resolved.

The paper's per-pair amortization is consistent with this decomposition. It is
neither a proof for PairKey nor evidence that wallet-independent setup is itself
a defect. Ask Silence for this precise setup/extension contract, rather than a
generic endorsement of “offline OT.”

## 3. Zero seed: agreement, bias and invocation binding

Both coins and their commitments are included in T. The pool seed is a
domain-separated hash of I and the ordered coins, so P and the MtA SID also
commit indirectly to that seed. Both native keyshares use EachParty[0] in 2PC;
their zeta masks are opposites.

The native zero-mask invocation is nevertheless different from MtA:
`digest_i` hashes the DSG label, ordered R1 indices, SIDs and nonce commitments;
`get_zeta_i` hashes the seed and that digest. It does not directly hash P.
The fresh honest R1 SID and commitment provide invocation separation, and native
message IDs bind InstanceId C (`setup.rs:109–131`). Native filtering matches the
expected ID and the signed/AEAD envelope authenticates it (`proto/tags.rs`,
`proto/signed.rs`, `proto/encrypted.rs`). Under fresh RNG and hash/
authentication assumptions, I found no replay path from this omission alone.
This is a source-level binding argument, not a proof of the full FZero mapping.

**Concrete qualification:** a malicious last revealer can calculate the candidate
pool seed and withhold its reveal unless a public predicate holds, for example
its low bit being zero. Consequently the seed conditioned on completed attempts
need not be uniform. A timeout burns the generation but does not quarantine the
peer, so fresh-generation retries do not eliminate that selection.

This observation does **not** establish a signing attack. In native keygen a
malicious lower-indexed party can choose the seed; a malicious higher-indexed
party can also abort after receiving it. A new honest signing nonce/SID is
sampled later in both constructions. The obligation is a seed-selection and
abort-aware FZero/signing argument, not secrecy of the seed from either signer
or a claim that completion is unbiased. Rate limits address availability/query
budget; they do not turn the seed into an unbiased coin conditioned on success.

## 4. Channel, ownership and failure boundaries

Signed boots bind enrolled identity, role, generation and DH public key.
SetupChannel rejects noncontributory DH, derives its key using the full context
and authenticates context, sender and phase label. Exact cross-context or
cross-phase replay therefore fails under the stated assumptions. Each phase is
used once per context; failed setup contexts are not reopened. The channel uses
random 96-bit nonces, so its security bound includes nonce-collision probability;
AAD does not make a nonce collision harmless. No concrete collision/replay
defect was found in this bounded, per-context-key usage.

Source: `pool_worker.rs:282–308,476–521`, `pool.rs:132–168,497–538`,
`wire.rs:246–343`. This is a two-party channel argument, not transferable
third-party evidence of blame or a general multi-party broadcast construction.

Attributable PPRF/commitment/native OT failures quarantine; aggregate native
consistency failures freeze. Timeouts, disconnects and context disagreement
burn without asserting peer guilt. The service invalidates unused entries and
ends the worker on command failure. Ordinary restart does not revive used setup
IDs. Fresh entries do not bypass the existing pairing-scoped incident authority.

Native required failure scope still needs confirmation. Local tests establish
cooperating-process behavior, not cross-host enforcement or hostile rollback
resistance. Do not promise that a malicious peer has erased its copy of a seed;
the useful invariant is that the honest party never invokes a retired entry again.

## 5. Independently run checks

| Check | Result | Limit |
|---|---|---|
| Existing `pool::tests` | 11 passed | Includes synthetic-seed ownership fixtures; not distribution evidence |
| Actual `pool-demo`, samples=1 | Six verified baseline signatures across three wallets and two paths; restart signature succeeded; all 23 refusal cases passed | Sequential research workers, fault feature enabled; not exhaustive adversarial scheduling |
| New public-API preprocessing/RVOLE probe | Six directional cases with inputs chosen after actual EndemicOT/PPRF satisfy c+d=a*b | Honest correlation correctness, not malicious security |
| New corrupted PPRF proof probe | Typed setup rejection (`Invalid proof`) | One actual proof mutation, not exhaustive corruption |
| New mismatched online SID and cross-entry seed probes | Both reject with `AbortProtocolAndBanReceiver` | Primitive boundary only; does not test worker incident propagation |

The four new tests are in
[focused_pool_composition_probe.rs](review-evidence/focused_pool_composition_probe.rs),
with [the independent run log](review-evidence/focused_pool_composition_probe.output.txt).
They ran in a scratch copy using the same locked versions and pinned native
source, with only the native dependency's filesystem path made absolute.
Its configuration digest differs because the scratch manifest differs; it is
not claimed as an end-to-end production-worker run. The pool demo used the real
experiment tree. No real roots, private seed material or aggregate signing
scalars are included in the saved review evidence.

Claude's newly strengthened layout/splice evidence was read but not independently
rerun here. It remains distinct from these actual-preprocessing probes.

## 6. Disposition and next actions

| Item | Disposition |
|---|---|
| Primitive role mapping, actual preprocessing interoperability | Supported by source and independent checks |
| Public transcript/request binding and honest local single use | Supported within the declared local authority/RNG/hash/channel model |
| Offline wallet selection as an inherent defect | No such defect identified; conditional argument above |
| O3 malicious setup/extension realization and zero-seed composition | Open; require the exact upstream contract or a completed realization argument |
| O4 full adaptive offline/online composition | Narrowed to that contract plus the documented binding/lifecycle assumptions; not unconditionally closed |
| O5 failure obligations and production authority | Local behavior checked; native-required scope and deployment enforcement remain open |
| O6 audit correspondence | Open; this review is not an extension of Silence's audit |
| Registration/constructor O1/O2 | Not resolved by this pool review |

Send Silence the concrete trace and ask for: (1) arbitrary fresh online SIDs and
late/adaptive input support after setup; (2) the compiled Functionality 5.1/output
fixing argument; (3) allowed zero-seed selection/abort behavior; (4) failure duties
across sessions; and (5) pin/API audit coverage. No request has been sent.

For PairKey, retain the enforced reservation/incident rules and add adversarial
integration coverage for the remaining context-mutation and interleaving matrix
before production use. Do not implement a hybrid splice until its seed/zero-seed/
final-SID ownership is fixed as a separate construction. Do not change native
parameters as a substitute for closing these contracts.
