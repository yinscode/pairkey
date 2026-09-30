# Minimal OT pool review specification

Draft v1, 2026-10-11. Review requirements, not an implementation or a security
approval. Silence parameters, dependencies and registration stay unchanged.
Results: [focused composition review](FOCUSED-OT-POOL-COMPOSITION-REVIEW.md).
Read with the [constructor contract reconciliation](CONSTRUCTOR-SECURITY-CONTRACT.md#reconciliation-of-claudes-migration-and-pool-review)
and [Silence questions Q3–Q6](SILENCE-REVIEW-QUESTIONS.md#q3-imported-preprocessing-and-common-zero-material-o3).

The [Mode 2 draft](MODE-2-MINIMAL-SPEC.md) retains complete native packages and
has no pool. Adding a pool is a separate construction. Fix the candidate before
reviewing it: original Spike C uses the custom constructor and pooled zero seed;
a migration/Mode 2 hybrid would splice pooled OT seeds into a native package.
Passing one candidate's tests does not approve the other.

## 1. Freeze the construction under review

Record the native pin, patches, dependency versions, configuration, two ordered
party identities, root/key creation contract and channel trust assumptions.
Specify exactly which keyshare fields come from native key generation, the pool
or PairKey. Include coordinates, shares, chain code, zero seed and final session
ID. For a hybrid, settle whether the zero seed stays native and how the final
session ID is assigned; do not silently inherit Spike C's constructor rules.

The review target is malicious-peer security within the stated deployment
model, including adaptive wallet/message selection and selective aborts.
Trusted-party or attestation assumptions may narrow that target only explicitly.
Neither a working splice nor an attested channel supplies the composition proof.

## 2. Setup and binding contract — O3/O4

Produce one trace from authenticated setup context through both base-OT
directions, PPRF verification, stored seed roles, completed setup digest,
consumption request and native signing checks. State when each value becomes
fixed, what the peer knows then and what it can choose after aborting.

Require fresh independent native randomness; role-correct seed placement;
distinct domain-separated IDs; authenticated peers/configuration/generation;
and agreement on the validated setup transcript before an entry becomes ready.
Consumption binds exactly one entry to the wallet record, child path, prehash
and signing attempt. Identify each actual native hash/envelope that carries
this binding rather than assuming that every challenge contains every field.

The checked native mapping uses OT receiver then OT sender in base-OT IDs,
builder then evaluator in PPRF IDs, SenderOTSeed for RVOLEReceiver and
ReceiverOTSeed for RVOLESender. Both two-party zero-seed slots are EachParty[0].
Native MtA uses the package-bound final session ID; zeta uses digest_i, which
does not directly include that package ID. The cited duplicate check rejects
duplicate party IDs, not duplicate round-1 session IDs.

Silence or a qualified composition reviewer must assess the joint distribution
and fixing order under malicious setup messages, overlapping entries, selective
abort and later wallet/message choice. Same primitive calls, different IDs,
valid signatures and byte-layout equality are supporting evidence, not this
argument. The paper's per-pair setup amortization supports investigating the
design; it does not establish PairKey's concrete binding scheme.

For the original pooled zero seed, include the coin-commitment/reveal rule and
last-revealer abort strategy. Both signers knowing the seed is expected in 2PC;
that fact alone does not settle adversarial seed selection or retry composition.

## 3. Lifecycle, abort and recovery contract — O4/O5

| State/event | Required behavior |
|---|---|
| Setup in progress | Not consumable. Any failed or uncertain setup is discarded; retry uses a fresh entry ID and fresh randomness, subject to incident policy. |
| Ready | Validated material has a single owner under the process/authority model. |
| Reservation | Atomically remove the entry from availability before request validation/agreement. Its retirement is irreversible. |
| Agreement mismatch, cancellation or timeout after reservation | Burn the entry. Never return it to the pool, even if no signing message was sent. |
| Signing success or failure | No second use of that entry. Preserve late worker failures and apply the required incident action. |
| Worker/process restart | Discard unavailable or uncertain RAM material. Generate fresh setup; do not reconstruct old entries or replay protocol RNG. |
| Peer state mismatch | Abandon affected entries and reconcile public state; never roll back a reservation to recover availability. |
| Attributable malicious failure | Enforce the reviewed ban/freeze and concurrent-session cutoff across the required scope. Fresh entries do not clear an incident. |

An ordinary timeout does not by itself justify blaming the peer. Distinguish
burning material from quarantine and freeze. Specify cross-wallet, process,
identity and configuration scope for each native error using Q5's requested
failure-action matrix.

State whether hostile VM snapshots/root-authority clones are excluded or which
external authority prevents a restored entry from being used. RAM-only storage
and ordinary local tombstones do not establish hostile rollback resistance.

## 4. Minimum evidence package

- Source trace with pinned references for primitive calls, argument order,
  seed placement, challenge inputs, authentication and failure actions.
- Identity-splice test preserving all native fields: byte-identical output.
  Keep constructor resharing tests separate and list their excluded fields.
- Actual pool-generated material used for independently verified signatures
  across distinct wallets and child paths, with fresh entries for each case.
- Malformed PPRF, mixed/swapped OT material and mismatched zero-seed cases:
  exactly two bounded outcomes, expected typed errors and no accepted signature.
  Assert the specified incident effects rather than merely some error.
- Races and crash injection around readiness, reservation, agreement and worker
  completion: at most one use, disagreement burns, restart never revives an
  entry, and late failures still reach the incident authority.
- Context mutations/replays across peers, configurations, boots, entries,
  wallets, paths and messages. Verify rejection and actual binding paths.
  A finite collision search does not prove identifier uniqueness.

Keep commands, pin/patch provenance and logs. Mark inspected prior results
separately from independently rerun tests. Existing layout-test evidence copies
native seeds; it does not establish pool-output distribution.

## 5. Review exit and upstream questions

PairKey can close concrete implementation findings and document lifecycle
invariants under its declared failure model. O3/O4 remain open until there is a
reviewable composition argument or an explicitly narrower accepted claim.
No composition defect found is not equivalent to composition established.

Ask Silence to confirm the required native keyshare setup properties, the
compiled OT stack's realization of Functionality 5.1 and fixing order, whether
the proposed offline setup/later binding satisfies them, zero-seed requirements,
failure-action scope, and audit coverage for the exact pin and construction.
These map to Q3–Q6; the audit-to-pin gap remains O6. O1/O2 still apply separately
to whichever key creation/constructor route is chosen.

The 2026 paper remains supplementary. This review proposes no parameter tuning,
dependency upgrade, registration change or production approval.
