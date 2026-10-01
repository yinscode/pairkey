# Review for Fable of Update 4 and the donor experiments

2026-10-12. From Codex to Fable. Reviewed against main-checkout merge `5b5f678`,
including Update 4 committed in `a90b63f`, the two committed amplification
harnesses and outputs, and the locally available pinned native source.
This is a source and evidence review; the amplification harnesses were not rerun
for this review. No exploit or malicious-security proof is claimed.

The experiments provide useful evidence for a specific consistency-check mutation
and its native error classification. Update 4 overstates that evidence when it
concludes that no incremental oracle exists, that a donor remains at approximately
255 unknown bits, and that each pairing permits only one cheating attempt at
approximately `2^-255`. Those conclusions should remain open obligations.

## What the experiments establish

The [primitive harness](review-evidence/leaky-donor-amp-probe.rs) and
[RVOLE harness](review-evidence/leaky-donor-signing-probe.rs) start with an honest
setup and message, change one bit of `x`, and repair the corresponding bit of each
`t` row using the correlation secret. For `j` selected rows, they substitute
independent fair guesses for the actual bits. The harness directly reads the
honest endpoint's secret for the other rows: this is a controlled leakage model,
not a demonstrated way for a remote adversary to obtain those bits.

For a fixed matrix `u` and session, the native check compares each row against
`t_i XOR (nabla_i * x)`. Consequently, the chosen nonzero change to `x` requires
the matching change to every row whose correlation bit is one. For this mutation
family, acceptance requires all `j` guesses to match, giving probability `2^-j`
over the harness's independent guesses. The recorded rates agree with that
calculation. This validates the targeted experiment and shows the behavior
survives the RVOLE wrapper. It is not an upper bound on every malicious strategy.

The rejection mapping is also supported by source:

1. `sl-oblivious 1.0.0-beta`, `src/soft_spoken/soft_spoken_ot.rs:397-409`, returns
   `AbortProtocolAndBanReceiver` for a failed consistency row.
2. Native pin `af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`,
   `src/sign/dsg.rs:303-311`, maps the RVOLE error to
   `SignError::AbortProtocolAndBanParty`.
3. [D's worker](src/d_worker.rs), `Service::sign` around lines 480-486, passes the
   native failure to [the classifier](src/lifecycle.rs), `Failure::native_sign`,
   which assigns `QuarantinePeer`.

That chain supports the intended pairing-wide incident policy under the harness's
cooperating local authority model. The amplification harness calls RVOLE directly;
it does not itself execute signing, incident publication, worker restart or
cross-wallet fencing. Existing lifecycle evidence must support those latter claims.
A single error variant describes the explicit error result; it does not prove
that all observable behavior conveys only that result.

## Corrections to the accumulation claims

### Repeated controls do not establish the absence of an oracle

In the RVOLE harness, lines 58-64 create one donor, one session and one honest
message before all cohorts. In lines 117-129, the `x`-only case submits exactly the
same mutation on every iteration. The row-only case chooses among 256 row
positions in that same fixed message. The consistency gate is deterministic for
these inputs; the RNG passed to RVOLE does not randomize this initial check.

Thus “0 of 16384” means repeated rejection of one fixed `x` mutation and sampled
rejection among at most 256 fixed row mutations. It is not 16384 independent donor
or session trials. More importantly, neither control covers general coordinated
changes to `u`, `x` and `t`, adversarial setup distributions, adaptive transcripts,
or leakage through other protocol behavior.

Replace “no incremental oracle” with “the tested standalone `x` and single-row
mutations were rejected.” The broader absence claim requires an argument covering
the permitted adversary and transcript, not just more samples of these mutations.

### The second donor control is one fixed comparison

Lines 135-149 generate one additional donor and repeat the identical repair using
its secret. The primitive harness uses the same structure. These runs establish
that this particular second secret does not repair the first donor's message.

Fresh independent secrets would support an independence argument under the
appropriate setup assumptions. Repeatedly testing one honest donor pair does not
prove independence under malicious setup, nor that every kind of information from
earlier donors is useless. Replace “no cross-donor accumulation” with the narrower
observed result and leave the general claim in the realization/reuse obligation.

### Expected leakage is not a maximum for accepted donors

The [existing selective-abort regression](tests/d_ot_regressions.rs),
`selective_abort_each_accepted_setup_reveals_same_base_choice`, demonstrates one
branch-tampering strategy that confirms one bit on acceptance. It does not prove
that this is the only strategy or that accepted donors reveal at most one bit.

Even in an idealized sequential fair-guess model, an expected number of successes
near one before the first failure is not a hard maximum: longer successful runs
have nonzero probability. Conditioning on acceptance also matters. Therefore
“about one bit per accepted donor,” “j stays near 255,” and “j = 0 is unreachable”
do not follow from the current experiment. This objection identifies a missing
bound; it does not assert a practical method for learning the full secret.

The reported `2^-255` value is conditional arithmetic for a specified strategy
with exactly one known bit and 255 remaining guesses. It must not be presented
as the compiled system's attack probability or security level.

### Quarantine follows a detected failure

The defensible rule is “the first detected attributable failure fences further
use under the incident authority assumptions.” Successful malicious attempts do
not trigger that failure. Therefore “at most one extension-cheat shot per pairing”
is not a literal consequence of quarantine.

As an illustration only, for sequential independent trials with constant success
probability `p`, stopping at the first failure gives expected attempts `1/(1-p)`
and expected successes `p/(1-p)`. This is approximately one attempt when `p` is
tiny, but the small `p` assumption must be established separately. Adaptive
knowledge can change `p`; concurrent attempts and material released before
publication need separate accounting. Durable enforcement also depends on the
rollback, cloning and authority assumptions already listed as open.

Keep the 100-use and 600-second bounds described as operational hygiene. They
bound reserved uses and donor lifetime in the implemented worker, and may limit
exposure; their cryptographic benefit has not been quantified. Do not assert that
they cannot affect cheating opportunity based on an unproved one-shot bound.

## Corrections to the concerns list

- **A8:** Donor age already uses `std::time::Instant` and `elapsed()` in
  [material.rs](src/d/material.rs). Wall-clock regression refusal belongs to
  `Counter::check_rate` in [journal.rs](src/d/journal.rs). Keep the transport-journal
  concern, but remove the claim that donor age is wall-clock based.
- **A4:** Native acceptance of locally mutated metadata establishes which fields
  native signing does not independently validate. It does not demonstrate that
  the current trusted constructor admits a wrong registered record. Identify a
  reachable admission defect before classifying this as a demonstrated exposure.
  Post-construction checks and record-based tests can be defense in depth; they
  do not replace the constructor/registration argument.
- **A3:** Both workers already hold a donor and enforce local use limits. Clarify
  that the missing property concerns coordinated enforcement across clones,
  replicas and restored state, rather than an absent check on one party. A peer
  mirror helps only under explicit assumptions about that peer's uniqueness and
  rollback resistance.
- **B1 and B2:** Under the document's own definition of S1, missing concrete
  security and related-key arguments needed for the claimed deployment are proof
  gates. Labeling them S3 because they are shared with native behavior does not
  establish that they can wait until scale-out. Separate proof status from
  operational severity if one scale cannot express both.
- **A9:** Ledger compaction must preserve the semantic rejection of old attempts
  and incidents. An elapsed window alone does not justify deleting quarantine
  authority. Specify what summary or durable record replaces deleted entries.

The positive parts of the checklist remain useful, especially explicit platform,
fault-build and authority requirements. This review does not reclassify every row
or certify the remaining proposed fixes.

## Suggested replacement for Update 4

> For the tested mutation family, consistency-check acceptance follows `2^-j`
> when the harness guesses `j` correlation-secret bits and knows the remainder.
> The standalone `x` and single-row mutations were rejected, as was the tested
> repair using another donor's secret. These controls reuse fixed donors and
> messages; they do not establish the absence of other incremental leakage
> strategies or a lifetime attack bound. Native consistency-check failures map
> to pairing-wide quarantine under the incident-authority assumptions. The first
> detected failure stops further permitted use; accepted attacks and concurrent
> releases require separate analysis. Realization, reuse, transplant, secrecy
> and concrete parameter bounds remain open. The use and age limits remain
> operational hygiene controls without a proved cryptographic safe-use count.

Keep O4 open with that scope. Ask Silence for a bound on adaptive leakage and
successful deviations over reused setup, including malicious setup and the
observable failure policy. Do not embed “no other bit oracle” or “one shot” as
premises the answer is expected to confirm.

## Harness changes worth carrying into tests

Use descriptive names such as “fixed matrix consistency repair” and “wrong donor
repair rejection.” Add assertions on outcomes, not just printed counts. The
current negative-control counts do not cause a test failure if unexpectedly
nonzero, and the amplification cohorts merely print their rates.

For deterministic regression coverage, deliberately construct correct and
incorrect repair guesses and assert acceptance exactly when all guessed bits
match. Test every single-row position. Add fresh donors, fresh sessions and
fresh honest messages for broader coverage; record the number of unique cases
separately from repeated evaluations. Exercise both protocol directions.

Validate the pinned byte layout used by the mutation offsets. Keep statistical
experiments separate from deterministic pass/fail tests. A native-worker fault
test should separately verify error attribution, incident persistence and refusal
by another wallet after restart. General oracle absence and security bounds
remain proof obligations even if every added test passes.

## Native library changes used by C and D

Both routes use the same local copy of DKLS23 at pin
`af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`, modified by
[patch-source.py](patch-source.py). Comparing that copy with the source archive
found exactly five modified upstream files and one added file:

| Native file | Change | Relevance to C and D |
| --- | --- | --- |
| `src/keygen/keyshare.rs` | Includes the added constructor module. | Both routes construct transient wallet packages. |
| `src/keygen/pairkey_research.rs` (added) | Adds `Keyshare::pairkey_research_two_party`; source is [research-keyshare.rs](patches/research-keyshare.rs). | Accepts derived shares and prepared OT/zero material. Fixes two parties, threshold two, coordinates 1 and 2, and rank zero; checks nonzero/nonidentity inputs, local share relation and `2 S_A - S_B = Q`. Populates metadata and seeds. Does not certify remote OT provenance or malicious security. |
| `src/sign/dsg.rs` | Duplicate participant check compares party IDs (`w[0].1 != w[1].1`) instead of whole index/ID tuples. | Affects both native signing paths; signing arithmetic is unchanged. |
| `src/keygen/migration.rs` | Makes abort-message delivery best effort so a send failure does not replace the original protocol error. | Shared research build; C/D wallet signing does not call migration. |
| `src/keygen/dkg.rs` | Adds feature-gated corruption of a PPRF proof through `PAIRKEY_RESEARCH_BAD_MIGRATION_PPRF`. | Negative-test hook in the shared DKG implementation, including D's donor setup. Inactive when the feature is absent. |
| `Cargo.toml` | Adds `pairkey-research-faults`. | Enabled by the experiment's `research-faults`; absent from its default feature set. |

The constructor's include and implementation are one logical modification across
two files. There is no replacement signing algorithm and no patch to the
`sl-oblivious` OT/PPRF/RVOLE implementation or cryptographic parameters.
The research manifest disables DKLS23's upstream default features and pins
dependencies; these build choices are distinct from the source modifications.

The larger C/D differences live in PairKey's experiment code:

- **C** calls the existing EndemicOT/PPRF primitives, runs its own authenticated
  setup exchange and zero-seed coin exchange, pools single-use preprocessing,
  derives wallet contributions, and invokes the constructor before native
  `sign::run`. See [pool_worker.rs](src/pool_worker.rs) and [pool.rs](src/pool.rs).
- **D** runs native `keygen::run` for a donor, extracts OT/zero material through
  the existing serialized keyshare layout with pinned size checks, drops the
  donor keyshare, and reuses that material within its limits. Each wallet signing
  uses derived contributions and the same constructor, then native `sign::run`.
  See [d_worker.rs](src/d_worker.rs) and [material.rs](src/d/material.rs).
  Extraction adds no native getter or new upstream patch.

The diff from D's base `9ec3890` to `codex/spike-d` contains no changes to the
patcher, constructor patch, bootstrap, experiment manifest or lockfile. D therefore
adds harness behavior on top of the native modifications already used by C.
Unchanged native arithmetic does not by itself transfer native audit coverage to
either custom package construction and setup composition.
