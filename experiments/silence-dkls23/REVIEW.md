# DKLS23 research review — lifecycle closure and Spike C

Keep DKLS23 experimental. A/B remain baselines; Spike C now uses a small RAM
preprocessing pool in long-lived local workers. Production dependencies and
architecture v0.4 are unchanged. The custom composition has not been adopted.

## Astra review of 0336e52 and assurance follow-up

Astra reports independently reproducing 43 distinct tests, 58 signatures and 34
refusal scenarios, plus Clippy in both configurations, with no new bypass,
duplicate consumption or regression demonstrated. Within cooperating processes
sharing an honest local filesystem, Astra recommends closing incident-check/queue-
handoff atomicity, both-role fencing, single-winner reservation, original-error
preservation and truthful persistence reporting. This review predates the newer
registration implementation; it does not approve that ceremony or composition.

The follow-up adds actual-native process tests: two separate workers generate
real EndemicOT setup material and run combined DKLS23 signing. A third process
publishes an incident only after both targets are paused before handoff. Setup
base-OT message 1, native R4 and verified final results each have protected,
positive and deliberate-bypass controls (nine schedules). An independent consumer
observes the actual transport queue; no oracle relies on cancellation or the
producer's error. These are Direct-route native executions using the common Wire
gate, not overlapping C pool/signing multiplexing. Already released R4 material
may permit signature assembly even when a later final-result frame is fenced.

Two process tests additionally cover twelve reservation transitions with both
injected I/O errors and SIGKILL (24 schedules). The competing process has already
loaded the same synthetic RAM entry. Before marker creation, the failed actor
releases no package and the competitor may become the single owner; after creation,
0-byte, 16-byte and complete tombstones all deny further ownership. Retries remain
retired. Sync failures are modeled at explicit checkpoints; these tests do not
simulate storage hardware or prove power-loss durability.

Native process probes and bypass controls compile only into the test binary with
`research-faults`. Reservation checkpoint callbacks are crate-private; production
research callers use no-op callbacks. Public metadata/control frames deliberately
bypass the gate: Hello/boot, readiness, status, failure and closure notifications.
Setup/native/result handoffs are gated; the newer registration also gates wallet
endorsements/commit ACKs. Avoid the broader phrase "each output".

Current validation: 56 runtime tests with `research-faults`, 51 without,
57 distinct runtime tests plus two compile-fail tests (59 total). Clippy in both
modes, release build, formatting, 59 demo signatures and 39 refusals pass.
Evidence is recorded in `results-assurance.json`. The registration and
older benchmark artifacts retain their own source inventories and revisions.
Cryptographic/upstream review, independent review of new registration, real TEE
provisioning/entropy, cross-host authority, hostile rollback/snapshots, recovery
and licensing remain open.

## Immutable public registration implemented

Spike C replaces wallet key generation with deterministic root contributions and
the fixed algebraic conversion `s_A=a/2`, `s_B=-b`, so `2s_A-s_B=a+b`. Ordinary
DKG generally occurs at wallet creation, not per signature. Supplying fresh,
single-use OT/PPRF preprocessing is a separate choice and proof obligation.
Functional compatibility does not establish malicious security of either choice.

C now requires a canonical, jointly endorsed `WalletRecord` before signing.
Each worker binds its possession proof and identity endorsement to the complete
record, durably saves its own prepare journal before releasing that endorsement,
and commits only after verifying both endorsements and its own journal. The driver
requires both commit acknowledgments and caches registration. Signing loads and
verifies the immutable record and requires exact digest/manifest equality before
consuming OT material. The recorded namespace preserves the existing key-ID KDF
and addresses; approved build configuration and all share/derivation versions
are fixed. Config migration and controller authorization remain unimplemented.

Ten registration unit tests plus a real-process competing-candidate regression
cover field/digest binding, valid and invalid proofs, idempotency, conflicting
endorsements, signing substitutions, prepared-only state, partial files, injected
write/sync errors and public storage parsing. The worker suite adds five refusal
scenarios for unregistered wallets, missing/wrong digests, chain-code substitution
and partial records. These refuse before OT consumption; a partial record remains
blocked for the same wallet across replacement. A successful restart reuses the
identical record/endorsements and public key while producing a fresh signature.

Validation: 51 runtime tests with `research-faults`, 49 without, plus two shared
compile-fail tests; 54 distinct tests total. The pooled demo passes 18 baseline
signatures, one registered-wallet restart signature and 23 refusal scenarios.
A/B retain 40 baseline signatures and 16 refusals. See `results-registration.json`
for current source-bound evidence; earlier artifacts retain their recorded revisions.

Authenticated invalid registration proofs retain typed incident attribution.
Invalid signatures and mismatched contexts refuse without accusing a signer;
a proof signed by the local identity freezes configuration without peer blame.

Before production adoption, select the applicable signing theorem and review
contribution proof context/extraction, adaptive contribution selection, independent
root provisioning, deterministic multi-wallet derivation, the constructor's
caller obligations and wallet-independent preprocessing composition. A commitment
phase or stronger proofs are unresolved design questions, not established exploits.
Upstream audit coverage must not be assumed to cover this constructor/ceremony.

Root compromise spans that signer's wallet namespace; sequential exposure of both
unchanged roots can expose aggregate wallet keys. OT freshness does not establish
proactive refresh. Root replacement generally changes addresses; preserving them
during recovery/refresh remains a separate design task. Native signing/OT arithmetic,
parameters, patches and resolved dependency versions remain unchanged. Pooled
control/signing messages changed; both workers must use the same new wrapper.

## Local cross-process authority at 0336e52

The pool/benchmark implementation is frozen at `4d2e21c` for review. The follow-up
adds a local Unix advisory lock held across scope marker checks, reservations,
native queue handoffs and incident publication. A marker for either role stops
both roles. The public direct `incident()` path uses the same lock. Separate
ledger locks serialize retirement writes through sync; lock files remain stable.
Idle workers poll for remote cancellation; each setup/native/result handoff independently locks/checks.

Seven real-process regressions cover duplicate synthetic RAM entries (one winner),
publication versus an in-progress queue handoff, both-role refusal and scope
independence, lock-holder death, durable retirement after death, partial-marker
refusal, idle remote cancellation and lock timeout. The handoff test observes its
actual synthetic queue with positive and deliberate-bypass controls. This is an
authority fixture, not a complete native signing across-process race test. Existing
actual-native R4 queue controls are rerun unchanged.

Validation at `0336e52`: 40 runtime tests with `research-faults`, 38 without, plus the
same two compile-fail tests. The union is 41 runtime tests plus two compile-fail
tests (43 distinct). The ignored child helper is explicitly executed by the seven
parent tests, not counted as an additional test. Evidence is `results-authority.json`.

This closes the check-then-handoff race for cooperating processes sharing one
honest local authority filesystem. Publication waits for an active handoff; output
already queued is released. Failed publication before marker creation cannot fence
other processes. Lock acquisition has a two-second timeout and permanently stops
the affected local gate. Cross-host/replica atomicity, hostile rollback, snapshot
protection, full native cross-process fault schedules and cryptographic review
remain open. The research manifest adds the already-locked `libc 0.2.190` as a
direct dependency; no package version, native patch or OT/VOLE parameter changes.

## Tasks 2–5: research scope at 4d2e21c

2. Canonical setup-input, completed-transcript and consumption contexts, with
   arrival-independent hashing, fixed directional roles, binding substitution
   checks and non-Clone seed ownership.
3. Two-slot RAM pool, signed boot enrollment, fresh idle EndemicOT/PPRF and
   zero-coin exchange, authenticated completion/consumption agreement,
   deterministic shares, fresh combined native signing and independent verification.
4. Ownership races, concurrent refill/reservation cutoff, capacity/expiry,
   cancellation, incidents, timeout/disconnect, replay and worker replacement.
   The process pool suite has 18 verified signatures and 18 refusal scenarios;
   A/B reruns retain 40 baseline signatures and 16 refusal scenarios.
5. A/B/C comparison across three wallets and two paths, three repetitions each,
   with 0/10/50 ms of simulated one-way peer delay: 162 verified signatures,
   matching public pins across all routes. Active-poll timing, separate idle
   setup computation/refill, parent serialization and 100 real pipe round trips
   expose where local overhead and suspended waits occur.

Validation: 33 runtime tests plus two compile-fail tests with `research-faults`;
31 runtime tests plus the same two compile-fail tests without it. The union is
34 distinct runtime tests plus two compile-fail tests. Clippy in both modes,
formatting, release build, bootstrap syntax and production isolation are checked.

Evidence at `4d2e21c`: `results.json` (A/B), `results-pool.json` (C), and
`results-comparison.json` (benchmark). The c33a1e1 evidence is preserved in
`results-lifecycle.json`; original run-03 measurements remain in
`results-baseline.json`. Every current artifact records source hashes and the
locked parameter decision. Run directories, root fixtures, native sources and
build products stay ignored.

### Boundaries recorded at 4d2e21c

C uses canonical **binary hash inputs**; its authenticated transport remains
JSON-over-AEAD/stdio. Exact validated native bodies enter the completed digest;
completion ACKs are outside that digest. Consumption propagates through native
InstanceId, package extra and package final SID into the native signing/MtA
identifiers. This source trace is not cryptographic/upstream sign-off on the
internal challenge transcripts or on wallet-independent single-use composition.

The pool owns real native seeds. Reservations remove ownership before validation
and durably retire IDs; setup IDs are burned before exchange. Exceptions/timeouts
clear the generation, EOF drains both workers, and replacement retries either use
fresh setup or remain blocked by quarantine. Incident failures retain the existing
once-only publication and local release cutoff rules. No pool/package/seed export
or split presigning operation exists in the worker protocol.

Each worker serializes commands; idle refill is scheduled by the trusted driver.
There is no overlapping native signing/refill or transport multiplexing. Thread
races test the shared pool/gate authority, and the earlier actual-native R4 queue
controls still test that gate. They do not establish cross-process release
atomicity. The supervisor's authority, wallet pins and policy receipts are mock
trusted fixtures, not the production Solana/auth service.

Same-process fencing, fsync tombstones and Rust ownership cannot prevent hostile
filesystem rollback or cloned/snapshotted process memory. Native copy-valued seeds
and package byte APIs also require careful restriction in any future production
adapter. Memory erasure, real attestation/provisioning, durable replica authority,
recovery, application licensing and cryptographic/upstream sign-off remain open.
Silence OT/VOLE parameters, patches and dependency lock are unchanged.

## Lifecycle closure at c33a1e1 (historical evidence)

Astra independently closed the three focused lifecycle findings at c33a1e1,
reporting 23 distinct tests, 40 baseline signatures and 16 refusal scenarios.
The following counts and measurements describe that earlier revision.

## Demonstrated behavior

- 22 tests pass with `research-faults`. The R4 regression observes actual output
  queues through EOF, proves both executions reached native R4, and sees no
  affected R4 handoff after cutoff. Positive and deliberate-bypass controls see
  two normal and two prohibited late handoffs respectively.
- 20 tests pass without that feature, including refusal of fault-injection requests.
  There are 23 distinct tests across the two configurations.
- Final optimized run: 36 sequential signatures across three wallets, two paths,
  both routes and complete worker replacement; four concurrent direct signatures.
  Public root/child keys remain stable, and signatures independently verify with
  low-S and checked recovery IDs.
- Sixteen refusal scenarios pass. All four newly reported authenticated setup
  violations persist quarantine and block fresh retries after process replacement,
  including a different wallet, path and migration/direct route.
- Unauthenticated garbage, request disagreement and cancellation do not falsely
  quarantine; fresh attempts after these transient cases succeed.
- Terminal-state tests exercise exit before originator diagnostics, closed pipes
  and reversed peer-abort/originator ordering. A real closed duplex-pipe test
  preserves the structured originator diagnostic and persistence outcome.
- Clippy with warnings denied passes in both feature configurations; formatting,
  optimized build, bootstrap syntax and unchanged production files are checked.

Historical public evidence: `results-lifecycle.json` from run-09. Original run-03 measurements
remain in `results-baseline.json`. Downloaded sources, root fixtures, tombstones
and build products remain ignored. No secret package/OT/zero seed is persisted.

## Failure policy

Every reported worker failure carries phase, kind, authenticated peer identity
when attributable, incident action, whether publication was attempted/confirmed,
and a separate flag for failed abort sending.
Classification uses typed native errors and successful setup authentication;
the supervisor does not infer policy from diagnostic substrings.

| Failure | Phase / attribution | Action | Fresh retry after replacement |
|---|---|---|---|
| Incorrect zero-coin reveal | Direct setup; authenticated sole peer | Quarantine peer/configuration scope | Blocked |
| Truncated base-OT reply or PPRF payload; malformed authenticated setup JSON | Direct setup; authenticated sole peer | Quarantine peer/configuration scope | Blocked; JSON path has typed classification, no dedicated end-to-end JSON fault fixture |
| Native base-OT/PPRF processing failure | Direct setup; authenticated sole peer | Quarantine peer/configuration scope | Blocked |
| Invalid native migration PPRF proof (including simultaneous abort-send failure); authenticated parse, commitment, DLog or polynomial violation | Migration; authenticated sole peer under fixed two-party handler audit | Quarantine peer/configuration scope | Blocked |
| Native signing InvalidMessage, InvalidCommitment, InvalidDigest or AbortProtocolAndBanParty | Signing; authenticated sole peer | Quarantine peer/configuration scope | Blocked |
| Native FailedCheck, K256Error, InvalidPreSign; aggregate/local migration errors | Native phase; no guilty peer identified | Freeze local use of pairing/configuration | Blocked; no peer accusation |
| Bad AEAD/signature, wrong context/session, request disagreement | Setup/signing/admission; no authenticated violation established | Refuse; burn any admitted reservation | New entry/setup permitted |
| Peer abort, missing message, disconnect, closed pipe, cancellation or timeout | Native/transport/control; no cheating established | Burn any admitted reservation; cancel/drain | New entry/setup permitted unless another attempt published an incident |
| Incident write/sync failure | Original attribution retained; persistence separately unconfirmed | Stop the local gate; do not republish the same failure | Refuse while a marker/control error remains; crash persistence unconfirmed |
| Existing incident or duplicate reservation | Control/admission | Refuse, never clear the marker/tombstone | Incident stays blocked; duplicate entry stays retired |

All native variants have exhaustive classification regression coverage. The
end-to-end suite does not separately inject every native variant. Invalid
pre-admission requests do not acquire a reservation; once admitted, all outcomes
leave the acquired tombstone retired.

## Incident and release semantics

Scope binds ordered stable peer identities and the fixed accepted protocol/
dependency configuration. Wallet, path, attempt and boot changes do not reset it.
Configuration changes must eventually be authority-approved; this is currently
a fixed research configuration, not a production approval mechanism.

Within one process, gates are shared for the same authority path and signer role.
Publication locks that gate, stops it before attempting durable fsync, and wakes
active attempts. Every native Sink handoff, including R4 partial-signature
material, runs under the same gate. Local stop survives a persistence error;
the failure reports that durability is unknown/failed. Publication is applied once
inside execute; the outer worker handler reports the classified result without
publishing again. An `incident_attempted` guard prevents accidental reapplication
from changing that evidence.

A marker filename alone is insufficient to confirm persistence. Existing records
must be complete (32 bytes), readable and re-synced with their directory. An
empty, truncated or oversized marker is never silently repaired or upgraded to
confirmed persistence; it still denies admission. A separate explicit publication
can confirm a complete record left by an interrupted prior publication only by
actually repeating both sync operations. Tests inject failures after creation,
writing and sync checkpoints and verify the reported outcomes.

**Cutoff:** ownership handoff to the transport queue under the gate lock. No
new affected handoff is allowed after local publication. Previously queued
material is already considered released, can arrive after cutoff, and cannot
be recalled. The two-attempt regression pauses both native executions just
before R4, publishes through the shared gate, then drains and checks the actual
outgoing queues independently of Wire::send and returned cancellation. No earlier
affected R4 can exist because both were paused before their first handoff. A
positive control signs and observes two handoffs; a test-only deliberate gate
bypass observes two late handoffs and demonstrates the oracle catches the old
false pass. It is a
local synchronization test, not a cryptographic proof or network snapshot test.

Across processes, each setup/native/result handoff checks its scoped filesystem marker, but marker
checking and output handoff are not atomic with remote publication. Cross-process
and cross-replica authority, hostile-host rollback and snapshot protection remain
production blockers. That revision had no long-lived worker/pool; Spike C adds them only as a research harness.

## Supervisor and fault fixtures

The supervisor tracks stdout closure and structured terminal failures separately
from relay writes. Broken pipes are recorded without unwinding the attempt.
EOF cancels blocked input reads while output remains available. It drains both
stdout streams, or a two-second grace, before killing workers. If grace expires,
missing diagnostics and persistence are explicitly unknown. Host crashes can
still interrupt durable publication; this is not a crash-proof incident service.

Upstream research patches are the typed constructor, duplicate participant-ID
comparison fix, preservation of the original migration error when abort sending
fails, and an explicitly feature-gated migration PPRF proof fixture. The wrapper
records abort handoff failure separately; it does not claim network acknowledgment.
The new combined PPRF/abort-send fault persists quarantine and blocks replacement
retries, with both the original violation and send failure visible.
The fixture flips the first tree's proof digest before native encryption; it
does not modify signing arithmetic. Fault injection is off by default.

An intermediate fixture initially changed a tree mask that need not affect the
receiver's selected path, so that test could succeed. It was corrected to mutate
the proof digest; final fault evidence uses the corrected fixture. No security
conclusion is drawn from the intermediate run.

## Measurements and unproven assumptions

Final sequential run has 18 samples per route (slower worker per attempt):

| Route | Median setup | Median signing + verification | Median total process/IPC wall time |
|---|---:|---:|---:|
| Migration | 110.0 ms | 13.4 ms | 140.3 ms |
| Direct | 111.4 ms | 13.3 ms | 140.1 ms |

These intervals combine compute and IPC waits. They are not isolated CPU, network
flight, TEE or cross-region measurements; no latency target is promised.

`POOLING.md` now separates pre-exchange setup inputs, the completed setup digest,
and consumption. It specifies canonical stage/directional ordering, zero-coin
binding and completed-digest acknowledgment. Later OT-extension transcript binding
remains a separate requirement. Retirement and ownership are irreversible. Its tested metadata
scaffold at that revision carried no seeds. Spike C now has separate seed-owning pool types. `extra` and
`final_session_id` bind data; they do not make reuse impossible. Commit/reveal
remains until required seed properties and malicious-party behavior are reviewed.
Root-based entropy hedging is not implemented and would not prevent snapshots.

`SECURITY-REVIEW.md` maps the exact locked code, constants and file hashes, and
expands the zeroization inventory. The full 2026 paper is now available and its access-error explanation is retired.
Per the project decision, the locked Silence parameters are unchanged. Upstream
resolution and confirmation of the exact implementation/audit assumptions remain
open; the paper alone neither demonstrates a concrete attack on this candidate
nor certifies it. Security strength is not inferred from parameter names.
Custom composition security, memory erasure, recovery, real attestation,
authoritative cross-replica controls, rollback protection, application licensing
and independent cryptographic review remain unproven or unfinished gates.

## A/B/C measurements at 4d2e21c (local research)

18 samples per route/delay (three wallets × two paths × three attempts), with
162 verified signatures total. A/B wall includes process launch/registration;
C online wall excludes its separately reported startup and wallet registration.
Each idle refill prepares one matched entry for the two workers.

| Injected one-way peer delay | A wall median | B wall median | C online median | C idle refill median |
|---:|---:|---:|---:|---:|
| 0 ms | 147.0 ms | 190.2 ms | 25.4 ms | 118.8 ms |
| 10 ms | 239.4 ms | 249.6 ms | 79.0 ms | 171.9 ms |
| 50 ms | 653.1 ms | 659.9 ms | 281.7 ms | 375.9 ms |

At zero injected delay, C's active native signing polls take a median 8.7 ms
on the slower worker; setup compute segments take 91.6 ms. Parent refill
serialization takes 2.62 ms. The separate 100-sample two-worker pipe/control
round-trip median is 0.112 ms (parent serialization 0.0010 ms).

Pooling moves setup off the online path; it does not remove the approximately
119 ms refill cost or create sustained throughput from the online number. Idle setup alone
is roughly 8.4 matched entries/second in this serialized harness; signing, wallet registration
and refill share worker time. These medians are one local run, affected by host
load/preemption and timer/framing overhead; no confidence interval, network-flight
count, fixed CPU performance or production latency target is claimed.

An initial disconnect assertion expected one diagnostic string. EOF can instead
arrive during native signing and produce typed `MissingMessage`. The final fixture
accepts typed transport/Burn refusal, requires both retirement markers and complete
drain, and confirms a fresh replacement retry. It never treats a parent timeout as
successful fault handling.
