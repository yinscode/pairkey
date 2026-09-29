# DKLS23 research review — lifecycle closure and Spike C

Keep DKLS23 experimental. A/B remain baselines; Spike C now uses a small RAM
preprocessing pool in long-lived local workers. Production dependencies and
architecture v0.4 are unchanged. The custom composition has not been adopted.

## Tasks 2–5: implemented research scope

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

Current evidence: `results.json` (A/B), `results-pool.json` (C), and
`results-comparison.json` (benchmark). The c33a1e1 evidence is preserved in
`results-lifecycle.json`; original run-03 measurements remain in
`results-baseline.json`. Every current artifact records source hashes and the
locked parameter decision. Run directories, root fixtures, native sources and
build products stay ignored.

### Boundaries for the next review

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

Across processes, each handoff checks its scoped filesystem marker, but marker
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

## Current A/B/C measurements (local research)

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
