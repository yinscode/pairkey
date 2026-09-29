# DKLS23 lifecycle revision — October 10, 2026

Keep DKLS23 experimental. Spike A (native migration on every attempt) and Spike B
(deterministic shares with fresh OT/PPRF) remain comparison baselines. No pooling
or production integration was added; architecture v0.4 is unchanged.

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

Current public evidence: `results.json` from run-09. Original run-03 measurements
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
production blockers. No long-lived worker or pool was adopted.

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
scaffold carries no seeds and is not an implemented pool. `extra` and
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
