# Spike C — experimental RAM preprocessing pool

Spike C implements this design for local research, using two long-lived worker
processes and a two-slot RAM pool. Spikes A and B retain per-attempt setup as
comparison baselines. Architecture v0.4 and production dependencies are unchanged.
This demonstrates functional compatibility and lifecycle behavior; the custom
composition is not cryptographically approved or adopted.

`src/pool.rs` defines canonical contexts and ownership; `src/pool_worker.rs`
performs setup/consumption/signing; `src/pool_driver.rs` orchestrates idle refill,
process failures and measurements. No pool entry, OT package, coin or zero seed
is written to disk. Roots and public retirement/incident records persist.

## Setup inputs, completed transcript, and consumption

These are three distinct bindings. The completed transcript is not an input to
session IDs used to generate that transcript.

1. **SetupInputDigest**, known before any exchange:
   `H(setup-input domain, ordered stable peer identities, approved configuration
   digest, protocol/dependency versions, entry ID, boot/generation identities,
   setup recipe/version)`.
   Configuration commits to curve, coordinates, threshold, OT/PPRF and VOLE
   realization/parameters, patched source and wrapper version. Enrollment and
   configuration changes require authority approval. Wallet, root public key,
   chain code, path, message and signing nonce are absent.
2. **CompletedSetupDigest**, computed only after successful authenticated setup:
   `H(completed-setup domain, SetupInputDigest, canonical setup transcript)`.
   Both peers exchange authenticated completed-digest acknowledgments and agree
   on the same digest before an entry can become available. A mismatch, missing
   acknowledgment or ambiguous agreement retires it. These acknowledgments are
   outside the hashed transcript, avoiding another circular dependency.
3. **ConsumptionContext**, known once the exact authorized request is available:
   `H(consumption domain, SetupInputDigest, CompletedSetupDigest, entry ID,
   pinned wallet manifest digest, derivation scheme/path, authorized prehash,
   authorization receipt/policy version, attempt ID)`.
   The manifest includes root public key and chain code. Both sides authenticate
   this same context before any signing output. It binds the native signing
   instance and the later directional OT-extension instances.

Use versioned canonical binary encoding: fixed-width unsigned integers in big
endian, fixed-length IDs/digests/identity keys, and length-prefixed UTF-8 labels
and byte strings. Do not hash ordinary JSON object iteration order. Transcript
records include version, SetupInputDigest, stage, sender and receiver roles,
message type and the exact validated protocol body bytes. Native bodies must
use the pinned encoding, including its fixed representation and length checks.
Transport arrival order, retransmissions and AEAD nonce/framing are excluded.

Canonical stage order is zero-coin commitments (role 0 then 1), zero-coin reveals
(0 then 1), base-OT message 1 (receiver 0 then receiver 1), and base-OT message 2
plus PPRF payload (sender 0 then sender 1). Every expected record appears once.
Conflicting duplicates or missing/invalid records refuse; reordering does not
change the canonical digest. Spike C implements this ordering. Each record has fixed stage/type and emitter/recipient roles; base-OT msg1 is emitted by the receiver.
All duplicate records are refused; there is no retransmission layer. Baseline wire bodies remain unchanged.

Directional base-OT SID:
`H(base-OT domain, SetupInputDigest, receiver role, sender role)`.
Directional PPRF SID:
`H(PPRF domain, SetupInputDigest, sender role, receiver role)`.
Zero-coin commitment:
`H(zero-commit domain, SetupInputDigest, contributor role, fresh coin)`.
Both commitments must arrive before either reveal. Reveal messages bind the
same input digest and contributor role, and must open the recorded commitment.
The common zero seed binds a separate domain, SetupInputDigest and the ordered
revealed coins. This depends only on already-known inputs, not the completed
transcript. Coin records are included in CompletedSetupDigest afterward.

Spike C maps the agreed ConsumptionContext digest to native signing InstanceId
and package `extra_data`. Package `final_session_id` is
`H(package domain, CompletedSetupDigest, ConsumptionContext digest)`. The native
`dsg.rs` combines that package SID with fresh R1 session contributions to produce
its signing final SID, then includes sender/receiver IDs in its directional MtA
SIDs. This propagates consumption into the existing native extension instance
identifiers without changing its arithmetic or OT/VOLE parameters. Package key ID,
chain code, weighted public shares and local secret mapping are also validated.
These identifiers bind data; they do **not** enforce single use or policy.

**Later OT-extension transcript binding is separate.** CompletedSetupDigest covers
base OT/PPRF setup, not future signing/VOLE messages. Each extension needs a
consumption-bound instance with sender/receiver roles, and its concrete native
challenge/Fiat-Shamir transcripts must have the required binding to the actual
OT-extension messages. Wrapping a setup digest in `extra`, signing outer frames,
or naming an extension SID does not establish that the internal challenge
construction has this property. The exact internal challenge/message binding remains an upstream/composition review
question; source-level SID propagation and successful signatures are not a proof.
No native OT-extension algorithm or parameters are changed here.

## Ownership and retirement

1. Finish authenticated, fresh setup; create a non-Clone `AvailableEntry` owning
   its seeds. No signing nonce/presignature is generated.
2. `reserve(self, consumption)` consumes availability, commits an irreversible
   tombstone in the authority, and returns a non-Clone `ReservedEntry`.
3. Exchange authenticated reservation agreement. Different entry IDs, provenance,
   wallets or consumption contexts refuse. Uncertain peer agreement burns.
4. `consume(self)` moves seeds into exactly one transient native package. Do not
   expose reusable seed references, Clone, serialization or an unreserve API.
5. Completion, cancellation, failure and dropped ownership clear material and
   leave the tombstone. Retry uses a new entry. Restart discards the RAM pool;
   tombstones remain. A pairing/configuration incident invalidates active attempts
   and all unused/reserved entries in its scope before further output handoff.

`pool::AvailableEntry` owns clearing wrappers around native sender/receiver seeds
and the common zero seed. `RamPool::reserve` removes an entry before any fallible
binding check, persists its public consumption tombstone under the release gate,
and moves it into `pool::ReservedEntry`. A mismatch or dropped reservation burns
ownership. `into_package(self)` checks the gate, expiry and request binding and
moves material into one transient native package; compile-fail tests prohibit
cloning entries or consuming a reservation twice. Seeds remain copy-valued in
upstream APIs, so these types do not prove complete erasure or prevent malicious
new code from copying native package bytes. The worker protocol has no package,
seed export or presign/finish operation. It calls combined `sign::run` only.

Setup IDs are separately retired **before** exchange, preventing repeated setup
under one ID. Available entries expire after 300 seconds. The pool has two slots;
a generation admits at most 1,024 IDs. A miss refuses immediately, without hidden
synchronous refill. The trusted driver schedules refill while idle, before the
next wallet/message is selected. Refill and native signing are serialized per
worker; overlapping signing/refill and transport multiplexing are not implemented.

Every command failure clears unused entries and ends that worker generation. The
supervisor closes the other worker's input, drains both terminal streams and
discards the pair; retry requires replacement workers and fresh setup. Incidents
also stop the shared release gate, fence reserved packages, and block replacements
across wallets, paths and routes. C uses the existing conservative A/B incident
scope, so changing the pool recipe cannot bypass an earlier quarantine. Public
setup/consumption records live in `controls/pool-setups` and `controls/entries`.
Enrollment/configuration approval and policy receipts are trusted local fixtures.

`lifecycle::ReservedEntry` remains the older metadata-only specification scaffold;
the actual seed-owning implementation is `pool::ReservedEntry`. Ownership tests
cover races, binding substitution, capacity, expiry, cancellation and restart;
the process suite exercises authenticated faults, timeout/disconnect, repeated
setup/consumption, incidents and replacement retries. Rust ownership and public
filesystem tombstones do not resist hostile snapshots, cloning or rollback.

## Seed and randomness requirements

Retain the baseline zero-coin commit/reveal for now. Each side contributes fresh
32-byte private hardware/OS entropy; commitments bind context and role before
reveal; the ordered contributions and context feed a domain-separated hash.
The common seed is known to both peers and hidden from the relay by AEAD. Its
security depends on commitments, hash assumptions and one honest fresh source.
A malicious peer can abort selectively after learning the reveal; successful
transcripts are not asserted to have an unconditional unbiased distribution.
Fresh base OT and per-signature randomness remain separate and private.

Native unilateral zero-share seed generation is evidence about its ceremony,
not a proof that replacing this exchange preserves the proposed composition.
Before removing/batching commitment rounds, define required seed distribution,
who must not learn it, freshness, ordering and allowed malicious abort behavior,
then show the replacement meets those conditions.

Root-based entropy hedging is not implemented. Any future hedge must separate
scheme, role, setup/signing purpose, approved configuration and attempt context;
tests must hold OS entropy constant and verify the intended separation and
explicit refusal on repeated contexts. A hedge cannot protect a snapshot that
clones roots, entropy, attempt IDs and authority state together.

## Gates and measurements

The pool is experimental only. Production adoption still requires independent
cryptographic/upstream sign-off, real attestation/provisioning, authoritative
cross-process/replica release and reservation controls, rollback/snapshot
protection, recovery, and licensing for the intended use. The locked Silence
parameters remain unchanged, as requested.

`pool-demo` records real pooled signatures and 18 refusal scenarios. `compare`
compares A/B/C across three wallets and two paths at 0, 10 and 50 ms of injected
one-way peer delay. Delayed deliveries are scheduled independently in each
direction; library subscriptions and registration/policy RPCs are undelayed.
Active-future poll timers exclude suspended awaits, but include synchronous
crypto, framing, filesystem calls and OS preemption. Separate setup timers omit
exchange awaits; parent framing CPU and a 100-sample pipe/control round-trip
probe are also reported. These are local measurements, not a CPU profiler,
network-flight proof, TEE/geographic benchmark or production latency promise.

C online wall time excludes its separately measured startup and wallet
registration. Refill wall time and sequential entries/second are reported
separately; keeping two entries ready moves setup off the online path but does
not remove its sustained throughput cost. See `results-pool.json`,
`results-comparison.json` and `REVIEW.md` for reproducible evidence and limits.
