# Spike C — experimental RAM preprocessing pool

Spike C implements this design for local research, using two long-lived worker
processes and a two-slot RAM pool. Spikes A and B retain per-attempt setup as
comparison baselines. Architecture v0.4 and production dependencies are unchanged.
This demonstrates functional compatibility and lifecycle behavior; the custom
composition is not cryptographically approved or adopted.

`src/pool.rs` defines canonical contexts and ownership; `src/pool_worker.rs`
performs setup/consumption/signing; `src/pool_driver.rs` orchestrates idle refill,
process failures and measurements. No pool entry, OT package, coin or zero seed
is written to disk. Roots, public wallet records/endorsements and public
retirement/incident records persist.

## Wallet key-generation replacement and public registration

Ordinary wallet DKG is a key-creation ceremony, not a per-signature requirement.
Spike C substitutes independent deterministic root contributions `a` and `b`
for native wallet key generation, then uses `s_A=a/2`, `s_B=-b` at coordinates
1 and 2. The identity `2s_A-s_B=a+b` establishes algebraic compatibility only.
Fresh wallet-independent preprocessing is a separate construction with a separate
proof obligation. Absence of ordinary DKG alone does not establish insecurity;
this particular replacement must satisfy the selected signing theorem's assumptions.

`registration::WalletRecord` implements version 1 of a canonical public record.
`describe()` obtains signed contribution proofs for the candidate; the workers
then create separate final-record-bound proofs and endorsements. Registration is
separate from signing and follows this implemented flow:

1. Canonically bind the wallet identifier/namespace, ordered stable signer
   identities, curve, both public contributions, aggregate key, chain code and
   its derivation rule, contribution-KDF version, share-representation version,
   participant IDs/coordinates/ranks/threshold and child-derivation version.
   The namespace identifies the existing key-ID KDF; it does not add a new KDF
   input or change addresses. Controller/recovery-domain authorization is not
   introduced into this experiment.
2. Both workers validate the same candidate and sign a dedicated registration
   endorsement over its full digest. A signature on one party's Hello is not
   an endorsement of the final joint record. The new Schnorr challenge binds the
   entire canonical record digest, role and proof commitment. The identity
   signature binds that digest, role, commitment and response. Proof extraction
   requirements and a possible contribution commitment phase still need review.
3. Commit one immutable record only after both endorsements. The local spike
   rejects conflicting registration and fails closed on partial files across
   restart; it never silently replaces a record. Each worker writes a public
   immutable prepare journal before releasing its endorsement. Retries reuse
   that exact endorsement. Complete valid records are re-synced before a retry
   or load confirms them; incomplete records remain blocked.
   An honest local store is a research authority, not rollback protection.
4. Each worker loads/verifies the committed record, checks its own deterministic
   contribution, and requires signing requests to reference that record digest.
   Signing admission rejects internally consistent request substitutions. Metadata
   versions and chain-code rules are fixed and validated. Tests cover restart,
   conflicting registrations, partial files, injected write/sync failures,
   invalid proofs and request substitutions. No OT entry is consumed before
   successful record admission.

The `Register` command returns an endorsement; `CommitWallet` verifies both
endorsements and the worker's own prepared journal, then returns the committed
digest. Both commit ACKs are required by the driver. These outputs use the incident
release gate. Public files live in `controls/wallets`: one per-role `.prepared`
journal and one joint `.wallet` record per key ID. File creation, checks and syncs
use the stable local authority lock. Existing records require the same approved
build configuration; record/configuration migration is not implemented.
Proof failures establish an incident only after identity authentication. Bad
scalar/commitment/possession checks in an authenticated endorsement quarantine
the identified peer, or freeze configuration if signed by the local identity.
Invalid signatures and wrong contexts do not establish cheating.
Registration initiation and policy remain trusted driver fixtures. There is no
contribution commit-before-reveal ceremony in this version.

Existing Schnorr proofs address knowledge of the advertised contribution under
their applicable assumptions. They do not establish independent root generation,
KDF compliance, or every extraction property a signing theorem may require.
Stronger context binding and commit-before-reveal to constrain adaptive contribution
selection are review questions, not established exploits or a completed security
argument. Upstream/independent review must select and check the applicable model.

## Transient package constructor security contract

The versioned [draft constructor contract](CONSTRUCTOR-SECURITY-CONTRACT.md)
maps existing enforcement and tests to environmental assumptions and open proof
obligations O1–O6. The [draft questions for Silence](SILENCE-REVIEW-QUESTIONS.md)
request the corresponding native input contract and audit evidence. Neither
document changes registration or selects a new ceremony; C1 remains open.

`pairkey_research_two_party` checks nonzero local secret, nonidentity public
points, distinct public shares, local secret/public consistency and
`2S_A-S_B=Q`. It fixes `n=t=2`, party IDs 0/1, coordinates 1/2 and ranks zero.
It stores the supplied key ID, chain code, setup SID, zero seed, OT seeds and
extra data. These checks do not certify remote setup or registration.

The caller is responsible for establishing, subject to cryptographic review:

- An authentic, agreed wallet record and contribution proofs meeting the
  selected signing theorem's assumptions; independent root generation is an
  enrollment/provisioning assumption rather than a scalar check.
- Correct direction/participant mapping and matching cross-party EndemicOT/PPRF
  correlations with the required secrecy, distribution and malicious security.
  Local seed structs alone cannot certify their remote correlations.
- A shared zero seed that yields the native zero-sum masks with the required
  distribution, transcript binding and freshness. The common seed is intentionally
  known to both signers; its required secrecy from other actors and allowed abort
  behavior need explicit analysis.
- Secure use of preprocessing selected before the wallet/message is known,
  later binding to that exact consumption, and fresh private signing randomness.
  Aborts, concurrent reservations and retries must preserve the required properties.
- Single-use ownership, authoritative reservation/incident controls and lifecycle
  isolation. Hashes and retirement records enforce specified local controls;
  they do not prove the cryptographic composition or prevent hostile snapshots.

The worker performs authenticated setup/consumption agreement, immutable public
registration and signing admission, linear ownership and local retirement controls.
The signing request's `wallet_record` digest enters version-2 ConsumptionContext;
unregistered pooled requests refuse. A/B retain their unregistered comparison
flow; metadata-only pool fixtures can exercise version 1, which the pooled worker
does not admit for signing. Other protocol assumptions are not established by
passing signatures. This constructor is a research import interface requiring
upstream review; historical native audit coverage does not automatically apply.

## Consequences of root-only secret persistence

One root compromise exposes that party's deterministic contributions throughout
its wallet namespace. Learning both unchanged roots at different times can expose
the aggregate private keys even if signing packages and OT entries were erased.
Fresh preprocessing does not refresh root-derived signing shares or provide
proactive security against such sequential compromise. Replacing a root generally
changes the public keys. Address-preserving recovery and proactive refresh require
their own design and authority/erasure assumptions; neither is implemented here.

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
   pinned complete wallet-record digest, derivation scheme/path, authorized prehash,
   authorization receipt/policy version, attempt ID)`.
   The record includes the manifest's public key and chain code plus registration
   metadata and approved configuration. Both sides authenticate
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

Local cross-process authority now uses a persistent `.authority.lock` inode in
each scope. A fresh file descriptor acquires an exclusive Unix `flock` for each
operation. Gate callbacks must be synchronous and must not reenter the same
scope/ledger lock. Marker checks, admission/reservation and transport-queue handoffs hold
the scope lock; publication takes that same lock before creating/writing/syncing
its marker. Both role markers stop the pairing. A separate ledger lock serializes
create-new retirement records through file/directory sync. A/B admission now also
reserves under its scope gate. Never delete or replace lock files.

An in-progress handoff may complete before publication acquires the lock. Once a
marker is created under that lock, subsequent handoffs refuse, including when the
marker is incomplete. Queued output remains released and cannot be recalled. A
two-second lock-acquisition timeout fails closed for that local gate; it does not
prove publication to other processes. Idle cancellation polls every 100 ms on a
best-effort basis; output fencing does not depend on that polling interval.

Kernel locks release on process death; retirement/incident records remain. Death
before marker creation, failed lock acquisition or inability to create the marker
does not establish a remote incident cutoff. The local publisher remains stopped
and reports unconfirmed persistence. Advisory locking depends on cooperative code,
one stable authority path/inode and local filesystem semantics. Independent hosts,
replicas, hostile rollback, snapshots and cloned entropy remain outside this bound.

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
cross-host/replica release and reservation controls, rollback/snapshot
protection, recovery, and licensing for the intended use. The locked Silence
parameters remain unchanged, as requested.

`pool-demo` records real pooled signatures, a successful registered-wallet restart,
and 23 refusal scenarios. `compare`
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

## Assurance limits after Astra's reviews

Astra's scoped review of `e9a6220` also covers immutable registration, within
cooperating processes sharing an honest local filesystem. The follow-up tests actual native setup/R4/result targets
in two processes against a third publisher, with queue-observed positive/bypass
controls. Twelve reservation transitions each receive error and process-death
schedules with a preloaded competitor. Reservation fixtures use synthetic seeds;
their purpose is ownership/durability control rather than OT composition security.
Process death and checkpoint-modeled sync failure do not establish power-loss
durability. Root ciphertext storage, hostile rollback and cross-host authority
remain outside this honest-filesystem bound.

Wire gates setup/native/result handoffs and wallet endorsement/commit ACKs. Public
Hello/boot, readiness, status, failure and closure/control frames bypass it.

The newer pooled process suite drives actual C workers through endorsement,
commit ACK, consumption agreement, native R4 and result handoffs. Twenty schedules
include positive/bypass controls and public `incident()` publication by either
role. Independent queue observation remains the release oracle. Thirty-two
registration write/sync interruption schedules and four release/death schedules
check exact recovery of complete records and continued refusal of partial records.
These are not overlapping C attempts or a storage-device/power-loss simulation;
post-reservation construction ownership schedules remain open. See `REVIEW.md`.
Source-bound configurations change with covered wrapper edits. Older immutable
records must not be silently rewritten to fit a new build; upgrade/recovery
requires a separately reviewed migration design.
