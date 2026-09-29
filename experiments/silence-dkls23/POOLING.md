# Proposed RAM preprocessing pool — specification only

No pool is implemented. Spike A (native migration per attempt) and Spike B
(deterministic shares with fresh interactive setup per attempt) remain baselines.
Current setup includes the exact request context, so its material cannot be
precomputed and relabeled. The following composition requires cryptographic
review before code that carries OT material is added.

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
change the canonical digest. This ordering is a proposed pool specification;
current baseline wire bodies remain unchanged.

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

A proposed package final_session_id would bind completed setup provenance;
`extra` would bind wallet and consumption metadata and be checked on load.
These fields provide binding; they do **not** prevent reuse or enforce policy.
Mapping these proposed identifiers to the native package/extension semantics
requires composition review. Current setup remains request-bound.

**Later OT-extension transcript binding is separate.** CompletedSetupDigest covers
base OT/PPRF setup, not future signing/VOLE messages. Each extension needs a
consumption-bound instance with sender/receiver roles, and its concrete native
challenge/Fiat-Shamir transcripts must have the required binding to the actual
OT-extension messages. Wrapping a setup digest in `extra`, signing outer frames,
or naming an extension SID does not establish that the internal challenge
construction has this property. This remains an upstream/composition review
question; no native OT-extension algorithm or parameters are changed here.

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

`lifecycle::ReservedEntry` is a public-metadata specification scaffold with tests
for ownership, substitution, cancellation and restart retirement. It contains
**no OT material**, does not authenticate the contexts, and is not a pool.
Compiler or process snapshots can clone ownership despite Rust types. Rewinding
public tombstones also permits reuse. Neither boundary is solved here.

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

No pool adoption until attributable failure handling, scoped cancellation,
partial-output fencing, authoritative controls and the exact OT/VOLE security
mapping are independently reviewed. After that, measure compute in isolation,
serialization and IPC separately, refill throughput and empty-pool behavior,
then injected RTT and realistic transport/TEE measurements. Current wall/setup/
signing timings combine computation and IPC waits; wire message counts include
subscriptions. They establish neither network flights nor a latency target.
