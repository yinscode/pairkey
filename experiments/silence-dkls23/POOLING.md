# Proposed RAM preprocessing pool — specification only

No pool is implemented. Spike A (native migration per attempt) and Spike B
(deterministic shares with fresh interactive setup per attempt) remain baselines.
Current setup includes the exact request context, so its material cannot be
precomputed and relabeled. The following composition requires cryptographic
review before code that carries OT material is added.

## Authenticated contexts

`PreprocessingContext = H(domain, ordered stable peer identities, approved
configuration digest, protocol and dependency versions, entry ID, boot/generation
identities, setup provenance/transcript digest)`.

The configuration must commit to curve, sharing coordinates, threshold, OT/PPRF
and VOLE realization/parameters, patched source and wrapper version. Enrollment
and configuration changes require authority approval; a caller cannot choose a
new configuration to evade an incident. Provenance commits to the base-OT and
PPRF transcripts and their domain-separated directional session identifiers.
Wallet ID, root public key, chain code, derivation path, message and signing nonce
are absent. All fields and freshness agreements must be peer authenticated.

`ConsumptionContext = H(domain, PreprocessingContext, entry ID, pinned wallet
manifest digest (including root key and chain code), derivation scheme/path,
exact authorized prehash, authorization receipt/policy version, attempt ID)`.

Both sides authenticate the same consumption context before any signing output.
Native signing instance IDs must bind it. A proposed package final_session_id
would bind preprocessing provenance; `extra` would bind wallet and consumption
metadata and be checked on load. These fields provide binding. They do **not**
make package reuse impossible or enforce authorization. Current native setup IDs
remain request-bound until this separate composition is reviewed.

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
