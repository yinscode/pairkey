# Spike D — shared donor base OT, transient wallet packages

Status: experimental implementation on `codex/spike-d`, branched from `silence-dkls23` at `9ec3890`. The user's subsequent correction supersedes the wallet-package cache and native-refresh route in `SPIKE-D-INSTRUCTIONS.md`. Production PairKey and v0.4 are unchanged.

## The corrected flow

1. Each worker loads only its own root and pins the ordered peer identities. Boot uses a fresh authenticated ephemeral channel. Real attestation, provisioning and controller authorization remain outside this local fixture.
2. Register a D wallet using derivation version 2. A wallet binds the ordered pairing, namespace, epoch, wallet identifier and version. Each worker derives its contribution locally. The aggregate key is `(a+b)G`; the native constructor uses `a/2` and `-b` at coordinates 1 and 2.
3. Reserve the wallet identifier durably. Exchange contribution commitments, save the peer commitment, exchange acknowledgments of the ordered commitment pair, then reveal. Both workers validate the openings, aggregate public key and chain code. Each prepares a fresh Schnorr possession proof and identity endorsement of the complete immutable record **before releasing that exact endorsement**. Commit requires both valid endorsements and the locally prepared endorsement. Both acknowledge the same committed digest.
4. Run native two-party DKG for a random **unused donor key**. This is donor establishment, not wallet DKG. Agree its native generation ID and public key. Extract only each worker's own sender OT seed, receiver OT seed and common zero-share seed; drop the donor `Keyshare`, including its signing share. No signature API exposes the donor key, and package construction explicitly refuses the donor public key.
5. Retain that donor material in RAM. Before signing, both workers agree that they have the requested live generation, then agree the signing instance. They irreversibly journal own/peer instances and issue an increasing public counter.
6. Re-derive the wallet contribution and check it against the exact committed public record. Construct a fresh RAM-only wallet package from that contribution, the immutable record and the donor material. Its session context binds record, donor generation and instance. The package is dropped after the attempt; it is never cached or written to disk.
7. Hedge fresh OS entropy with operation, role, request context and counter. The instance binds wallet/record, generation, path, prehash and attempt. Call combined native `sign::run`; the split presign API is unused. An authenticated R1 observer journals each native session ID before queue release/native admission and reconstructs the actual native final session ID. Verify signature, low-S form and recovery before the gated result handoff.
8. Rotate the donor with a **new native DKG**. Native refresh needs signing shares we deliberately discarded. Rotation changes OT generation without changing registered wallet addresses.

The common zero-share seed is also taken from the donor and reused with distinct native signing contexts. This is part of the custom composition under review, not merely an optimization to storage.

## Persistence and crash rules

Persistent secrets are roots only. Public state includes registration records and proofs, commitment/reservation journals, donor generation/retirement markers, incident markers, instance/session replay journals, counter issuance and transport-abort timestamps. Roots are plaintext files only in the co-located research fixture; this does not implement TEE sealing.

The commitment opening (point plus fresh salt) stays private in RAM until reveal. Saving the opening in an ordinary public prepare file before reveal would defeat the intended ordering against a storage observer. A restart with a reserved wallet but no complete prepared record **retires that wallet slot**. The implementation chooses retirement rather than trying to finish an opening it no longer has. Asymmetric preparation refuses. If both parties have the same complete prepared record, they resend exactly the saved endorsements and can finish the same certificate. Incomplete or conflicting files remain refused; they are not overwritten or silently repaired.

Counters use immutable issuance markers plus an atomic head update. Head regression relative to existing markers and interrupted issuance refuse. They do not detect rollback of the entire filesystem. R1 and instance journals enforce replay refusal within the same honest-filesystem boundary.

No donor seed, zero seed, wallet contribution, native package or signing nonce is serialized. Native package dropping and explicit clearing wrappers are exercised structurally; complete physical secret-memory erasure is not established.

## Limits and failure scope

One donor per worker/pair. Attempts are serialized in the worker; separate native tests exercise concurrent transient packages. Defaults and maximums: **100 attempts or 10 minutes (600 seconds), whichever comes first**. Smaller bounds may be configured for tests. Reservation consumes a use before native signing, including unsuccessful attempts; earlier failures discard the entire generation. The 100th successful attempt retires the donor before the result handoff. A monotonic timer disposes idle expired material and cancels an in-flight sign at expiry. Rotation requires fresh donor DKG; public wallet records remain unchanged. Previously queued frames cannot be recalled, and this timer is an operational lifecycle control, not a real-time release theorem. These are **operational hygiene bounds**, not a proven safe number of reuses.

Every command failure discards the donor, including transport failures and context mismatches. A peer must establish a fresh donor generation before a replacement attempt. Persistent transport/peer-abort accounting permits fewer than three such events in a 60-second window; future timestamps refuse clock regression. This uses host clocks in the fixture.

| Returned failure | Action |
| --- | --- |
| Authenticated native peer violation, invalid reveal or authenticated possession proof | Pairing-wide incident/quarantine; all wallet releases fenced |
| Native aggregate failure | Pairing-wide configuration freeze, without sole-peer accusation |
| Generation/context/replay mismatch | Burn attempt and donor; require new DKG |
| Transport/timeout/peer abort | Burn attempt and donor; persistent rate limit |
| Failed incident publication | Local refusal; persistence remains unconfirmed |

Native DKG already preserves the original violation if sending its abort fails. The wrapper records abort-delivery failure separately and retains original attribution. Shared `ReleaseGate` orders **setup/native/result handoffs** against incident publication for cooperating processes on an honest shared local filesystem. Public enrollment and control frames are outside that sensitive-output boundary. Previously queued frames cannot be recalled.

## Security contract and review gates

This corrected D route **still uses the research constructor**. It does not remove package assembly or establish native audit coverage of the new composition. Extraction checks the exact pinned native binary layout and fails on size/metadata mismatch; there is no new native accessor or native protocol patch.

Native DKG establishes correlated donor material. It does not establish that this material is safe to transplant into root-derived wallet packages and reuse across wallets and paths. Review separately:

- deterministic multi-wallet derivation and root compromise scope;
- commit-before-reveal, possession/extraction assumptions and endorsement context;
- constructor obligations and fixed-layout donor extraction;
- repeated donor OT **and zero-share** material under distinct contexts;
- selective-abort, failed-setup and malicious-peer composition;
- revisited OT/VOLE analysis and upstream applicability to the pinned audited parameters.

The choice-XOR negative control shows that reusing base material with the same extension SID exposes choice XOR even while individual checks pass. A different SID removes that particular cancellation; this is not a security proof. The selective-abort regression deliberately reproduces the accepted-branch base-choice leak. Discarding the donor after any failure and freezing authenticated violations are operational defenses, not proof that all adaptive attacks are excluded.

Upstream parameters, dependency versions and existing native patches are unchanged. Cryptographic approval remains open. Also open: hostile-storage/rollback/snapshot protection, cross-host authority, production controllers, real TEE entropy/attestation, power-loss and directory-hierarchy durability, licensing, configuration migration, address-preserving recovery and refresh. D configuration pins source bytes; records are never silently rewritten to accommodate upgrades.

## Reproduction

```sh
bash experiments/silence-dkls23/bootstrap.sh test --locked --offline
bash experiments/silence-dkls23/bootstrap.sh test --locked --offline --features research-faults
bash experiments/silence-dkls23/bootstrap.sh run --release --locked --offline --features research-faults -- d-demo .local/spike-d-soak 1000
bash experiments/silence-dkls23/bootstrap.sh run --release --locked --offline --features research-faults -- d-bench .local/spike-d-latency
bash experiments/silence-dkls23/bootstrap.sh run --release --locked --offline --features research-faults -- d-stress .local/spike-d-bounded-stress 10
bash experiments/silence-dkls23/bootstrap.sh run --release --locked --offline --features research-faults -- d-expiry .local/spike-d-real-expiry
```

Use new ignored fixture directories after source changes; immutable record configuration checks deliberately refuse an older realization. Benchmark reports include public records, signatures and timings only. They exclude secret material.

The stress schedule rotates ten generations across ten wallets and two paths, alternating in-process rotation with worker restart. Both roles must persist retirement after each 100th signature. It probes attempt 101 only after the last batch: deliberately failing every batch makes the driver close both inputs, which produces secondary transport-abort accounting and can legitimately exhaust the unchanged three-events-per-60-seconds limiter. Negative expiry/refusal schedules are kept separate from normal rotation. The real expiry probe waits 602 seconds; the shorter test also delays an in-flight native attempt across a real one-second test age.

Transport deployments must deduplicate exact retransmissions per instance and stage before native admission. The native R1 replay guard currently treats duplicate authenticated frames as a burn; it is not a reliable-network deduplication layer. Public counter/instance/session journals have no safe pruning implementation yet. Never prune them merely because a donor retired. Immutable source-pinned records need an explicit configuration migration design; incomplete/prepared wallet slots require operator-visible diagnosis rather than automatic rewrite.
