# Spike D — donor-route implementation and review report

2026-10-11. Branch `codex/spike-d`, based on `silence-dkls23` at `9ec3890`. Implementation saved in the isolated managed worktree for a branch commit. The original checkout and reviewer-owned documents were left untouched.

## Implemented behavior

The user's correction replaces the brief's cached-wallet migration route. D now runs native DKG for an unused donor key, extracts only the correlated OT/zero-share material and generation metadata, and drops the donor native keyshare. No donor signature is requested. No native wallet package is cached or persisted.

Wallets use pairing/namespace/epoch-bound derivation v2 and immutable commit-before-reveal registration with Schnorr possession proofs and identity endorsements. Public prepared/committed records survive restart. Signing re-derives contributions and builds a transient native package using the existing research constructor. Donor material is reused across wallets within a bounded RAM-only generation; rotation is fresh donor DKG. See [the design and security contract](SPIKE-D-DONOR-DESIGN.md).

Other controls: generation agreement before native signing; irreversible own/peer instance journals; durable counter issuance; hedged fresh seeds; authenticated native R1/session replay guards; actual final-session observation; output/low-S/recovery verification; pairing-wide incident fencing; donor disposal on failure; transport rate accounting.

## Validation

- Ordinary full suite: **73 runtime tests and 2 compile-fail tests passed**.
- Full fault-enabled release suite: **101 runtime tests and 2 compile-fail tests passed**.
- **21 new runtime tests**, including donor material reuse across eight concurrent native wallet attempts, multi-wallet/path signing, use/age bounds, rotation/restart, instance/native-seed replay refusal, repeated-entropy hedging, proof binding, donor PPRF/abort-send preservation, authenticated native R1 commitment tampering, aggregate zero-seed failure and truthful retirement errors.
- **48 injected write/sync checkpoint errors**, separately **48 SIGKILL checkpoint schedules**, and **24 one-sided registration death schedules**. These exercise process/software behavior, not storage-device failure or power loss. Incomplete public records remain refused; complete recovery reuses exact saved endorsements.
- **18 actual-native donor-route handoff schedules**: setup, R4 and result; publication by either role; positive/protected/deliberate-bypass modes. Independent stdio queue observations see both positive/bypass targets and zero protected targets after cutoff. Fixture stdin is explicitly closed before awaiting child completion.
- **1,000 signatures across three wallets and two paths in one donor generation**, with deliberately repeated entropy input but different context/counter; all instance IDs, observed native final session IDs and aggregate signature `r` values distinct. Another signature after fresh-DKG rotation verifies the unchanged wallet address. This does not establish an individual-nonce or OT composition theorem.
- Choice-XOR negative/positive controls and the 64-trial selective-abort regression reproduce the known primitive behavior.
- Clippy with `-D warnings` passed in both configurations; formatting, release build and diff checks passed.
- Native parameters, `Cargo.toml`, lockfile, bootstrap patcher and native patch files match `9ec3890` exactly.

A wrapper shortcut that matched the text “already reserved” was removed: that text also wrapped unavailable-ledger errors. Donor disposal still clears RAM material, but incomplete retirement markers and storage failures now return failure instead of reporting successful retirement. The regression injects an empty existing marker and verifies continued refusal without modifying it.

## Local latency measurements

Release build, two child workers, fresh fixture directories, measured after the test suites/soak. Delay is applied to each peer-directed native/setup frame. Five warm attempts per row; these are small fixture samples, not production SLOs. Signing includes two authenticated context exchanges before four native rounds and local public-journal operations.

| One-way delay | Registration | Donor DKG | Warm signing median | Fresh donor rotation | Registration + donor + first signature |
| --- | --- | --- | --- | --- | --- |
| 0 ms | 95.3 ms | 134.1 ms | 77.1 ms | 165.8 ms | 300.6 ms |
| 50 ms | 363.4 ms | 470.2 ms | 384.4 ms | 479.7 ms | 1222.3 ms |

The 1,000-signature soak median was **80.4 ms**. No secret material is in the evidence. Complete measurement rows retain public signatures, native final-session IDs, byte/frame counts and parent framing time.

## Evidence and review priorities

Ignored local evidence: `.local/spike-d-review/manifest.json`, logs, source hashes, `soak.json` and `latency.json`. Reproduce commands are in the design note. The original native fixture tests remain part of both full suites.

Review independently:

1. Root derivation v2 and the commit/reveal/proof ceremony, including adaptive contribution selection and extraction assumptions.
2. The donor extraction/layout and transient-constructor contract. Native DKG origin does not extend audit coverage to the splice.
3. Reused OT **and zero-share** material across wallets, paths and concurrent native attempts, distinct-session requirements, selective-abort behavior and failure-driven retirement. The 1,000/24-hour bounds are hygiene, not cryptographic limits.
4. Replay/counter journals, pairing-wide release ordering, asymmetric registration recovery and truthful storage-error handling.

Cryptographic/upstream approval remains open. D worker commands are serialized; concurrent native-package tests do not establish a production multiplexed worker. The adversarial regressions are a focused suite, not an exhaustive malicious-peer analysis. Also open: TEE/entropy/snapshot guarantees, hostile storage, cross-host authority, production controllers, full memory handling, power-loss/directory hierarchy durability, licensing, configuration migration and address-preserving recovery/refresh. More passing lifecycle tests do not close these gates.
