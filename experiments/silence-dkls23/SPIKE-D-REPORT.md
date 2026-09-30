# Spike D — donor-route implementation and review report

2026-10-11. Branch `codex/spike-d`, based on `silence-dkls23` at `9ec3890`. Implementation saved in the isolated managed worktree for a branch commit. The original checkout and reviewer-owned documents were left untouched.

## Implemented behavior

The user's correction replaces the brief's cached-wallet migration route. D now runs native DKG for an unused donor key, extracts only the correlated OT/zero-share material and generation metadata, and drops the donor native keyshare. No donor signature is requested. No native wallet package is cached or persisted.

Wallets use pairing/namespace/epoch-bound derivation v2 and immutable commit-before-reveal registration with Schnorr possession proofs and identity endorsements. Public prepared/committed records survive restart. Signing re-derives contributions and builds a transient native package using the existing research constructor. Donor material is reused across wallets within a bounded RAM-only generation; rotation is fresh donor DKG. See [the design and security contract](SPIKE-D-DONOR-DESIGN.md).

Other controls: generation agreement before native signing; irreversible own/peer instance journals; durable counter issuance; hedged fresh seeds; authenticated native R1/session replay guards; actual final-session observation; output/low-S/recovery verification; pairing-wide incident fencing; donor disposal on failure; transport rate accounting.

## Validation at baseline `2d735bd`

The counts, one-generation soak and timings in this section describe the original 1,000/24-hour policy. The current policy is 100/600 seconds; see the follow-up below.

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
3. Reused OT **and zero-share** material across wallets, paths and concurrent native attempts, distinct-session requirements, selective-abort behavior and failure-driven retirement. The current 100/600-second bounds are hygiene, not cryptographic limits.
4. Replay/counter journals, pairing-wide release ordering, asymmetric registration recovery and truthful storage-error handling.

Cryptographic/upstream approval remains open. D worker commands are serialized; concurrent native-package tests do not establish a production multiplexed worker. The adversarial regressions are a focused suite, not an exhaustive malicious-peer analysis. Also open: TEE/entropy/snapshot guarantees, hostile storage, cross-host authority, production controllers, full memory handling, power-loss/directory hierarchy durability, licensing, configuration migration and address-preserving recovery/refresh. More passing lifecycle tests do not close these gates.


## Follow-up: 100 attempts / 600 seconds (2026-10-12)

The current worker enforces the first of **100 reserved native signing attempts or 600 monotonic seconds** per RAM-only donor generation. Lower test bounds are allowed; larger values are refused. The 100th successful attempt disposes and durably retires the donor before handing off its verified result. An idle expiry timer disposes donor material without a new request; an in-flight signing timer cancels at expiry. Failures still discard the donor. These are operational hygiene controls, with no proven cryptographic safe-reuse count. Previously queued frames cannot be recalled.

The completed stress run used **10 batches × 100 signatures**, ten registered wallets, two derivation paths and ten distinct native DKG donor generations. It alternated five in-process rotations with four worker restarts. Both roles' retirement markers were checked after every batch. All 1,000 signatures verified, both roles agreed on each output and use count, and all instance IDs, observed native final-session IDs and aggregate signature `r` values were distinct. All 20 wallet/path public keys remained stable across generations. Distinct aggregate `r` values are an observable regression check; they do not establish secrecy or non-reuse of every internal nonce component.

The actual default-age probe waited **602 seconds**: the old generation refused signing without an incident, fresh DKG produced a new generation, and signing resumed for the same wallet/path address. Separate tests cover strict 99/100 and just-before/at/after-600-second edges, idle disposal at a real one-second test age, and cancellation of a delayed in-flight attempt followed by successful fresh setup.

### Failures and their interpretation

1. The first stress schedule deliberately requested attempt 101 after *every* batch. Four batches / 400 signatures succeeded, then fresh setup was blocked by the persistent three-transport-events-in-60-seconds limit. On the first worker's expected generation/bound refusal, the driver closes both inputs and drops pending delivery; its peer consequently reports a secondary disconnect. Role 0 had accumulated three such disconnect timestamps within the window. This is a reproducible operational interaction between test shutdown and rate accounting, not a failed signature or demonstrated cryptographic leak. The completed throughput schedule rotates normally and performs one explicit attempt-101 refusal at its final boundary. **Rate limits, journals and failure classification were not weakened or reset.** Repeated invalid requests can still cause this rate-limit behavior; production orchestration needs to rotate before submitting stale-generation requests.
2. A new 16-attempt concurrent native observer test exceeded its five-second outer timeout in a full debug suite while builds/tests and the stress run competed for CPU. The isolated optimized version passed. The fixture now uses the existing worker's 30-second native TTL and a bounded 60-second outer wait; native cryptographic parameters are unchanged. The failed log is retained, and the ordinary suite was rerun.
3. Attempt 101 and expired-generation requests deliberately return Burn; a peer disconnect can be a secondary terminal diagnostic under the current driver shutdown. No quarantine was observed from these hygiene schedules. Expiry during an in-flight attempt burns that attempt and its donor; replacement uses fresh DKG.

The stress run's same-host warm median was approximately **124 ms**, and donor DKG median approximately **192 ms**, under concurrent builds/tests. These are diagnostic timings rather than a latency benchmark or TEE/network prediction.

### Additional review evidence in this revision

Cross-wallet process tests publish a pairing incident while one wallet is at native R4, independently observe the queues, then verify a second wallet stays fenced through worker restart; a different pairing remains usable. Registration tests reject changed wallet/role/pairing/epoch commitment contexts, prove one local reservation winner per role, and reject a revealed-then-aborted wallet returning with a fresh commitment. Independent role winners do not imply an atomic global registration winner; disagreement safely refuses or retires.

Six transient-package mutation cases clarify the constructor boundary. Native signing refuses coordinate, aggregate-key and package-session mutations. It still signs the correct original wallet when unused public-share/key-id/extra metadata is changed in a raw package. D's trusted constructor and immutable record checks must establish those fields; native signing alone is not a complete import validator. This fixture directly mutates local packages and is not a reproduced remote D signing bypass.

Native DKG donor generation becomes `Keyshare.final_session_id`. Each transient package session binds the immutable record digest, donor generation and signing instance. Native R1 contributions then determine the actual signing final session, and native directional MtA/zero-mask contexts incorporate the signing transcript. This implementation trace does not prove that donor material can safely be transplanted and reused across root-derived wallets.

The known choice-XOR and accepted-branch selective-abort primitive regressions remain relevant. No new root/share extraction or invalid released signature was demonstrated by these stress/expiry tests. Cryptographic composition review, reliable transport deduplication, snapshot/rollback protection, cross-host authority, power-loss durability and upgrade/recovery design remain open. No Silence request was drafted or sent, as requested.

Evidence is retained under ignored `.local/spike-d-10x100-rotation-20261012/`, `.local/spike-d-600s-expiry-20261012/`, `.local/spike-d-10x100-20261012/` (the first failed schedule), and `.local/spike-d-demo-101-bounded-20261012/`. A source-hashed validation manifest and copied logs are in `.local/spike-d-bounded-review-20261012/`. The primary `silence-dkls23` checkout and reviewer-owned files were not changed.

Final validation: **78 default runtime tests + 2 compile-fail tests**, **109 fault-enabled runtime tests + 2 compile-fail tests**, Clippy in both configurations, formatting, release build and diff checks passed. The existing demo completed 101 samples with automatic rotation at 100 and another verified signature after explicit rotation. Native parameters, dependencies, bootstrap patcher and patch files remain byte-for-byte unchanged from `2d735bd`. This follow-up is recorded on `codex/spike-d`; the validation manifest identifies its source snapshot and baseline.
