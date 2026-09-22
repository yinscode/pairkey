# PairKey MVP Specification

**Replaceable Hyperliquid agent keys governed by Solana sessions**

Updated October 10, 2026. Status: implementation specification with explicit dependency and deployment gates.

The MVP demonstrates one complete flow: an owner grants a session on Solana, an agent submits a restricted Hyperliquid operation, and two independently authenticated TEE workers produce its native ECDSA signature. The owner keeps the Hyperliquid master key. PairKey controls a replaceable agent credential using cryptographic 2-of-2 signing.

[PairKey Architecture v0.4](architecture-v0.4.md) remains the reference architecture for persistent accounts, recovery, refresh, additional authorization modes, and additional chains. This specification defines the smaller initial implementation. Its omissions are scope decisions, not removals from the reference architecture.

## Outcome and scope

The first end-to-end acceptance result is a threshold-signed order accepted on Hyperliquid testnet after both workers verify the same finalized Session PDA. A cancellation must also succeed. Negative cases must show that either honest worker can refuse an unauthorized request despite a malicious coordinator or peer.

| Included | Deferred |
|---|---|
| Two-party secp256k1 DKG and fresh signing | Recovery authority C and both recovery constructions |
| Library supported public account derivation | Address-preserving share refresh and migration |
| Root creation and one-time activation | Persistent keys controlling master-account authority |
| Finalized Solana Session PDA | SIMULATE and generic exact-operation approvals |
| Owner and delegate signature authentication | Passkeys, OAuth, and consumer onboarding |
| Default-deny Hyperliquid action adapter | Generic EVM, Bitcoin, and Solana FROST |
| Encrypted external packages and restart | Required multi-store replication |
| Freshness, freeze, and revocation handling | Cumulative budgets, reservations, and position accounting |
| Client-returned signing receipts | Append-only receipt service and Solana anchoring |
| Replacement keys on loss or image upgrade | Existing-share release to upgraded worker code |

The MVP does not claim a cumulative spend limit, a maximum trading loss, instantaneous revocation, proactive security, or automatic rollback protection. An agent that cannot withdraw can still cause trading losses.

## Key class and account boundary

Each root serves one owner, one Hyperliquid network, one destination account configuration, and one agent registration generation. The agent uses a fixed non-hardened derivation path, initially `m/0`, supported by the selected backend. The path is recorded on-chain and clients cannot select another path during signing. A new agent registration generation gets a new root and address.

The owner retains control of Hyperliquid agent approval and revocation. PairKey never receives or reconstructs the master private key and does not sign master-account approval, withdrawal, or transfer operations.

The preferred beta boundary is a dedicated Hyperliquid master account funded only with capital deliberately allocated to the strategy. A sub-account configuration is also possible after eligibility and margin semantics are verified. In that configuration both workers require the exact configured `vaultAddress` and reject master-account or other sub-account requests.

Pinning `vaultAddress` is a PairKey adapter restriction. Hyperliquid documents API wallets approved by a master as signing for that master or its sub-accounts. If the complete credential or both signing domains are compromised, the destination may accept actions outside the pinned sub-account. Native credential scope must be demonstrated before claiming destination-enforced isolation. [Hyperliquid API-wallet model](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets)

Funding, owner top-ups, account mode, margin isolation, and other authorized signers affect the capital boundary. No automatic top-up or cross-account transfer is part of the MVP.

## System structure

```text
Owner client                    Agent client
  Solana controller key           Delegate key
  Hyperliquid master key          Structured action request
         |                              |
         v                              v
    PairRegistry                 Coordinator and relay
    root and session                    |
    configuration          +------------+------------+
                           |                         |
                           v                         v
                       Worker A <---- MPC ----> Worker B
                       own KMS                 own KMS
                       own RPC set             own RPC set
                       own package             own package
                           |                         |
                           +------------+------------+
                                        |
                             Signature and receipts
                                        |
                              Hyperliquid exchange API
```

The coordinator is untrusted for authorization and cryptographic inputs. It can delay, drop, reorder, replay, or censor messages. Each worker authenticates the entire client request and constructs its own destination signing payload. Peer messages are authenticated, confidential where required, and bound to a unique protocol instance.

The core contains authorization logic, canonical operation parsing, and protocol state transitions. It has no direct filesystem, RPC, KMS, or network access. It receives explicit observations and cryptographic inputs through adapters and emits commands and outputs. A cryptographic protocol driven by fresh entropy is not assumed to be deterministic.

## Cryptographic backend boundary

PairKey depends on a `ThresholdEcdsa` interface, not on DKLS23-specific package layout or round count.

| Interface operation | Contract |
|---|---|
| Start DKG | Create a two-party protocol instance bound to the root request, participants, suite, and fresh entropy |
| Derive public account | Derive the configured account public key from the root public key, chain code, and fixed path |
| Start fresh signing | Bind exact digest, root, path, participant set, and attempt context; use independent fresh entropy |
| Drive protocol messages | Validate typed messages and emit authenticated transport commands through a state machine |
| Encode and decode package | Preserve required long-term secrets and metadata; support bounded, validated decoding |
| Verify signature | Check against the expected derived public key; produce the destination's required ECDSA representation |
| Classify failure | Distinguish transport interruption, configuration rejection, and cryptographic inconsistency where supported |

This is an interface contract rather than a final Rust ABI. The implementation note for the selected backend must define package format, entropy requirements, auxiliary setup, supported derivation, protocol concurrency, signature normalization, and audit coverage.

Only complete fresh signing is exposed to application callers. Split presignature APIs, key export, singleton import, and secret reconstruction are inaccessible through the service. Temporary presigning inside a complete call is allowed; its transaction-specific state is never persisted or reused.

### Backend selection gate

| Candidate | Licensing position | Evaluation requirement |
|---|---|---|
| Silence Laboratories DKLS23 | Non-commercial public license; commercial terms required for this intended product | Exact derivation, signing, package, and dependency audit coverage |
| LFDT-Lockness CGGMP24 implementation | Apache-2.0 or MIT | Audit revision, auxiliary setup, full signing latency, and timing-attack assumptions |
| 0xCarbon DKLs23 | Apache-2.0 or MIT | Independent security assessment and exact supported features |

The Silence Laboratories license includes internal commercial applications; licensing must be resolved before adopting it for a commercially intended prototype. [License](https://github.com/silence-laboratories/dkls23/blob/main/LICENSE)

The LFDT-Lockness README advertises compatible public derivation, full signing, and an audit, while listing refresh and identifiable abort as unsupported. It also explicitly excludes timing attacks and intentionally uses operations that are not constant-time. Those assumptions require assessment for PairKey's hostile-host TEE model. [LFDT-Lockness implementation](https://github.com/LFDT-Lockness/cggmp21)

The 0xCarbon repository lists permissive licenses; an algorithm name or license is not evidence that the selected code revision is production reviewed. [0xCarbon repository](https://github.com/0xCarbon/DKLs23)

Phase 0 selects and pins a backend revision, dependencies, compiler, parameters, and enabled features. Performance, security assumptions, and licensing are recorded in its implementation note. Recovery support is not an MVP selection requirement.

## Registry accounts

The MVP uses root, session, and enclave-set accounts. It does not introduce a separate WalletRecord. Field lists below specify semantics, not a serialized ABI.

### EnclaveSet account

An enclave set records the registry and deployment generation, participant roles A and B, their approved measurements and hardware identities, registered identity public keys, attestation-verification policy, activation timelock, and active or retired status.

Attestation is verified off-chain under a documented verifier and registration authority. The registry validates enrolled identity signatures rather than directly parsing hardware quotes. The registration process must establish that each identity key belongs to the specified domain and measurement. A self-signed measurement claim is insufficient.

Identity keys are deterministically provisioned or derived under exact-image KMS rules, separately from signing roots. Fresh instance channel keys are bound to hardware attestation and proved by possession. Replicas may share a domain identity; that does not make them additional threshold participants.

Mock measurements and test trust roots cannot be enrolled in production. The enclave-set governance authority, its timelock, and the registry program's own upgrade authority are explicit trust dependencies.

### Root account

The owner creates a request PDA. Its address is the root ID, with a controller nonce preventing reuse across root generations. The request binds the controller, Hyperliquid network, master address, optional sub-account address, agent generation, fixed account path, selected enclave set, and backend suite.

Activation adds the root public key, public chain code, derived agent public key and address, package digests for A and B, creation attempt ID, and readiness signatures. The activation transaction is permitted exactly once and requires both enrolled participant signatures and owner authorization over the resulting commitments.

Key fields are immutable after activation. Lifecycle controls may freeze or retire the root and advance a control version. Replacement creates a new request PDA; there is no share epoch, refresh operation, or recovery-mode selector in this MVP.

The chain code itself is public on-chain metadata, so clients can independently derive the agent address. The registry validates bounded encoding and signature authority; attested workers and the verifying owner client establish the cryptographic consistency of the activated fields.

### Session account

A Session PDA references one active root and binds:

- The controller and delegate public key.
- Hyperliquid network and exact destination account configuration inherited from the root.
- Allowed actions and numeric asset identifiers with their fixed-point interpretation.
- Per-action size, price, submitted-notional, and batch bounds where configured.
- Creation control version, expiry slot, and revocation status.
- Adapter version and policy schema version.

Only the configured controller can grant or revoke a session. Authority comes from the Session PDA; no separately dual-signed capability token is required. A grant is usable only while its creation control version matches the active root control version. Freeze, retirement, and owner-authorized resumption therefore invalidate old sessions and require fresh grants where signing resumes.

These are stateless restrictions per request. Repeating different valid operations can exceed any informal cumulative target. Session fields must not be labelled as cumulative budgets or total-loss guarantees.

## Creation and activation

1. The owner submits the root request on Solana and waits for finalization.
2. Both workers independently verify the request, enclave-set approval, controller binding, and current control state.
3. Both agree on a fresh creation attempt bound to the request PDA and participant identities, then run two-party DKG.
4. Each computes the fixed derived agent address and checks agreement on public root material, chain code, account path, and destination configuration.
5. Each encrypts and uploads its complete long-term package, then reads it back, decrypts it, and verifies it against the agreed configuration.
6. Each signs the same activation commitment, including both package digests and the creation attempt ID.
7. The owner client verifies both domain identities, independently derives the address from the proposed public root material, and authorizes activation. The registry activates the root once in a single transaction.
8. After finalization, the owner client re-reads the root and independently derives the agent address again before requesting the Hyperliquid master wallet to sign `approveAgent`. The approval must match the intended network, master account, root, and registration generation shown to the owner.
9. The owner verifies destination approval, creates the Session PDA, and grants the delegate its public references.

An unsuccessful attempt leaves inactive orphan blobs. A retry uses a fresh creation attempt and entropy. Competing activation attempts cannot overwrite an active root. Root/session references supplied by the coordinator are revalidated by each worker.

Binding a Solana controller to a Hyperliquid master is a client and registration responsibility, not an inference from matching addresses. The owner must verify the full mapping; destination approval is performed by the independently held master key.

## Package envelope and restart

Persist each complete backend package as an encrypted envelope in an external blob store. One store is sufficient for the MVP's declared availability policy; durable multi-store replication is deferred. Losing either package permanently prevents signing under that agent root and requires replacement and re-approval.

The proposed envelope uses an AEAD key derived with unambiguous domain separation:

```text
K_pkg = HKDF(image_bound_seal_secret,
             Encode("pairkey-mvp-package", envelope_version,
                    root_id, side, backend_suite, creation_attempt_id))

AAD = Encode(registry_identity, root_id, side, enclave_set,
             backend_suite, root_public_key, chain_code,
             fixed_account_path, creation_attempt_id)

package_digest = SHA256(canonical_encrypted_envelope)
```

Each encryption uses a fresh AEAD nonce. Adding an attempt ID separates keys across preparations but does not replace nonce discipline. Package decoding verifies the backend version, root binding, participant role, and all public configuration.

At boot, a worker obtains its exact-image sealing secret, authenticates its peer, establishes freshness, and loads packages lazily. It verifies a package digest against the active root account before decrypting. It holds decrypted packages only in memory. Long-term backend auxiliary secrets remain inside the encrypted package; transaction-specific state is never written to disk.

Untrusted storage can delete or withhold an envelope but cannot cause honest workers to accept another root's package. Logs, swap, dumps, diagnostics, and local persistence must not expose production secrets.

## Signing and adapter policy

The delegate signs a canonical request covering registry identity, root and session references, adapter version, the complete structured action, destination nonce, destination expiry, and a request identifier. The service accepts neither arbitrary client digests nor arbitrary exchange payloads.

The initial action allowlist contains simple limit-order batches and cancellations by supported identifiers. Supported time-in-force and grouping values are frozen in the adapter schema. Transfers, withdrawals, agent approval, leverage changes, account-mode changes, builder fees, and unknown action fields are rejected. Scheduled cancellation can be added through an explicitly reviewed allowlist entry before beta; it is not enabled by accepting arbitrary action types.

Use bounded fixed-point parsing with checked arithmetic. Reject malformed decimals, duplicate object keys, unsupported grouping, ambiguous fields, and oversized batches. The owner pins asset identifiers and their encoding metadata when granting the session; client market names do not override those identifiers.

The submitted price multiplied by size is an input notional check, not a guarantee of realized notional, exposure, or loss. Static size and price bounds do not require a live oracle. Dynamic price bands, positions, leverage accounting, and aggregate order budgets are deferred.

For each request both workers:

1. Verify delegate possession and request encoding.
2. Establish a sufficiently fresh registry view; verify root activation, enclave-set membership, session scope, expiry, and negative control signals.
3. Enforce exact network and destination-account binding. For a sub-account, require the pinned non-null `vaultAddress`; for direct master trading, require the configured null value.
4. Independently build the Hyperliquid signing payload and digest using the adapter's frozen encoding rules.
5. Agree on root, package identities, account path, session/control version, payload digest, and a fresh cryptographic attempt ID.
6. Run complete threshold signing with fresh independent entropy in each worker.
7. Recheck authorization if its freshness deadline expires before final signature contribution; abort when negative state is observed.
8. Verify the native signature against the derived agent key and return it with receipts.

The adapter is checked against the official SDK's action encoding, including network separation, field ordering, nonce, expiry, and account binding. [Hyperliquid signing documentation](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing)

Destination nonces are part of the authenticated request. The delegate SDK allocates them uniquely for its agent identity; multi-process delegates need their own nonce allocation discipline. The signers validate the permitted timestamp window and never silently replace a nonce. A collision may cause rejection at Hyperliquid; it must not weaken authorization.

Short `expiresAfter` values are required where the enabled action supports them. The adapter rejects missing or excessive expiry under the deployment's maximum signature lifetime and timestamp uncertainty bounds; it does not rely on an SDK default. Expiry prevents late submission, not later fills of an order already accepted. An order's validity and cancellation semantics remain Hyperliquid's responsibility.

## Freshness rule and clock assumptions

The MVP can use Solana observations plus a validated enclave monotonic timer without a separate time service, under an explicit provider trust model. At least one required agreeing provider per domain must be honest, currently synchronized, and serving correct account state. Provider TLS terminates inside the enclave. A and B use separately configured provider sets; two independent providers per side is the initial minimum.

All required providers participate in the acceptance rule. Choosing an agreeing subset cannot silently discard the assumed honest provider. Provider replacement is a governed configuration change. This is a trusted-state model, not a chain-state proof.

The worker uses the following rule:

1. At bootstrap, obtain live finalized observations from every required provider within the request deadline. Establish the latest reported finalized lower bound `F` and matching root/session contents at contexts at least `F`.
2. Obtain that context's block-time estimate through the required providers and wait for an observed finalized-slot advance before enabling signing. Bootstrap still relies on the assumption that a required provider is current; progress alone cannot authenticate historical state.
3. Track finalized progress and accepted observations using the validated monotonic timer. Repeated observations of the same slot do not reset the no-progress deadline.
4. Before signing, refresh when the observation cache expires. Require context lower bounds, consistent relevant account contents, bounded request delay, and bounded peer slot skew. Reject conflicting positive authority.
5. Stop signing when any required provider is unavailable, observations disagree, finalized progress exceeds the no-progress bound, or clock validity cannot be established.

Different response slots are permitted when the relevant records agree. `minContextSlot` establishes a lower bound rather than an exact snapshot. A malicious provider reporting an excessively high slot can stall this rule. False-state acceptance remains possible if the required provider trust assumption is violated.

For Hyperliquid timestamp checks, anchor estimated UTC to the validated block-time sample and add elapsed monotonic time; re-anchor on fresh observations. Block time is an estimate, so the validated profile includes timestamp uncertainty and finality lag. [Solana block time](https://solana.com/docs/rpc/http/getblocktime)

Session expiry remains in slots. A stalled chain cannot extend authority indefinitely because the no-progress deadline stops signing. Restart does not carry over a previous worker's freshness claim; it repeats bootstrap. Host rewind, pause, scaling, and cloning of the timer are part of the platform assessment. If the platform cannot meet the timer assumption, use an independently authenticated freshness/time mechanism or keep that deployment out of beta.

Phase 0 and fault testing must select and document `max_rpc_delay`, `max_observation_age`, `max_no_finality_progress`, `max_peer_slot_skew`, `max_timestamp_uncertainty`, and `max_signature_lifetime`. They are required deployment parameters, not arbitrary defaults inferred from a slot count.

## Freeze and revocation

Grant authority only from finalized state. Treat authenticated confirmed-state revocation and freeze observations as conservative reasons to stop, even before finalization. An isolated provider can consequently cause an availability failure through a false negative signal; it cannot grant new authority through that signal.

A worker latches an observed negative control event in memory with its root/session, control version, and context. It does not clear the latch merely because another provider serves older state or a timer expires. A revoked session is replaced by a new finalized grant. Root resumption after a freeze requires an owner-authored finalized clear advancing the control version and reconciling the latched event, including the rolled-back-confirmed-event case.

Restart repeats confirmed and finalized control checks. Latches are not a globally durable security boundary. Finalized control versions, the provider assumptions, and freshness deadlines govern replacement instances and replicas. Revocation can race with an in-flight operation and does not invalidate a signature already released.

## Failure handling and replicas

| Failure | Required response |
|---|---|
| Timeout or process crash | Abort local attempt; retry only with fresh randomness and attempt identity |
| Cryptographic verification failure | Stop signing for the root; authenticate evidence, alert, and invoke controlled incident handling |
| Invalid request or authority | Reject without signing |
| Missing or corrupt package | Reject; restore the same validated ciphertext if available, otherwise replace the agent |
| Activation result uncertain | Read finalized root state before continuing; never overwrite active metadata |
| Time or state freshness failure | Refuse until bootstrap or fresh observations satisfy the configured rule |

Do not label an unverifiable coordinator error as proven peer cheating. Backends without attributable aborts report a cryptographic failure without inventing a culprit. Incident handling may protectively freeze the affected root under the configured authority; resumption requires investigation and owner control.

A retry of the exact destination operation preserves its signed nonce and payload. Hyperliquid replay protection determines whether duplicate delivery executes once. Changing any destination field is a different authorized operation. Every signing attempt still uses fresh protocol state.

One deployed worker per domain is an operational simplification. Hosts may launch replicas with the same measurement and receive the same provisioning. The core must therefore tolerate concurrent exact-operation attempts and independent valid requests without relying on local counters. Backend concurrency and session separation are tested before deployment.

This works because the MVP promises only stateless per-request limits and destination replay safety. Introducing cumulative budgets or exclusive resources later requires durable claims or reservations, as specified in v0.4.

## Immutable deployments and replacement

Each production sealing secret is bound to one exact worker image identity. The initial configuration provides no path to release or re-encrypt existing signing packages to a changed image. The hardware spike must demonstrate the actual provider settings, including application and KMS upgrade/migration controls. Image binding is not inferred from a brand name.

Oyster documents image-dependent persistent derivation. Phala's exact application release policy must be verified for the selected deployment. KMS operators, KMS upgrades, attestation roots, registry governance, and hardware compromise remain trust dependencies even with immutable worker images. [Oyster persistent-key behavior](https://docs.marlin.org/oyster/build-cvm/tutorials/persistent-keys)

Upgrade and loss use the same replacement sequence:

1. Start the replacement deployment beside the existing one and enroll its verified identities under the timelock.
2. Create and activate a fresh root and agent address. The owner independently verifies the address and approves it through the master account.
3. Grant a new finalized session and verify the replacement with a controlled operation.
4. Stop old delegates, revoke old sessions, and cancel or manage outstanding orders through available owner authority.
5. Deauthorize the old agent at Hyperliquid and verify the result, respecting registration limits and replacement behavior.
6. Retire the old root and deployment configuration on Solana, then shut down old workers under the operational retention policy.

A lost package may prevent old workers from cancelling; the owner must retain a tested direct cancellation/reduction path. Deauthorizing an agent does not itself close positions or necessarily cancel existing orders. Never reuse a retired agent address: Hyperliquid warns that pruning its nonce state can enable replay of previously signed actions. [Agent lifecycle and nonce rules](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets)

Rotating keys on upgrade avoids same-address migration. It does not undo prior trading, erase extracted secrets, or make old signatures disappear. New registration may require owner availability and destination access; replacement is an explicit workflow rather than automatic recovery.

## Receipts and observability

Both workers return signed receipts identifying the root, session, derived agent, payload digest, signing attempt, accepted control version, observed chain contexts, backend/adapter versions, and measured worker identity. Clients retain them.

There is no required append-only log or on-chain anchoring service. Receipts are assertions by authenticated workers, not proofs of correct policy or destination execution. A coordinator may withhold them. Client-visible failures distinguish request rejection, freshness failure, transport interruption, package loss, and cryptographic incident without exposing secret diagnostics.

Operational monitoring records latency, errors, provider progress, package availability, and deployment identity. Production logs exclude private request material unless explicitly permitted and never include signing secrets or randomness.

## Development seams and fast loop

| Seam | Local implementation | Production implementation |
|---|---|---|
| Sealing secret | Test secret in an isolated temporary fixture | Exact-image provider provisioning |
| Attestation and identity | Dev-signed evidence using reserved mock identities | Hardware evidence and verified enrollment |
| Chain view and clock | Injected observations, LiteSVM, and virtual time | Required RPC sets and assessed timer/time mechanism |
| Blob store | Temporary directory | External encrypted object storage |
| Transport | In-memory channels, then local sockets | Authenticated encrypted sessions routed through relay |
| ThresholdEcdsa | Selected real backend with isolated test entropy | Same pinned backend with protected fresh entropy |

LiteSVM is a test fixture. The production enclave embeds no Solana VM. Dev files and simulated attestation are excluded from production paths.

The fast loop has four tiers:

1. **Unit and integration tests:** real two-party MPC in one process, injected observations and virtual time, message drops/reordering, package fixtures, and SDK differential vectors. Keep expensive setup in a separately selectable suite when necessary; benchmark rather than assume all real MPC tests run in seconds.
2. **Local processes:** coordinator, two workers, test validator, and encrypted package store. Run destination integration against Hyperliquid testnet separately from deterministic offline tests.
3. **Provider adapter tests:** available official provider simulators and narrowly scoped local mocks. Simulator availability is validated during Phase 0; mocks prove application wiring, not hardware confidentiality or release-policy security.
4. **Real hardware:** both providers with reproducible images, real attestation, real provisioning, and measured transport. Run before release and during scheduled CI only if scheduling is separately configured.

Production builds exclude mock provisioning, fake attestation, deterministic entropy, and test trust roots. CI rejects incompatible insecure feature combinations and verifies the measured production artifact. Production registry enrollment rejects reserved development identities. These guardrails are enforced at build, verification, and enrollment boundaries, not merely by a runtime environment flag.

## Build phases

| Phase | Deliverable | Exit criterion |
|---|---|---|
| 0 Feasibility | Backend comparison, plain-key Hyperliquid encoding probe, hello-world on both providers | License and backend selected; provisioning, attestation, timer assumptions, networking, and inter-provider latency recorded |
| 1 Local skeleton | Two logical workers with real MPC, registry in LiteSVM, fixed adapter schema | Finalized session to accepted testnet order/cancel; core denial tests pass |
| 2 Service | Separate workers, relay, mock identity adapter, encrypted packages, restart and fault injection | Relevant invariant suite passes under concurrency and failures |
| 3 TEE deployment | Provider adapters, reproducible builds, verified enrollment, immutable image release policy | Same suite passes on both real providers; p50/p95/p99 and throughput measured |
| 4 Limited beta | Owner verification, replacement workflow, revocation, monitoring, external review | Disposable agents only; destination scope, clock trust, and production build exclusions demonstrated |
| Later persistent accounts | Recovery, refresh, reservations, and broader key lifecycle | Separate implementation plan based on v0.4 |

Plain-key signing in Phase 0 validates destination encoding only and is absent from the deployed signing service. TEE hardware is not postponed entirely: the first hello-world spike tests assumptions that local code cannot establish.

## Invariants and acceptance mapping

| ID | Invariant | Required acceptance evidence |
|---|---|---|
| I01 | A signature requires both enrolled domains for the selected root | One unavailable or refusing participant yields no service signature; wrong peer identity rejected |
| I02 | Root activation is owner-authorized, jointly acknowledged, and immutable | Competing activation cannot overwrite; changed public material or package digest rejected |
| I03 | Owner approves the independently derived destination agent | SDK derives from chain code/root metadata and detects altered approval address or network |
| I04 | Every request proves delegate possession and binds all relevant fields | Modified nonce, expiry, root, session, action, or adapter version fails authentication |
| I05 | Actions and fields are default-deny | Unknown actions, withdrawals, transfers, leverage changes, builder fields, and malformed batches rejected |
| I06 | Network, account path, and destination account are fixed | Wrong network, alternate path, missing/changed sub-account, or unauthorized master context rejected |
| I07 | Both workers construct the same exact signing payload | Official SDK differential vectors, including decimals, order encoding, nonce, expiry, and account context |
| I08 | Accepted authority is sufficiently fresh under declared assumptions | Provider disagreement, excessive slot, stale bootstrap/progress, timer fault, and cache expiry cause refusal |
| I09 | Confirmed negative controls stop signing; grants require finality | Revocation/freeze during signing, fork rollback, older-provider response, and explicit finalized resumption tested |
| I10 | Every cryptographic attempt has fresh entropy and unique context | Explicit entropy-source failures fail closed; retries/concurrent attempts have distinct protocol inputs; no deterministic production feature |
| I11 | Packages are authenticated and bound to their root and image | Corrupt envelope, swapped side/root/attempt, wrong image secret, and malformed backend package rejected |
| I12 | Restart cannot resume an unfinished signing attempt | Crash at each protocol boundary starts a new attempt; completed duplicate delivery follows destination replay semantics |
| I13 | Cryptographic failures are not ordinary retry events | Injected consistency failures stop root signing and alert; unattributed errors do not falsely name a peer |
| I14 | Replacement never migrates an old key to changed worker code | Old/new deployment coexistence, master re-approval, old-agent deauthorization, and lost-package workflow demonstrated |
| I15 | Production excludes development trust and secret persistence | Build/enrollment rejection of mocks; secret-log/dump checks; real attestation and provisioning verified |
| I16 | No cumulative or loss bound is implied by stateless checks | Repeated permitted requests demonstrate absence of a total-budget guarantee; documented account-boundary test |

The suite is backend-aware: it does not assume a fixed number of rounds, an OT package layout, or attributable abort support. Freeze races and released signatures are reported with their actual limits rather than tested against an impossible instantaneous-revocation guarantee.

## Beta gates and remaining choices

Before beta, pin the backend and licenses, approved image/KMS configurations, off-chain attestation verifier and registration authorities, provider sets and fault assumptions, timer behavior, freshness parameter profile, Hyperliquid account boundary, fixed action schema, asset interpretation, and owner replacement procedure.

Document the chosen blob store's availability policy and tolerated replacement time. Package replication can be added for uptime without changing the cryptographic threshold or pretending to provide share recovery.

Measure the whole authorized path, including cold/warm package loading, chain observation, MPC, queueing, and signature delivery. A round count is not a latency promise. The beta gate requires observed distributions and an agreed service objective; no 100 ms target is assumed satisfied.

The MVP ends at restricted signing with replaceable agents. Persistent signing authority, cumulative limits, simulation, and additional chains continue under the unchanged v0.4 reference architecture.
