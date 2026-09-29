# PairKey Architecture v0.4

**Solana governed threshold signing across independent TEE domains**

Updated October 10, 2026. Status: architecture proposal; cryptographic integration, recovery implementation, and performance remain subject to validation.

PairKey lets applications and agents control native blockchain accounts through programmable authorization on Solana. Two independent signing domains evaluate each request and jointly produce a standard destination signature. Each domain runs replaceable, diskless enclave workers backed by encrypted root key packages and a durable Solana control plane.

V0.4 replaces independent KDF derived signing roots with jointly generated distributed roots. It uses one controller and recovery domain per root, library supported account derivation, fresh online signing, and explicit package activation. The baseline retains cryptographic 2-of-2 signing with protected recovery material. A genuine 2-of-3 configuration with a dormant recovery participant is an alternative requiring a separate initial key ceremony and security statement.

## Architecture decisions

| Area | V0.4 direction |
|---|---|
| Active domains | A and B, operated through independently governed TEE infrastructure |
| Initial providers | Phala and Oyster, subject to verified hardware, KMS, and release configurations |
| Root scope | One controller and recovery domain per independent root; separate roots per scheme |
| Root creation | Protocol supported distributed key generation without a complete private key being assembled |
| ECDSA account derivation | The selected DKLS23 implementation's BIP32 public derivation and chain code |
| Ed25519 | Compatible FROST implementation; account derivation deferred until reviewed |
| Worker persistence | No local durable secret state; encrypted packages stored externally |
| Durable activation | Finalized PairRegistry records identify the active package set |
| Signing | Fresh online protocol execution; no persistent transaction specific presignatures |
| Initial authorization | A committed Session PDA, followed by independently enforced session checks |
| Stateful limits | Durable reservations or accounting; Solana is the initial serialization point |
| Baseline recovery | 2-of-2 signing plus separately protected package recovery |
| Alternative recovery | 2-of-3 key with C dormant during routine signing |
| Security claims | No automatic rollback immunity, instantaneous revocation, or proactive security claim |

## System structure

```text
Application or agent
        |
        v
PairKey SDK and API
        |
        v
Untrusted coordinator and message relay
        |
        +--------------------------+
        |                          |
        v                          v
TEE domain A                  TEE domain B
  Request authentication        Request authentication
  State and policy checks       State and policy checks
  Package loading               Package loading
  Chain adapter                 Chain adapter
  Threshold signing <---------> Threshold signing
        |                          |
        +-------------+------------+
                      |
                      v
          Native destination signature

Both domains independently access:
  PairRegistry and application programs on Solana
  Encrypted package storage
  Their own KMS and attestation infrastructure
  Approved time and destination data sources
```

The coordinator routes messages and may censor or delay them. It has no signing share and cannot substitute authorization, derivation paths, or message digests accepted by honest workers. Client authentication covers the full request. Transport encryption protects sensitive payloads; encrypting client payloads to the enclaves reduces coordinator visibility, but timing and routing metadata remain visible.

The worker's local policy component authenticates capabilities, parses operations, enforces constraints, and verifies Solana evidence. V1 does not embed a general Solana execution VM. Application business rules live in application programs; SIMULATE later evaluates their authorization instruction through an explicitly trusted execution and state interface.

## Security domains and governance

A signing domain includes its worker software, hardware attestation root, KMS, storage key lifecycle, secret release rules, deployment credentials, upgrade authorities, and state providers. Phala and Oyster are provider choices; their names alone do not establish independence.

Each domain must have independent authority over release of existing secrets to new code. Registry and policy upgrades are also authority paths: replacing a Solana program at the same address can change what the honest signers authorize. Code identities, dependencies, and upgrade rules must therefore be pinned or governed through explicit timelocks. The actual hardware split is a deployment invariant, not an assumption inferred from a provider brand.

Timelocks apply at the secret release and migration boundary as well as the peer measurement allowlist. A signing worker rejecting a new peer does not prevent an unauthorized KMS release. Owner notifications and cancellation paths accompany sensitive transitions. An exit window only helps while the owner retains an available authorized signing path.

Provider KMS configurations must be evaluated separately. Phala documents a KMS controlling sealing and application key release; Oyster documents root servers and on-chain access control for its KMS. Neither is treated as outside PairKey's trusted computing base. [Phala key management](https://docs.phala.com/dstack/design-documents/key-management-protocol), [Oyster KMS architecture](https://docs.marlin.org/oyster/nautilus/architecture)

## PairRoot distributed key management

A and B run DKG for each root. For an illustrative additive representation:

```text
root secret x = a + b mod q
root public key P = xG
```

The actual key shares and interpolation rules are those of the selected library. Arbitrary scalar injection is not a substitute for protocol setup. Root creation includes agreement on participant identities, controller, recovery configuration, cryptographic suite, and a fresh protocol instance.

Each root belongs to one controller, which may be an owner key, a multisig, or a program governed authority. Accounts derived under that root share its recovery and compromise scope. Independently owned accounts require separate roots. High value or exportable accounts can use dedicated DKG roots instead of sharing a derivation family.

ECDSA roots use the library's root public key and chain code to derive account public keys. Schematically:

```text
account secret x_i = x + offset_i mod q
account public key P_i = P + offset_i G
```

The selected implementation determines the offset from the derivation path; PairKey does not introduce a custom tweak hash. A canonical path allocation records application and account identity without ambiguous encodings or collisions. Public derivation under this configuration must not be presented as hardened derivation.

Root identity, scheme, derivation version, public key, and chain code are stable. Share epochs and policy epochs are separate mutable versions. Refresh must preserve both the root public key and chain code to preserve derived addresses.

Complete child private keys are not exported from a shared additive derivation family. Given a child secret and its public derivation offset, the root secret can be recovered. A derived participant share can likewise expose that participant's root share through its known relation. Separately encrypted child packages do not remove these relationships.

FROST Ed25519 uses a separate root and reviewed key setup. RFC 9591 specifies compatible signing, not an account derivation API. V1 can assign one account to each Ed25519 root. Additional threshold derivation requires its own implementation and review; it is not inherited from the DKLS23 path. [FROST specification](https://datatracker.ietf.org/doc/html/rfc9591)

## Key packages and enclave workers

DKLS23 packages contain more than a signing scalar: they include participant metadata, verification information, a root chain code, and long-lived OT material. The package also supports immutable application extra data. PairKey includes root ID, recovery domain, scheme, and metadata version there and verifies them on load. The implementation exposes public account derivation through that package. [DKLS23 key package](https://github.com/silence-laboratories/dkls23/blob/main/src/keygen/keyshare.rs)

| State | Durable location | Worker behavior |
|---|---|---|
| Provider sealing secret | Provider KMS | Released only under approved attestation and governance |
| Root key package for each participant | Encrypted external blob | Verified, decrypted, and cached in memory |
| Package commitments and active epoch | PairRegistry | Read through the state and freshness policy |
| Controller, policy, freeze, and recovery records | Solana | Independently evaluated by both signers |
| Reservations and cumulative accounting | Solana initially | Atomically claimed when required |
| Session token | Client supplied or cached | Authenticated and checked against current control state |
| Long-lived OT seeds | Inside encrypted root package | Available in memory with that package |
| Signing randomness and protocol messages | No durable location | Fresh per attempt and discarded afterward |
| Instance channel keys | No durable location | Fresh ephemeral keys bound into attestation |

Each worker receives its provider sealing secret at boot, establishes its identity and fresh attested communication channels, and loads packages lazily. Secrets, decrypted packages, random seeds, and unfinished protocol state are never written to local disk, logs, swap, crash dumps, or host diagnostics. Deployment must validate the memory and entropy assumptions for the chosen platform, including any snapshot or cloning capabilities.

This is a diskless worker model backed by a stateful service. It avoids copying local persistent state between workers; it does not eliminate durable state, rollback risk, replica races, or package availability requirements.

### Package encryption and loading

Each side encrypts its complete package with AEAD. A proposed envelope key derivation is:

```text
K_pkg = HKDF(seal_root_side,
             Encode("pairkey-package", envelope_version,
                    root_id, scheme, side, share_epoch))

AAD = Encode(root_id, scheme, side, share_epoch,
             root_public_key, chain_code_commitment, metadata_version)

package_digest = SHA256(canonical encrypted envelope)
```

Use unambiguous encodings and fresh AEAD nonces. The envelope contains enough authenticated version information to select the correct decoder. This is a storage design proposal, not a substitute for reviewing the envelope implementation.

An epoch specific package key limits the scope of a leaked leaf encryption key. A leaked sealing root still derives all of that side's package keys across roots and epochs. Root scoping therefore isolates complete wallet key families but does not isolate a shared application sealing-root compromise on one side.

Before signing, the worker obtains a trustworthy, sufficiently fresh registry view, fetches the active envelope, checks its digest, authenticates and decrypts it, and verifies package metadata against the root record. Cached packages are keyed by root, participant, and share epoch and are unusable after the cache's authorization freshness deadline.

Ciphertext storage is untrusted for confidentiality and integrity, but essential for availability. Replicate active packages and necessary recovery material to at least two independent stores. Read back, decrypt, and validate copies before signing preparation readiness. These checks detect initial storage failures; subsequent durability requires monitoring and repair. A lost package with no surviving replica is a lost share package.

## PairSign and the OT lifecycle

DKLS23 establishes reusable OT setup during root creation. Each independent root's participant packages carry their matching setup. PairKey keeps this material scoped to the generated package pair rather than introducing a global OT pool across unrelated roots. Account paths within the same root reuse that root's setup while each signature performs fresh multiplication work.

```text
Boot A and B
    |
    +-- Create root R1: DKG and OT setup -> packages A1 and B1
    |
    +-- Create root R2: DKG and OT setup -> packages A2 and B2

Sign R1, path 1 -> A1 and B1 + fresh signing randomness
Sign R1, path 2 -> A1 and B1 + fresh signing randomness
Sign R2, path 1 -> A2 and B2 + fresh signing randomness
```

The inspected signing entry point uses a caller-supplied seed to generate secret protocol randomness, runs an internal presigning phase, then completes a signature. It also exposes separate presign and finish APIs and party-identifying errors on failed multiplication checks. [DKLS23 signing implementation](https://github.com/silence-laboratories/dkls23/blob/main/src/sign/dsg.rs)

PairKey's wrapper exposes only the combined signing entry point. It generates a fresh independent seed inside the TEE for every DKG, refresh, and signing attempt from a validated cryptographic entropy source. It never derives an attempt seed deterministically from a sealing root, request, timestamp, or public session ID. Test helpers and deterministic test seeds are excluded from production paths.

Transaction specific presignatures may exist temporarily inside a combined call but are neither persisted nor reused. Nonces, attempt seeds, round state, and intermediate outputs are erased on completion or abort. A crash ends the attempt; the replacement worker starts a new protocol session.

Both workers independently authenticate the caller, authorize the operation, and construct the destination payload and digest. They agree on root, share epoch, participant set, account path, adapter version, exact payload, and authorization commitment before running MPC. Package mismatches are rejected before MPC rather than left to arithmetic failures.

For the inspected implementation, the conceptual signing sequence is:

1. Exchange fresh session contributions, nonce commitments, and session encryption information.
2. Exchange OT based multiplication messages.
3. Exchange multiplication responses and verification material.
4. Exchange final signature contributions and verify the resulting signature.

This maps the implementation's four message stages; it is not a claim that every DKLS23 implementation has the same network schedule.

| Outcome | PairKey response |
|---|---|
| Crash or transport timeout | Abort; permit a fresh attempt under retry rules |
| Authorization rejection or expired evidence | Refuse signing; require valid new evidence |
| Authenticated cryptographic inconsistency | Stop signing for the root, preserve non-secret diagnostic evidence, and alert |
| Package or configuration mismatch | Reject and reconcile against active registry configuration |

A reported fault must be authenticated and attributable before triggering durable incident handling. The coordinator cannot freeze a root merely by submitting an unsigned error. An active signer may request a protective freeze; unfreezing requires the configured owner and remediation authorization.

Retries preserve the destination operation identity, nonce, and reservation where applicable, while using new cryptographic attempt IDs and seeds. A completed signature may already exist elsewhere even when a worker times out. Safe retries depend on destination replay protection and durable accounting, not on assuming that timeout implies no signature was released.

## PairRegistry control plane

PairRegistry separates root lifecycle from wallet policies. The following fields describe records, not a final Rust ABI.

| RootRecord field | Purpose |
|---|---|
| root_id and recovery_domain_id | Stable identities and recovery scope |
| controller | One governing authority for the root |
| scheme and derivation_version | Immutable interpretation of root material |
| root_public_key and chain_code_commitment | Stable signing and derivation identity |
| threshold and participant configuration | Cryptographic access structure chosen before DKG |
| normal_signer_set | Routine operational participants, normally A and B |
| share_epoch | Current package generation |
| participant_package_commitments | Active encrypted package digest for each participant |
| recovery_mode and recovery_config_commitment | Approved recovery construction and authorities |
| recovery_material_commitments | Active backup or recovery package references |
| status and pending_transition | Active, paused, frozen, or pending lifecycle operation |

The public chain code is distributed through authenticated derivation metadata and verified against its registry commitment. It is not a signing secret in this public derivation configuration.

| WalletRecord field | Purpose |
|---|---|
| wallet_id and root_id | Account identity and root reference |
| canonical_derivation_path | Account selection; empty for an underived root account |
| account_public_key | Pinned expected public key |
| policy_root and policy_epoch | Approved authorization configuration and version |
| frozen | Wallet specific protective control |

Additional records cover finalized sessions, exact-operation approvals, reservations, approved enclave measurements, upgrade transitions, incidents, and recovery requests. Application business rules belong in application programs, while PairRegistry enforces shared lifecycle and authorization invariants.

Wallet policies may differ under a root, but recovery authority and root compromise fate remain shared. Controller transfer or recovery changes must make that scope clear and invalidate affected capabilities through policy or recovery versions.

## Package transitions and crash handling

DKG creates an initial package set. Refresh and recovery create a replacement set. Signing is paused during replacement in the initial implementation to keep transitions simple.

1. **Authorize and pause.** Establish the operation's authority and expected current epoch. A new root remains inactive until its initial ceremony is committed.
2. **Prepare.** Participants run the required protocol with fresh randomness, validate the result, encrypt packages, replicate them, and prepare matching recovery material.
3. **Acknowledge readiness.** Required participants sign the same transition commitment containing root ID, previous and next epochs, participant configuration, all package and recovery commitments, public key, chain code commitment, and protocol instance.
4. **Commit.** One Solana transaction checks the expected previous epoch, required participant signatures, owner authorization, lifecycle status, and recovery rules, then activates the full package set atomically.
5. **Activate.** Workers observe finalization through the freshness policy, load matching packages, discard old in-memory state, and resume signing when the transition allows it.

Refresh preserves the public key and chain code. Changing threshold or membership is a separately governed migration and cannot be assumed to be covered by ordinary refresh or its audit.

| Failure point | Required behavior |
|---|---|
| Before readiness | Abort or restart preparation with fresh randomness; no new package signs |
| Prepared but never committed | Blobs are inactive orphans; owner may authorize cancellation and resumption of the prior epoch |
| Commit result uncertain | Read finalized transition status; do not assume either outcome or replay blindly |
| Committed but one worker crashes | Replacement loads the finalized package set; activation does not depend on the original instance |
| Committed package unavailable | Stop signing and repair storage or invoke recovery; do not silently fall back to an old epoch |

Registry commits identify the active packages. They do not guarantee storage durability, erase historical secrets, or coordinate every request. Replicas still need durable serialization for shared authorization decisions.

## PairPolicy authorization

Authorization requirements are selected by registered policy, never by a caller choosing a weaker mode. Both signers independently enforce the same relevant policy version and bind evidence to the operation.

### COMMIT

A Solana program records authorization for a session or exact operation. Signers verify account ownership, record identity, controller, policy epoch, operation binding, expiry, and any reservation requirements from sufficiently fresh finalized state.

Approval records distinguish one exact destination operation from a general grant. Re-signing identical destination bytes may be safe when destination replay protection guarantees one execution. Changing the destination nonce or any signed field creates a different operation and requires matching authority. Approvals involving budgets or exclusive resources also require durable accounting.

### SESSION

V1 creates a finalized Session PDA containing the delegate key, wallet and root references, permitted actions, market or destination allowlists, constraints, expiry, and policy epoch. A self-contained capability may mirror this record and carry signatures from both active domains; the coordinator cannot issue authority. The registry record remains the durable source for issuance and revocation.

Each request proves possession of the delegate key and is bound to the full intent. Workers evaluate scope, policy epoch, freeze status, expiry, state freshness, and any accounting requirement. No Solana write or simulation is required for each request governed solely by stateless limits. Solana reads or maintained finalized observations still contribute to latency.

Short-lived caches have explicit freshness deadlines. Revocation affects future signing once the new state is observed under those deadlines; a change can race with an already authorized in-flight operation. PairKey does not promise instantaneous revocation or invalidation of signatures already released.

### SIMULATE

Simulation is a later authorization adapter for application-defined predicates. Standard Solana RPC simulation supplies execution results, not a consensus-authenticated state witness. The initial simulation release explicitly trusts its providers for the supplied state and execution; an attested executor alone does not authenticate its inputs.

Use a constrained transaction template, independently authenticated caller binding, and structured return data committing to the exact intent. Prevent caller-added instructions from altering simulated policy state before authorization. A simulated signer flag alone does not prove identity when signatures have not been verified. `minContextSlot` is a lower bound, not a request to execute an exact historical snapshot. [Solana simulation](https://solana.com/docs/rpc/http/simulatetransaction), [Agave context selection](https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L259)

The evidence agreement protocol must specify how both workers obtain compatible policy observations. Observation slots can differ when the committed records are unchanged; unstable predicate results cause rejection or re-evaluation. Exact snapshot execution requires additional infrastructure.

Simulation can authorize stateless predicates and intentional per-operation permissions. It cannot enforce a cumulative budget or consume an approval without an additional durable mechanism.

### Stateful accounting

Counters in separate enclave instances do not enforce a global budget. Requests requiring cumulative limits atomically claim a reservation on Solana before signing. Reservations bind the exact operation, amount or resource, policy epoch, and destination replay identity.

Do not release a reservation merely because a request timed out: a signature may exist or execution may still occur. Settlement and release require adapter-specific evidence or a destination-enforced expiry that rules out later execution. Signing on Solana and execution on another chain are not one atomic transaction.

## State freshness and rollback

Each signer uses its own configured RPC provider set with TLS terminated inside the enclave. V1 trusts the selected providers for state correctness and sufficiently current finalized observations. Multiple providers reduce some correlated failures but do not create a cryptographic state proof.

The proposed freshness rule combines independently authenticated time with chain context:

1. Obtain a fresh authenticated time sample using an anti-replay challenge and bounded response delay.
2. Obtain consistent finalized context and relevant account observations under the provider quorum policy.
3. Require the observed finalized block's estimated time to lie within configured past and future bounds of the time sample.
4. Require authorization account responses to meet that fresh context lower bound, and verify consistency of the relevant record contents.
5. Require bounded peer context skew, compatible root and policy epochs, and matching operation authorization.
6. Refuse signing when time, state, or cache freshness cannot be established. Refresh observations before final contribution when the configured deadline has elapsed.

Solana block time is an estimate computed from validator vote timestamps, so bounds must allow finality lag, timestamp uncertainty, and normal provider delay. [Solana block time](https://solana.com/docs/rpc/http/getblocktime)

The time service, quorum assumptions, maximum chain lag, response deadlines, cache lifetime, and peer slot-skew bound require deployment validation. Authenticated time delivery also needs an assessed delay bound; it does not make host-controlled timers trustworthy. Peer slot agreement alone is insufficient: two workers can agree on stale state. Freshness applies to the account observations themselves, not merely to a separately fetched block timestamp. These checks cannot detect a consistent lie by a compromised trusted-provider quorum.

This mechanism protects honest code from accepting stale packages and authorization within its stated assumptions. It does not revoke extracted old signing quorums or eliminate all memory rollback and cloning risks. Snapshot behavior and entropy must be validated separately. One active instance per domain is an operational simplification, not a security boundary; another identically measured instance may receive the same secrets.

## PairRecovery configurations

Recovery mode is selected and recorded before initial DKG. Switching modes requires a reviewed migration or a new root; it is not a runtime toggle.

### Baseline 2-of-2 signing with protected backups

A and B hold the only signing packages. C holds recovery secret material and does not participate in routine signing or signing-key DKG.

Backup B encrypts B's complete long-term package under a fresh wrapping secret split between A and C. Backup A is symmetric, requiring B and C. Neither C nor the surviving signer can decrypt the missing package independently. Surviving-side recovery fragments are themselves protected durable secrets and appear in the material inventory.

To replace B:

1. Record owner-approved recovery binding the root, epoch, backup commitment, replacement identity, approved measurement, and recovery operation ID.
2. Apply the timelock, notify the owner, permit cancellation, and pause affected signing.
3. A and C independently verify recovery authority, freshness, and B prime's attestation-bound communication key.
4. Deliver their recovery contributions separately to B prime over protected channels. Reconstruct the wrapping secret only inside B prime and restore B's package there.
5. Verify the restored configuration, then have A and B prime refresh and prepare new packages and recovery material.
6. Activate the replacement epoch through PairRegistry and retire old material according to the explicit retention policy.

A user-controlled C must protect actual recovery secrets or control a protected service that holds them. An approval signature alone does not unlock a package. The wrapping and delivery construction requires independent review before production.

Persistent C decryption keys plus recoverable historical peer fragments and backup ciphertexts can remain an enduring recovery quorum. Registry updates cannot erase copies. V1 documents this bound rather than claiming that old backups are harmless or cryptographically retired.

If both A and B packages are permanently lost, C alone cannot recover them under this design. A different disaster-recovery access structure must be explicitly introduced to promise otherwise.

### Alternative 2-of-3 with dormant C

A, B, and C jointly create a genuine 2-of-3 key. C holds a complete package, including protocol material, and participates in package-refresh ceremonies. Routine operations select A and B, while C's approved software restricts its role to recovery.

If B is lost, A and C supply the surviving old shares, and A, B prime, and C run refresh to create a complete replacement package set. The library has a lost-share refresh path requiring a threshold of survivors; this cannot restore a lost participant in a 2-of-2 key. Audit coverage of this specific path must be verified separately from a general refresh audit label. [Refresh source](https://github.com/silence-laboratories/dkls23/blob/main/src/keygen/key_refresh.rs), [survivor constraint](https://github.com/silence-laboratories/dkls23/blob/main/src/keygen/dkg.rs)

This removes the missing-share wrapping construction, but C still needs durable encrypted package storage. A+C and B+C can cryptographically sign. C's dormancy is an operational restriction enforced through software and governance, not an A+B-only cryptographic access structure.

| Property | Baseline 2-of-2 with backups | Dormant 2-of-3 |
|---|---|---|
| Routine signing | A and B are cryptographically required | A and B are selected by policy |
| C material | Protected recovery material | Full signing key package |
| A plus C | Can restore B and ultimately enable signing | Can directly sign cryptographically |
| Initial signing-key ceremony | A and B | A, B, and C |
| Package refresh | A and B, with recovery material also updated | All participants, including replacements |
| Suitable C | User recovery device or protected recovery service | MPC-capable third TEE or device |
| Main review target | Backup, release, and restoration protocol | Lost-share refresh and C enforcement |

The baseline preserves v0.3's explicit 2-of-2 signing requirement. Evaluate the alternative when C is an independently operated third TEE and the product accepts a true 2-of-3 access structure.

## Refresh and historical compromise

Refresh redistributes the same signing key. In simplified additive notation:

```text
a prime = a + delta
b prime = b - delta
a prime + b prime = a + b
```

Refresh preserves addresses and changes which current shares work together. It does not revoke a complete historical threshold: any retained old quorum controlling the same root can still sign outside PairKey. Destination signatures do not carry the registry's share epoch.

| Exposure | Security consequence |
|---|---|
| One signing share captured once | Later share refresh may help if old counterparts and recovery paths become inaccessible |
| One epoch package encryption key | Exposure can be scoped if future keys cannot be derived from it |
| Persistent sealing root | All accessible packages derived from that root remain exposed, including future epochs |
| Continuing KMS or release compromise | Refresh cannot stop continued access to newly issued secrets |
| Historical threshold or complete child secret | Same-address refresh cannot restore confidentiality of the root signing key |

Proactive security requires coordinated share refresh, inaccessible future storage keys for the removed attacker, retirement of historical recovery material, secure erasure, and rollback resistance. Rotating a label or updating a registry digest is insufficient. V1 claims governed address-preserving refresh and migration, not forward secrecy against persistent domain compromise.

## PairAuth and chain adapters

Authentication proves who requested an operation; authorization determines whether that identity may perform it. The initial implementation uses an owner Solana signature and a cryptographic delegate key. Passkeys, OAuth-bound identities, and other authentication methods follow after the core signing lifecycle is validated.

Signers accept structured operations through reviewed adapters. Each independently verifies the network, destination or account, amount, action fields, nonce, expiry, derivation path, and serialization, then computes the exact signed bytes. Generic client-supplied digest signing is unavailable for wallets whose policies constrain transaction meaning.

Adapter versions are part of the authorization commitment. EVM typed data, transaction payloads, Solana transaction messages, Bitcoin sighash variants, and Hyperliquid actions require their own reviewed encodings and replay models. Adding a chain adds security-critical code and destination semantics.

## Hyperliquid initial integration

Hyperliquid is the first destination. The owner authorizes an API agent using the master account, then a Solana program grants a restricted PairKey session for the agent's threshold key. PairKey need not control the master account in the initial milestone; if it does, agent approval and sensitive master operations require COMMIT.

```text
Owner approves Hyperliquid agent
        |
Solana program creates Session PDA
        |
A and B verify finalized session
        |
Delegate authenticates an order or cancellation
        |
Both adapters enforce scope and construct payload
        |
Fresh DKLS23 signature
        |
Hyperliquid accepts or rejects the action
```

The adapter follows Hyperliquid's distinct L1-action and user-signed-action encodings. Agent credentials cannot transfer or withdraw under the documented SDK model, but unauthorized trades can still destroy value. PairKey protects the credential and narrows the operations it can authorize. [Hyperliquid signing](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing), [official agent example](https://github.com/hyperliquid-dex/hyperliquid-python-sdk/blob/master/examples/basic_agent.py)

Define per-order notional using explicit fixed-point price and size semantics. A per-order cap does not establish cumulative exposure or a maximum loss. Position, leverage, price-band, and outstanding-order limits require sufficiently fresh destination data and concurrency-aware accounting. Those data sources become additional trust dependencies. The initial milestone uses simple scope checks; sophisticated risk limits are a subsequent deliverable.

Use short signed `expiresAfter` values where supported. Expiry prevents later submission after the deadline but does not cancel orders already accepted. Allocate a distinct agent identity for each registration generation and generally for independent trading processes; nonce handling follows the destination's signer-specific rules. [Hyperliquid nonce and agent rules](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets)

An outage in either active domain blocks new orders, cancellations, and reductions through that pair. A scheduled cancel-all heartbeat can limit resting-order exposure, but does not close positions and has destination trigger limits. Owner-controlled alternative cancellation or reduction access must have an explicitly defined scope and is an additional authority path. [Hyperliquid exchange endpoint](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/exchange-endpoint#schedule-cancel-dead-mans-switch)

## PairProof signing receipts

Both active signers issue attested receipts containing wallet and root IDs, derivation path or its commitment, share epoch, policy epoch, adapter version, intent and payload commitments, authorization evidence, observed finalized context, signing attempt ID, enclave measurement, and time evidence reference.

The common authorization commitment covers canonical operation data and relevant record commitments. Individual observation slots can appear in separate receipts without requiring identical slots when the accepted record contents agree.

Receipts identify the code and evidence a signer says it used. They are not proofs of policy correctness, authentic chain state, or actual destination execution. Native destination signatures do not enforce receipts or registry epochs.

A replicated append-only receipt log with periodic Solana anchoring supports later audit. Omission and availability remain limitations unless signature release is made conditional on independently verifiable durable logging. Batch anchoring can avoid a Solana write per signature, but must not be described as complete on-chain observability.

## Compromise and availability model

| Compromise or failure | Consequence and boundary |
|---|---|
| Coordinator alone | Can censor, delay, and observe permitted metadata; cannot independently sign |
| One current signing package | Cannot alone sign; public derivation can expose the same participant's share across that family |
| One provider sealing root | Exposes all accessible encrypted packages protected by that root on that side |
| Both active domains or a historical signing quorum | Can sign outside PairKey's policy controls |
| Authority able to release both domains' existing secrets to malicious code | Can collapse administrative independence |
| Policy or registry upgrade authority | Can change authorization behavior unless pinned or constrained by independent governance |
| Trusted state-provider failure | Can make honest workers accept false or stale authorization under a breached trust assumption |
| C alone under baseline recovery | Cannot independently restore either signing package |
| C plus matching peer recovery material | Can restore a package and ultimately enable signing for that root |
| C plus either active share under 2-of-3 | Constitutes a cryptographic signing quorum |
| All replicas of one package lost in 2-of-2 | Signing stops; recovery requires the protected backup path |
| Solana or time freshness unavailable | Signing stops once freshness deadlines cannot be met |
| Blob stores delete or withhold packages | Cold loading and restart fail even if registry commitments remain valid |
| Compromised delegate | Can request operations within available scope; cannot exceed correctly enforced authorization |

No user signing share exists in the baseline. Owner authorization and recovery material are distinct from holding a threshold signing share. An optional user signing participant would change the access structure and require a separate design.

## Implementation and licensing gates

Silence Laboratories' DKLS23 implementation is a candidate, not a finalized production dependency. Its README marks DKG, signing, and refresh as audited and import, export, quorum change, and migration as unaudited; the audit refers to specific commits. Validate exact derivation, lost-share recovery, concurrency, serialization, and dependency coverage rather than extending that label to all current code. [Repository and audit scope](https://github.com/silence-laboratories/dkls23)

The current repository license limits use to non-commercial applications and requires commercial terms for commercial use, including internal business use. Resolve licensing before adopting the crate for a commercially intended prototype or product, or select another implementation with acceptable terms and independently verified security. [License](https://github.com/silence-laboratories/dkls23/blob/main/LICENSE)

Production gates include the actual KMS release configurations, reproducible builds, independent upgrade control, hardware entropy and rollback behavior, recovery construction, destination adapter, and registry program. Source availability and attestations do not replace those reviews.

The October 10 source review inspected candidate DKLS23 revision `af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`; this is an audit reference, not a selected dependency. Its duplicate-party-ID check compares complete `(participant_index, party_id)` tuples, allowing a peer's repeated package ID to reach a self-ID assertion. Resolve this static panic-path finding and enforce identity-to-package-ID mapping before adoption. [Pinned signing check](https://github.com/silence-laboratories/dkls23/blob/af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src/sign/dsg.rs#L142), [pinned assertion](https://github.com/silence-laboratories/dkls23/blob/af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src/keygen/keyshare.rs#L314).

The historical audit does not certify that revision or this integration. Only Lagrange sharing was in scope, and the report includes supplemental review and a partially resolved OT specification finding. Relevant selective-abort failures require aborting current and concurrent sessions with the offending counterparty and refusing future sessions. The integration must durably fence all sessions sharing affected OT material, including replicas and restarts; process-local FROST refusal is not a reusable DKLS incident design. No global cross-root OT pool or independent-KDF DKLS share injection is approved. [Assessment report](https://github.com/silence-laboratories/dkls23/blob/af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/docs/ToB-SilenceLaboratories_2024.04.10.pdf).

The current implementation still uses the experimental FROST construction in ADR 001. Its [audit remediation](implementation-status.md#frost-audit-remediation-october-10-2026) fixes local ownership, transcript and issuance defects without implementing this proposed DKG/package architecture. ECDSA, package persistence and recovery remain proposals.

## Performance and deployment

V0.3 latency numbers remain unmeasured hypotheses. V0.4 does not promise a fixed latency until benchmarked across the chosen providers with authorization checks enabled.

Measure cold package load, warm package signing, provider and time observation overhead, each MPC message stage, end-to-end signature delivery, concurrent roots, retries, and failover. Report p50, p95, p99, throughput, error rates, payload sizes, and deployment geography.

Four message stages do not necessarily cost four full RTTs. Network critical path, local multiplication work, state freshness, and queueing determine latency. Nearby deployments can improve speed but may correlate operational failures or jurisdictions. Operator and hardware diversity are documented separately from geographic distance.

Persistent attested channels and warm in-memory package caches are initial optimizations. A SESSION signature can avoid a Solana transaction fee when no reservation write is required, while still paying the latency cost of sufficiently fresh control state. Budgeted operations with on-chain reservations incur transaction fees and finality delay. DKG, refresh, recovery, and transition activation are outside the routine fast path.

## Implementation roadmap

| Phase | Deliverables |
|---|---|
| Design gate | Recovery mode, licensing, provider release rules, root scope, registry transitions, freshness assumptions |
| V0 cryptographic prototype | Two attested domains, DKG, native ECDSA derivation, fresh combined signing, encrypted package restart |
| V1 authorization milestone | Root and wallet records, committed Session PDA, delegate authentication, Hyperliquid testnet orders and cancellations |
| V1 lifecycle validation | Package activation, pause and freeze, ciphertext replication, retries, atomic reservations where required, incident handling |
| V1.5 recovery | Selected recovery construction, replacement attestation, timelock and cancellation, address-preserving refresh |
| V2 policy and risk adapters | SIMULATE under declared trust, destination data checks, exposure accounting, advanced trading policies |
| Later schemes and integrations | Solana FROST, reviewed Ed25519 derivation if needed, EVM, Bitcoin, additional operators and stronger state verification |

The first milestone is a finalized Solana session authorizing a Hyperliquid agent operation, independently checked and signed by two TEEs, with neither holding the complete private key. It does not require simulation, OAuth, passkeys, or a generalized multichain signing API.

Acceptance must cover altered intents, wrong account paths, mismatched epochs, stale or conflicting policy evidence, revoked delegates, invalid authentication, nonce reuse prevention, cryptographic faults, crashes before and after activation, package deletion, duplicate exact-operation requests, and concurrent budget claims. Recovery tests include cancellation, malicious replacement identities, missing packages, and retained historical material. Performance is measured only with the relevant safeguards enabled.

## Open decisions

| Decision | Required resolution |
|---|---|
| C deployment | User-held recovery secrets favor protected backups; an MPC-capable recovery TEE permits evaluating true 2-of-3 |
| Recovery implementation | Select and review before production DKG; baseline backup construction is not yet finalized |
| Cryptographic dependency | Commercial licensing and exact security coverage of the selected revision |
| Freshness policy | Time source, provider quorum, delay assumptions, chain lag, cache lifetime, and slot-skew bounds |
| KMS lifecycle | Who releases existing secrets, how upgrades and independent sealing-key replacement are governed |
| Blob deployment | Independent stores, access controls, read-back, durability monitoring, and orphan retention |
| Historical material | Retention and erasure rules; enduring recovery quorum disclosed wherever erasure is unavailable |
| Account path allocation | Canonical namespace mapping and collision rules using library supported paths |
| Replication | Concurrency validation and durable resource claims before active replicas are supported |
| Incident and freeze authority | Protective freeze permissions, notification, investigation, and authorized resumption |

PairKey's v0.4 foundation is distributed roots scoped to their controller, independently enforced Solana authorization, diskless workers with external encrypted packages, and fresh threshold signing. Recovery and refresh are governed key lifecycle operations with explicit access structures and historical-compromise limits.
