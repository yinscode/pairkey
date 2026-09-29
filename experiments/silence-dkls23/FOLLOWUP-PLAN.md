# DKLS23 follow-up: upgrades, recovery and cryptographic review

Status: design/review plan, not an implemented or approved protocol. Architecture
[v0.4](../../docs/architecture-v0.4.md) remains the reference architecture. Spike C
is an experimental alternative: independently derived contributions plus transient
native packages and fresh preprocessing. Passing lifecycle tests does not promote
that construction into the reference architecture.

## Task 5 — configuration migration and address-preserving recovery

### Phase 5A: specify the upgrade contract

1. Inventory every field currently committed by `WalletRecord` and the source-
   derived `configuration()`. Classify stable cryptographic identity separately
   from authorized implementation versions. Preserve the exact old record bytes,
   digest, contributions, aggregate key, chain code, representation and derivation
   version. A changed constructor, derivation or scheme is a compatibility
   decision, not automatically a software-only upgrade.
2. Design an append-only transition record referencing the exact predecessor,
   old and new configuration digests, ordered identities, affected wallets/domain,
   controller authorization, sequence, activation rules and both endorsements.
   This authorizes execution under a new configuration without modifying the
   original wallet record. An old schema without an authorized transition is
   refused; it is never silently re-registered or rewritten.
3. Specify an authoritative commit/activation point, initially PairRegistry in
   the v0.4 design. Both workers must verify finalized, sufficiently fresh control
   state. Pending preparation is not activation. Define old-version fencing,
   cancellation, timeout, emergency freeze and rollback behavior. Enclave/KMS code
   release governance must enforce the transition too; a registry entry alone
   does not prevent release of roots to arbitrary new code.
4. Build a local model and fault tests before integrating Solana: interrupted
   prepare/commit, one-sided upgrade, conflicting successors, stale authority,
   replayed endorsements, concurrent old/new attempts and an unrelated domain.
   Require unchanged wallet/address identity, an unambiguous active configuration,
   and refusal of unapproved transitions. Already released contributions cannot
   be recalled by a later activation.

Exit: reviewed transition specification and local tests. Cross-host enforcement,
freshness, snapshot resistance and real KMS governance remain deployment gates.

### Phase 5B: choose a recovery model explicitly

5. Separate service replacement from key replacement. Restoring the same root,
   KDF version and signer slot can reproduce the same contributions and addresses.
   It also recreates the same secret exposure: old workers/clones must be fenced
   by authoritative identity/boot activation. Replacement starts fresh channels,
   entropy and preprocessing; it never restores a consumed pool entry.
6. Evaluate a concrete 2+1 recovery ceremony against v0.4's protected-package
   baseline: recovery domain, C's authority/material, survivor participation,
   attested replacement identity, authenticated encrypted transfer, timelock,
   notification/cancellation, durable activation and recovery drills. For the
   root-only experiment, test encrypted restoration of the *same scoped root*
   first. A single platform-wide root makes all its derived wallets share that
   recovery and compromise scope; domain isolation would require separate roots.
   Do not infer a third cryptographic signing share from a recovery approval key.
7. Resolve address-preserving root rotation/proactive refresh separately. A new
   independent KDF root generally changes contributions and wallet addresses.
   Preserving an old aggregate key needs retained/transferred old secret material
   or a reviewed refreshed-share/offset/package design with additional state and
   a new security argument. Compare that cost with v0.4's distributed package
   refresh and genuine dormant 2-of-3 alternative. Do not claim that fresh OT
   refreshes deterministic shares or erases previous root exposure.
8. Exercise loss of either worker, loss of backups, unavailable/compromised C,
   cloned old instances, interruption at each recovery commit point and a restored
   worker with stale authority. Require the same public key and chain code for
   address-preserving recovery, independent verification of resulting signatures,
   and documented residual ability of old backups to reconstruct secrets.

Exit: an explicit recovery choice, threat model and testable ceremony. Root backup
restoration is not proactive cryptographic refresh. Implementing a production
ceremony requires real attestation, entropy, authoritative controls and licensing.

## Task 6 — independent cryptographic review

### Phase 6A: freeze and map the construction

1. Freeze a review commit, upstream revision, patches, resolved dependencies,
   unchanged Silence parameters, configuration digest and exact wire encodings.
   Produce canonical registration/setup/consumption/native transcript examples
   using public data, plus a secret-memory and entropy lifecycle inventory.
2. Write an assumption-to-code matrix for the applicable DKLs23 security argument.
   Include the deterministic KDF contribution distribution, root independence,
   multi-wallet/domain separation, scalar rejection, Shamir conversion and public
   child derivation. State root/child compromise consequences explicitly.
3. Specify registration's malicious-party model. Ask whether current Schnorr
   proofs and context-bound identity endorsements establish the needed extraction
   assumptions; analyze adaptive contribution selection and whether commitment
   before reveal is required. Knowledge of a scalar is not evidence that it came
   from an independently provisioned root. Treat this as an open obligation.
4. State the constructor contract: checked local algebra versus caller-established
   setup authentication, OT/PPRF correlations, zero-share seed distribution,
   freshness, identity ordering and complete transcript agreement. Seek upstream
   review of the restricted import interface and exact audit coverage.

### Phase 6B: review composition, then resolve findings

5. Commission a threshold-ECDSA/MPC cryptographer to assess wallet-independent
   preprocessing followed by wallet/message/attempt binding, directional seed
   correlation, zero-coin commitments, native OT-extension binding, concurrent
   consumption, malicious aborts and selective failure across sessions. Review
   the combined signing API, nonce/seed freshness and cancellation/release model.
   Single-use ledgers and matching hashes are implementation evidence, not a
   proof of this composition.
6. Obtain upstream resolution of the revised OT/VOLE analysis for the exact locked
   implementation and audit assumptions. Per the project decision, keep native
   parameters unchanged while this question is open. No parameter-name inference,
   passing test, or native-library audit substitutes for a justified security
   conclusion for the custom construction.
7. Require a written findings report with theorem/assumption scope, actionable
   issues, residual risks and an explicit accept/reject/conditional decision.
   Fix accepted findings in separately reviewable changes and rerun relevant
   vectors/lifecycle tests. An unresolved proof obligation remains a blocker.
8. Track licensing, platform attestation/entropy/memory, cross-host authority,
   rollback/snapshots and storage/power-loss durability as separate gates. Obtain
   product-use rights before product integration. Cryptographic review does not
   certify those operational properties.

Exit: independent written approval of the specific construction and reviewed
remediations, or a decision to retain the native DKG/package baseline. Additional
lifecycle tests and Astra's implementation review cannot close this gate.

These design and review preparations can proceed without TEE provider accounts.
Production platform validation and secret release/recovery drills cannot.
