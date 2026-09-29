# PairKey Platform Implementation Plan

**FROST first signing infrastructure with Solana authorization**

Updated October 10, 2026. Status: numbered implementation plan; no implementation tasks have been completed by writing this plan.

Execution evidence: the local Phase 0–3 track is implemented and tested; the original Task 5 hardware probe and full Phase 0 hardware exit remain open because provider accounts are unavailable. The user explicitly deferred provider probes on October 10, 2026 and selected the local Solana Phase 6–7 track before ECDSA. The local Solana Phase 6–7 extension is now implemented and tested; EVM and hardware-dependent exit requirements remain open. Service keys and passkeys are the requested access methods; OAuth is deferred. See [task-by-task status](implementation-status.md).

Build the general PairKey platform first: two independent signers, deterministic accounts, replaceable enclave workers, fresh signing, and requests authorized by Solana accounts or programs. Start with FROST Ed25519, add two-party ECDSA, then SESSION, broader authentication, SIMULATE, and application integrations. Hyperliquid is an integration rather than the first platform milestone.

[Architecture v0.4](architecture-v0.4.md) remains the broader reference architecture. Its distributed-root design is not silently replaced: the FROST construction below is a proposed alternative that must pass Phase 0 and be recorded as an architecture decision before adoption. The existing [Hyperliquid MVP specification](mvp-spec.md) is retained as an integration-oriented proposal; its Hyperliquid-first sequencing does not govern this plan.

## Milestones and execution rules

**First platform milestone:** after namespace registration, an SDK derives a Solana account address without contacting the signers. A Solana account or program authorizes the exact transaction message, two workers produce an Ed25519 signature, and the transaction executes on a local validator.

**Hardware milestone:** the same suite runs through independently attested Phala and Oyster workers, survives worker replacement without changing existing account addresses, and demonstrates the actual entropy, provisioning, and upgrade assumptions.

**Second scheme milestone:** the common request flow supports native ECDSA, and a derived account executes an EVM transaction on a local development chain.

Tasks have stable numbers. Complete a phase's exit criteria before treating its dependent behavior as established. The original sequence starts hardware feasibility in Phase 0. Under the user-directed deferral, local software work continues, while all original hardware and production exit gates remain open. Cryptographic spikes and local test funds do not constitute a public production release.

Each completed task produces the relevant code or configuration, focused validation evidence, and a concise record of unresolved assumptions. Do not begin all tasks as one undifferentiated implementation prompt. Start with Task 1 and work through bounded tasks or closely dependent groups.

## Corrections incorporated from the feedback

The FROST proposal can eliminate stored per-namespace secret packages because key packages can be reconstructed from derived shares and authenticated public metadata. That does not eliminate the two persistent provider secrets, public registry records, upgrade authority, or nonce rollback risk. ECDSA may require external encrypted setup packages.

COMMIT can avoid a wall-clock dependency only when the initial authorization is deliberately immutable and does not expire or become invalid through cancellation, freeze, consumption, or another changing condition. Such a commitment continues to authorize the same bytes. Introduce current-state verification when negative controls enter the service; add bounded expiry and revocation freshness with SESSION. A forged RPC record remains a forged authorization even for an immutable request.

Repeated signing is not a universal exactly-once guarantee. Test the actual destination's replay behavior with two different valid FROST signatures over identical message bytes. Never refresh a transaction blockhash or destination nonce under an old exact-message approval.

Destination-domain separation derives different keys for different configured destinations; it does not make a raw signature intrinsically chain-aware. Program-controlled namespaces inherit the program's actual upgrade authority unless code identity or governance is explicitly constrained.

## Phase 0 Feasibility and architecture gates

**Goal:** establish the cryptographic and provider assumptions before building the platform around them.

1. **Freeze the platform scope and vocabulary.** Specify provider secrets, controller namespaces, derived accounts, signer identities, request identities, and the meanings of worker statelessness and fresh signing. Record precedence over the earlier Hyperliquid MVP and list the guarantees the initial COMMIT prototype actually provides.

2. **Pin the FROST dependency and review its security boundary.** Evaluate the Zcash Foundation Ed25519 crate, licenses, compiler/features, native signature encoding, and exact audited revision. Confirm constructor and scalar/public-share APIs in the chosen release. Record that the constructor's existence does not validate PairKey's injected-share protocol.

3. **Prove the deterministic namespace construction in a small spike.** For participant IDs 1 and 2, derive independent scalar shares from side-specific secrets using a reviewed KDF and canonical scheme/namespace encoding. Verify the interpolation relation `P = 2*S_A - S_B`, public registration, secret-share possession, malformed-point rejection, and malicious-peer behavior. Validate public account tweaks and reconstruction through the crate without assembling the aggregate secret. Obtain independent cryptographic review before using this custom path for real assets. If it is unsuitable, return to the v0.4 distributed-root approach and explicitly revise the root-only requirement.

4. **Specify exact-message COMMIT and replay semantics.** Decide the authorization digest algorithm, message encoding and size limits, permanent versus cancellable approval semantics, and request/response identity. Ed25519 signs the original message bytes after their authorization hash is checked; it does not silently switch to signing that hash. Test repeated signatures, blockhash expiry, durable nonces where appropriate, and downstream execution counts.

5. **Run hello-world on both providers.** Exercise attestation verification, application-secret durability across restarts, release to upgraded images, transport, protected entropy, and cross-provider latency. Investigate memory snapshot/cloning and host control of clocks. Record verified platform properties and unknowns; local simulators cannot establish them.

6. **Declare root durability, loss, and upgrade scope.** Define stable application identities with independently governed release authorities, and what permanent provider loss means for existing funds. A global side-root escrow covers all namespaces on that side; it is an operator recovery path, not per-owner recovery. Design the peer-plus-cold-authority access structure and required approvals now, with implementation in Phase 9. Separate controller-level compromise from global KMS-root exposure.

**Exit:** deterministic FROST signatures verify under the selected Solana verifier; the registration and derivation construction has a documented review boundary; both hardware probes run; the COMMIT and loss policies are explicit. All funding remains in controlled test environments until the applicable production gates are satisfied.

## Phase 1 FROST core and deterministic account SDK

**Goal:** implement the cryptographic core without networking or chain I/O embedded in it.

7. **Create the Rust workspace and interfaces.** Separate common wire types, pure authorization logic, FROST backend, worker orchestration, registry program, coordinator, and SDK. Define backend-neutral interfaces with optional setup material: none for the accepted FROST reconstruction path, potentially encrypted blobs for ECDSA. Inject entropy, attestation, chain views, provisioning, and transport.

8. **Implement namespace registration.** Bind both public shares and their reviewed possession evidence to controller namespace, scheme, participant identity, protocol version, and registration transcript. Both workers acknowledge the same aggregate public key and metadata. Registry ownership and participant authorization prevent unauthorized namespace replacement or rogue-key registration.

9. **Implement public account derivation.** Define a canonical hash-to-scalar tweak over namespace public key, immutable derivation authority identity, destination domain, version, and path. For IDs 1 and 2, adding the same tweak to both Shamir shares must yield the public key `P + tweak*G`. Owner or policy changes do not silently change derivation identity. Publish SDK vectors covering paths, namespaces, schemes, and destinations.

10. **Implement ephemeral key-package reconstruction.** Re-derive only this side's namespace and account share, verify registered public metadata, construct the in-memory package, and erase secrets when evicted. Do not serialize FROST key packages merely for convenience. Public records supply the peer verification data; they do not contain signing shares.

11. **Implement fresh two-round signing.** Bind peer commitments to authenticated identities, exact message, derived key, participant set, and fresh attempt context. Consume nonce state once, including concurrent round-two attempts. Reject replayed, substituted, malformed, or inconsistent messages. Fresh entropy drives proof and signing nonces; no deterministic test source reaches production.

**Exit:** SDK-only public derivation matches worker derivation; native Ed25519 verification passes; multiple namespaces and paths work; one participant cannot sign; negative and nonce-lifecycle cases pass. Root-only storage remains contingent on the Phase 0 construction and deployment assumptions.

## Phase 2 Solana COMMIT and local end-to-end signing

**Goal:** demonstrate authorization by both ordinary accounts and programs.

12. **Implement minimal registry accounts.** Define enclave sets, controller namespaces, immutable request records, and response records. Pin scheme, derivation metadata, namespace public shares/key, identity keys, and registry/network identity. Use canonical account derivation and bounded serialization.

13. **Implement account-authorized requests.** Require the namespace controller's real Solana authorization and store the exact message hash, length, derivation path, destination domain, scheme, and request identifier. The prototype's approvals are append-only and permanent for those bytes; no implicit cancellation or one-time consumption promise is made.

14. **Implement program-authorized requests.** Provide a CPI entry point and a sample program using its properly checked authority PDA. Enforce namespace ownership and runtime signer authority. Record program upgrade control in the namespace's trust description; a caller-provided program ID is not proof of program authorization.

15. **Implement independent worker COMMIT checks.** Read actual account ownership, PDA identity, finalized request data, namespace registration, and exact delivered bytes through separately configured state providers. Coordinator-supplied evidence is a reference to validate, not authority. The core signs authorized bytes without a general business-policy transaction parser.

16. **Implement signature return and response validation.** Support an API result and an optional on-chain response that verifies the final signature under the derived public key and exact request message. A response record is an output cache, not a mechanism enforcing exactly-once destination execution. An untrusted relay cannot substitute a result.

17. **Land a real local Solana transfer.** Register a namespace, derive the destination account without signers, fund it on the local validator, authorize its transaction through an account and then the sample program, collect signatures, and submit. Verify balances and test duplicate messages with different valid FROST signatures. New blockhashes or changed nonce fields require new approvals.

**Exit:** both account and program paths execute a real derived-account transaction; altered payloads, wrong namespaces, false callers, forged responses, and ambiguous encodings fail. Exact-message retry behavior is measured rather than assumed.

## Phase 3 Separate service processes and developer API

**Goal:** make the local platform usable while preserving the trust boundaries.

18. **Split coordinator and workers into separate processes.** Define authenticated message routing, independent worker observation, cancellation of transport attempts, bounded resource use, and protocol instance separation. The coordinator has no root secret or authority to approve requests.

19. **Add development attestation and identity adapters.** Use reserved mock identities and test trust roots, binding fresh channel keys and proving possession. Enrolled participant identity is checked independently from transport endpoint names. Make production exclusion enforceable through build and registration policy.

20. **Expose the base SDK and API.** Provide namespace registration, public address derivation, account/program request helpers, payload delivery, result polling/subscription, signature verification, and receipt retrieval. Account/program authorization is sufficient initially; consumer login methods are deferred.

21. **Implement restart and fault behavior.** Kill either worker before and after each round and result publication. Replacement workers derive the same shares from their provisioning secret, abort interrupted attempts, and begin fresh attempts. Permanent loss of provisioning is a different failure and follows the declared loss policy.

22. **Implement trusted-state and negative-control behavior.** Make provider correctness/currentness assumptions explicit and use disjoint sets across domains. When adding namespace freezes, signer retirement, or incident controls, require current observations; immutable COMMIT does not exempt mutable controls from freshness. Define refusal and resumption behavior, and never infer consensus proof from matching RPC replies.

23. **Build the fast test loop and observability.** Run real MPC with injected chain views, LiteSVM program tests, a local validator integration tier, protocol fault injection, and non-secret diagnostics. Return attested receipts to clients without adding mandatory on-chain logging. Capture latency distributions and concurrency results.

**Exit:** two workers, relay, program, SDK, and response flow run locally; process loss changes neither keys nor addresses; tampering and fault tests pass. “No loss” refers to intact provisioning secrets and authorized restart, not surviving permanent loss of a signing domain.

## Phase 4 Real TEEs and persistent-key governance

**Goal:** run the base on real hardware without turning code upgrades into key rotation.

24. **Implement provider provisioning and identity adapters.** Supply A and B with independent stable application secrets; verify complete TDX/Nitro attestation chains and their actual hardware identities. Bind fresh channel keys to evidence and register stable signer identity keys under approved measurements.

25. **Build reproducible production images.** Pin dependencies, compiler, build inputs, and runtime configuration. Exclude mock attestation, insecure entropy, debug access, secret dumps, and test trust roots. Verify enrollment accepts only the intended measured artifacts.

26. **Implement independent upgrade governance.** Establish separately controlled, timelocked authorities over each domain's release of existing roots to new code. Include KMS migration/release rules and the registry's own upgrade authority. Preserve application secrets and existing namespace public keys across a tested authorized upgrade; reject an unauthorized release.

27. **Resolve memory cloning and nonce reuse.** Demonstrate the chosen platform's handling of paused, restarted, or cloned signing state and concurrently provisioned replicas. If a host can reuse one nonce state in multiple accepted transcripts, add a reviewed external fencing mechanism or decline the strict stateless deployment. Do not rely on single-instance operations as a security boundary.

28. **Validate current-state controls and outage behavior on hardware.** Test provider withholding/disagreement, negative controls during signing, configuration retirement, secret provisioning failure, and actual timer assumptions where needed. Repeated stale observations must not renew a freshness claim. Document restart bootstrap behavior.

29. **Run the complete hardware milestone and review.** Execute the Phase 2 account/program transfers through both providers, exercise restart and authorized upgrades, measure p50/p95/p99 and throughput, and obtain independent review of custom key derivation, proof handling, authorization, and provisioning. Record production restrictions and unresolved recovery guarantees.

**Exit:** native transactions succeed through both TEEs; existing addresses survive controlled instance/image replacement; real evidence validates the security assumptions. Public production funding remains gated by the chosen loss policy and the Phase 9 recovery/launch review.

## Phase 5 Two-party ECDSA backend

**Goal:** add the second signing scheme without forcing its setup into FROST's storage model.

30. **Select and license the ECDSA implementation.** Compare DKLS23 candidates and viable alternatives on audit scope, supported setup/derivation, complete fresh signing, concurrency, hardware threat assumptions, and commercial licensing. Pin the selected revision and record the choice; the algorithm name alone does not establish suitability.

31. **Define scheme-specific roots and optional setup blobs.** Implement protocol-supported key setup and account derivation. Domain-separate FROST and ECDSA material. If the selected protocol requires OT or other long-term setup, persist its complete encrypted package outside workers and bind it to authenticated registry metadata. Explicitly decide whether this satisfies the user's worker-stateless requirement; do not claim root-only reconstruction unless demonstrated.

32. **Implement fresh ECDSA signing and failures.** Expose only complete signing, ensure fresh protected randomness, bind the exact authorized payload/digest and hash recipe, normalize destination signatures, and distinguish transport interruptions from cryptographic incidents. Review prehash interfaces so arbitrary scalar inputs are not mistaken for validated message hashes.

33. **Unify request and SDK handling across schemes.** Add explicit suite/version selection, public derivation metadata, signature formats, and setup lifecycle without changing authority semantics. A path or root from one scheme cannot be reinterpreted under the other.

34. **Execute an EVM transaction on a local chain.** Compute the account address through the public SDK, authorize the exact signing payload with COMMIT, obtain a threshold signature, and verify transaction execution, nonce replay behavior, network separation, restart, and package integrity.

**Exit:** the same platform supports Ed25519 and ECDSA with declared scheme-specific setup. No ECDSA licensing, audit, or stateful-setup assumption is inherited from FROST.

## Phase 6 SESSION and bounded delegation

**Goal:** reuse restricted authority without an on-chain request for every operation.

35. **Define session capabilities and records.** Bind controller, namespace/account, delegate key, allowed operations/destinations, policy/control versions, and expiry. The registered policy chooses required authorization; a client cannot downgrade COMMIT to SESSION.

36. **Implement the expiry and revocation freshness rule.** Select provider quorum assumptions and validated timer or authenticated time sources; specify bootstrap, chain progress, cache deadlines, peer disagreement, and fail-closed behavior. Respect confirmed negative controls conservatively and define finalized resumption. Test stale views, repeated slots, restarts, and in-flight revocation races.

37. **Implement destination-aware session adapters.** Unlike exact-byte COMMIT, scoped sessions require both workers to parse the operation's meaning and construct its signing payload. Start with a reviewed Solana adapter and then EVM. Bind adapter versions and refuse arbitrary digests for semantically restricted grants.

38. **Implement delegate proof and safe concurrency.** Authenticate full requests, use fresh signing attempts, preserve destination operation identity across retries, and test replicas. Enforce stateless per-operation restrictions without advertising cumulative limits.

39. **Add durable accounting only for promised guarantees.** If an application requires a total budget or exclusive resource, implement atomic reservations and destination-specific settlement/release rules. Otherwise explicitly declare those limits unsupported. Signature issuance and cross-chain execution are not atomic.

**Exit:** delegated signing respects scope, expiry, and bounded revocation observation; no request can switch to a weaker authority path. Timers/provider trust and stateful guarantees are explicit.

## Phase 7 General signing access and SIMULATE

**Goal:** provide a Turnkey/Lit-style application access layer and add programmable simulation policy.

40. **Expand authentication and access APIs.** Add passkeys, service credentials, and OAuth-bound cryptographic identities in that order of validated need. Keep identity authentication separate from Solana authorization; an identity-provider token alone does not grant unrestricted signing. Document namespace ownership and credential revocation.

41. **Provide reusable application integration flows.** Package account/program requests, sessions, delegation, verification, and receipts into SDK examples. The access layer calls the same two-party signer; no new independent signing network is introduced. Keep root, scheme, destination, and policy choices explicit.

42. **Implement SIMULATE under a declared trust model.** Use a constrained authorization instruction, authenticated caller binding, pinned/governed program code, structured return data, and exact-intent commitments. Define how both workers agree on relevant state/evidence. `minContextSlot` is not an exact snapshot selector, and an attested executor alone does not authenticate chain inputs.

43. **Test composed policy requirements.** Support COMMIT, SESSION, SIMULATE, and required combinations through registered policy. Reject replayed/mismatched evidence, unsigned simulated signer claims, injected preparatory instructions, stale control versions, and unauthorized program upgrades. Simulation does not consume permissions or enforce aggregate budgets by itself.

**Exit:** application authentication, delegation, and programmable policies use the existing cryptographic base, with non-bypassable requirements and documented state trust.

## Phase 8 Agents and Hyperliquid integration

**Goal:** build trading and agent products on the finished authorization base.

44. **Implement generic agent delegation examples.** Demonstrate a restricted agent using SESSION, sensitive operations requiring COMMIT, and optional SIMULATE conditions. Show credential compromise boundaries and owner-controlled cancellation/freeze behavior.

45. **Implement Hyperliquid encoding and account registration.** Validate both signing schemes against official SDK vectors, retain owner control of master approval, and have the owner independently verify the derived agent address. Keep replaceable agent credentials distinct from persistent principal keys.

46. **Implement trading scope and destination boundaries.** Pin network and account context, default-deny actions, control destination nonces/expiry, and verify sub-account eligibility and credential scope. Do not describe adapter-pinned `vaultAddress` as universal destination-enforced isolation. Add dynamic risk/accounting sources only for guarantees the product promises.

47. **Validate testnet operations and outages.** Test orders, cancellations, replacement agents, owner emergency access, revoked sessions, and provider failure. Scheduled cancellation does not close positions. Measure the real authorized signing path before adopting latency targets.

**Exit:** Hyperliquid and agent use are integrations of the same base; their account, risk, replacement, and execution semantics are independently verified.

## Phase 9 Recovery and production readiness

**Goal:** implement the declared persistent-key loss policy and complete release review.

48. **Implement the selected root recovery mechanism.** For global provider secrets, enforce the peer-plus-cold-authority release structure, scope-wide governance, timelock, cancellation, replacement attestation, and independent authorization. Verify recovery cannot be performed by C alone. If per-owner recovery is required, design it explicitly rather than relabelling global root escrow.

49. **Test permanent provider loss and existing addresses.** Restore into the approved replacement domain, prove every affected namespace/account retains its public identity, and exercise unavailable counterpart/cold authority cases. No complete aggregate signing key is reconstructed. Document what happens when both provider secrets are permanently lost.

50. **Specify refresh and historical material limits.** Any address-preserving refresh for independent KDF roots needs an additional construction/state decision; it is not supplied by replacing a root secret. Test old recovery material and old signing quorums. Registry epochs cannot revoke an extracted historical threshold controlling the unchanged key.

51. **Complete external review and release checks.** Reconcile the implementation with architecture decisions, review custom cryptography and production provisioning, validate the loss policy and operational drills, publish the compromise matrix and measured service limits, and close unresolved production blockers. Update the reference architecture through an explicit revision after decisions are established.

**Exit:** the supported recovery and availability claims match tested mechanisms; a public release no longer relies on unreviewed injected shares, an assumed clone-resistant platform, or an unspecified secret-release path.

## Proposed workspace layout

```text
crates/
  pairkey-types/           Canonical wire types and contexts
  pairkey-core/            Authorization and protocol orchestration
  pairkey-frost/           Reviewed Ed25519 setup and signing wrapper
  pairkey-ecdsa/           Later backend and optional setup package
  pairkey-worker/          Provider, state, entropy, and transport adapters
  pairkey-coordinator/     Untrusted relay and result delivery
programs/
  pair-registry/           Identity, namespace, request, response, controls
  example-controller/     Program-authorized request demonstration
sdk/
  Public account derivation, request clients, sessions, verification
tests/
  Vectors, real MPC, LiteSVM, validator, process, and hardware suites
docs/
  Architecture decisions, backend notes, trust assumptions, operations
```

This is a proposed layout, not files to create before Phase 0 has resolved the construction. A narrow backend adapter should wrap established implementations; do not rewrite FROST or ECDSA to make interfaces symmetrical.

## Invariants to carry through the tasks

| ID | Invariant | Primary tasks |
|---|---|---|
| I01 | Both independent active domains are required for normal signatures | 3, 11, 18, 24, 32 |
| I02 | Registered public identity matches the reconstructed private shares | 3, 8, 9, 10, 31 |
| I03 | Scheme, namespace, derivation identity, domain, and path are unambiguous | 1, 9, 12, 33 |
| I04 | Account/program authority binds the exact requested operation | 4, 13, 14, 15, 37 |
| I05 | Nonce state is single-use across retries, concurrency, and supported platform behavior | 11, 21, 27, 32, 38 |
| I06 | Restart preserves keys only through intact authorized provisioning | 5, 6, 21, 24, 49 |
| I07 | Mutable negative controls and sessions use sufficiently current observations | 22, 28, 36, 43 |
| I08 | Destination execution semantics determine exact-operation replay safety | 4, 17, 34, 38, 47 |
| I09 | Upgrades cannot release both domains' existing secrets through one administrative compromise | 6, 24, 26, 48 |
| I10 | Development attestation, entropy, and diagnostics do not enter production | 19, 23, 25, 29 |
| I11 | A caller cannot downgrade registered policy requirements | 35, 37, 43 |
| I12 | Recovery, historical compromise, and aggregate-limit claims match implemented mechanisms | 6, 39, 46, 48, 49, 50, 51 |

## Implementation model recommendation

Use **GPT-6.1 Sol with High reasoning** for day-to-day implementation: bounded Rust tasks, Solana programs, SDK work, integration tests, and service wiring. Use **GPT-6 Astra with Extra High reasoning** for the FROST construction, proof and nonce review, provisioning/upgrade threat model, ECDSA selection, and recovery design. These are workload-based recommendations rather than PairKey-specific benchmark results.

If choosing one model and prioritizing depth over time/cost, choose **GPT-6 Astra with Extra High reasoning**. If choosing one model for sustained implementation with a practical time/cost balance, choose **GPT-6.1 Sol with High reasoning**, and preserve the independent specialist review gates.

Official OpenAI documentation recommends GPT-6.1 Sol for complex coding and sustained work, and Astra for the most demanding analysis. Higher reasoning effort is appropriate for difficult work with multiple steps and tradeoffs; availability depends on the account and client. [Models in Codex](https://learn.chatgpt.com/docs/models), [model selection guidance](https://developers.openai.com/api/docs/guides/model-selection)

| Task class | Proposed model and effort |
|---|---|
| Phase 0 derivation, trust model, and key lifecycle decisions | GPT-6 Astra, Extra High |
| Registry, SDK, worker, relay, and focused implementation tasks | GPT-6.1 Sol, High |
| Nonce/cloning, ECDSA composition, and recovery review | GPT-6 Astra, Extra High |
| Small mechanical edits after interfaces and tests are established | GPT-6.1 Sol at lower effort as appropriate |

Keep each implementation prompt tied to task numbers, invariants, dependencies, and exit evidence. A second model review is useful evidence, but neither model replaces a cryptographic review or hardware validation. No model switching, subagent delegation, or implementation run is performed by this recommendation.

## Source boundaries for the first gate

The Zcash Foundation repository describes its NCC audit of v0.6.0, covering key generation and signing. Its current constructor permits explicit key-package inputs. Neither fact establishes audit coverage of PairKey's KDF-derived shares, custom possession ceremony, or public account tweak. [FROST audit scope](https://github.com/ZcashFoundation/frost#ncc-audit), [KeyPackage constructor](https://docs.rs/frost-core/latest/frost_core/keys/struct.KeyPackage.html), [FROST license](https://github.com/ZcashFoundation/frost/blob/main/LICENCE)

RFC 9591 requires secure randomness and single-use signing nonces. Derivation is a separate integration decision. [FROST specification](https://datatracker.ietf.org/doc/html/rfc9591)

Solana replay behavior must be tested against the selected validator/runtime, including identical messages with different valid signatures. Agave includes message-hash status checks; the plan does not assume that signature uniqueness alone defines replay safety. [Agave runtime](https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank.rs)
