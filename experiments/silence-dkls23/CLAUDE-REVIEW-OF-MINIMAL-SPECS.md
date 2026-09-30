# Claude review of the two minimal specifications

2026-10-11. Reviewed [MODE-2-MINIMAL-SPEC.md](MODE-2-MINIMAL-SPEC.md) and
[OT-POOL-MINIMAL-REVIEW-SPEC.md](OT-POOL-MINIMAL-REVIEW-SPEC.md) against the pinned native source
`af5ada2a`, the experiment tree at `1a507bc`, and a five-case test run in a scratch copy of the
patched native crate (section 4). Also records which of Astra's corrections in `356ac2c` I accept
and what changed in my notes as a result. No exploit asserted; no code, parameter or dependency
change proposed.

## 1. Astra's corrections, checked against the code

All accepted. Each was verified before my notes were changed.

| Correction | Code | Change made |
|---|---|---|
| Zeta is indexed by `digest_i`, not the final session id | `sign/dsg.rs:169-183` computes `digest_i`; line 234 passes it to `get_zeta_i` | Pool review 2.4, 2.6 and the coverage rows corrected |
| The cited duplicate check concerns party ids | `sign/dsg.rs:139-152`; session-id agreement is enforced at 283, 368 and 393; no duplicate round-1 session-id check exists | Coverage row and test list corrected |
| Local OT1 is generated before the expected-key check | `keygen/dkg.rs:296-330` feeds OT1 with round 2; the check at 411-419 precedes processing of the peer's OT1 at 423 | Derived-shares table and the TL;DR wording corrected |
| Withholding a reveal is a timeout burn without quarantine | `src/pool_worker.rs:510` times the command out as a burn; `src/lifecycle.rs:302` publishes no incident for a burn; the driver asserts no incident for `setup-timeout` | Pool review 2.4 and finding 3 corrected |
| Neither registration mode closes O1 | Argument only; the simulator, prior disclosures, retries and concurrency remain to be written | Derived-shares 3.3 and 4.4 softened |
| Mode 2 needs reservation and retirement, not an optional field | `key_refresh_data` gates eight places in `run_inner`: 191, 209, 333, 388, 417, 509, 571, 584 | Derived-shares 4.2 to 4.5 rewritten to a typed operation and the spec's state machine |
| A pool also hides cold-wallet first-signature latency | Comparison of flights in the decision record | Decision record section 11 qualified |
| Closures are implementation evidence, not composition | Agreed | Pool review verdict, finding 8 and conclusion reworded |
| Test disposition | Astra inspected, did not rerun | Test hardened as asked, see section 4; still not independently rerun |

## 2. MODE-2-MINIMAL-SPEC.md

**Verdict.** Sound and consistent with the pinned code. I would adopt it as the Mode 2 contract and
the template for Mode 1's lifecycle, with the additions below. Nothing in it contradicts the source.

**Confirmed against the code.**
- Separate operations are necessary, not a convenience. The refresh flag drives input validation,
  the constant term, the chain-code source, lost-party handling, the expected-key check and the
  chain-code agreement in one `run_inner` path. Initial derived keygen needs the constant-term
  override at line 209 together with the non-refresh chain-code path at lines 333 to 337 and 596
  to 601, and without the check at 417. The spec's section 2 says exactly this.
- The proposed chain-code policy matches the code: the non-refresh path samples a random chain-code
  session id per party and hashes them all; the refresh path takes a supplied value and requires
  equality. Recovery through migration therefore preserves a recorded chain code.
- Recovery changes coordinates and public shares because native key generation draws coordinates
  at random, `keygen/dkg.rs:213`. The record schema must not fix them, as the spec says.
- Step 3 of the first creation requires that no contribution-bearing message leaves the native
  commitment ordering. Today `Hello` carries the contribution, `src/lib.rs:142-234`, and `Describe`
  returns it, so both change under this spec.

**Findings and requested additions.**
1. **Package-generation agreement is incident safety.** Case 5 in section 4: two valid sharings of
   the same key held by different peers fail native consistency check 3, which the lifecycle maps to
   a configuration freeze. Section 6's rule that peers agree on the package generation must be
   enforced before `sign::run`, and section 7 should test that an honest restart followed by a
   unilateral recovery is refused before native signing and raises no incident. Must have.
2. **Retire-on-any-failure in `RESERVED` is safe but costly.** A transient failure in the readiness
   exchange, before any native message, burns a wallet id. The honest party knows whether it sent its
   own round-2 reveal, and the wrapper can recognise outbound message ids, as the test probe in
   `src/pool_worker.rs:424-431` already does. A documented option: one retry under the same
   reservation only if the local round-2 message was never sent; otherwise retire. Decision for
   PairKey and Silence; the strict rule is acceptable.
3. **`PREPARED` cleanup.** A party stuck in `PREPARED` because the peer retired can never finish.
   An authenticated retirement notice from the peer could move it to `RETIRED`. Retirement only
   reduces availability, so the notice cannot be abused to reopen anything.
4. **Repeated first-run failures.** Each costs a wallet id and nothing else. Repeated failures with
   the same peer should feed the incident or rate-limit policy, even though a single timeout is not
   evidence of cheating.
5. **Mode 1 under the same machine.** Mode 1 is the only implementable path until Silence ships the
   operation. Give it the same reservation before the commitment is sent and the same retirement
   after a local reveal, so the two modes are interchangeable later and the journal rules are
   written once.
6. **Recovery context.** Include the package generation id used for cache agreement in the recovery
   context, beside the record digest, so the agreement in finding 1 is authenticated rather than
   assumed.
7. **Acceptance checks to add.** One-sided native success leaves one peer `PREPARED` and the other
   `RETIRED` with no usable address on either side; a recovered pair whose generations differ is
   refused before signing.

## 3. OT-POOL-MINIMAL-REVIEW-SPEC.md

**Verdict.** Accurate. Every code statement in sections 2 and 3 matches the source, including the
`digest_i` and party-id points. Adopt it as the exit criteria for any pool candidate.

**Additions.**
1. **Freeze what the code already fixes.** Entry life of 300 seconds, capacity 2, generation budget
   1024, the setup-id ledger written before the first OT message, and the channel keyed by the input
   digest. These belong in section 1.
2. **Map the evidence package to existing artifacts.** Driver schedules with asserted diagnostics and
   incident expectations, `src/pool_driver.rs:725-780`; the pool and reservation unit tests named in
   [OT-POOL-REVIEW.md](OT-POOL-REVIEW.md) section 2.7; and the five scratch cases in section 4 here.
   What is still missing against section 4 of the spec: in-process assertions of incident effects,
   which today only the driver makes, and a systematic context-mutation matrix beyond
   `setup_inputs_exclude_wallet_and_payload_and_bind_roles_generation_config`.
3. **Zero seed is bound into the package id.** Both coins are in the completed transcript, so the
   package id and the MtA session ids commit to the seed even though `digest_i` does not. Worth one
   sentence in section 2.
4. **Error classes with evidence.** Mixed or one-sided OT material: `AbortProtocolAndBanParty` on
   both sides. Mismatched zero seed or share generation: `FailedCheck` on both sides. These map to
   quarantine and freeze respectively under `src/lifecycle.rs:108-130`.
5. **Identity splice.** Case 4 is a byte-level identity splice preserving all native fields except
   the OT region, and it signs; a one-sided splice is rejected. A splice-function identity test, byte
   for byte, applies once a hybrid splice function exists.

## 4. Evidence, version 3

Scratch copy of the patched native crate, `cargo test --offline`, five cases, exactly two bounded
outcomes each, typed negative assertions, verified signatures on positives, fresh material per case.
Source and log in `review-evidence/`. Not independently rerun by Astra.

```
case 1: layouts agree outside x_i/big_s/s_i; 2 verified signatures from rebuilt keyshares
case 2 (mixed OT material): [Err(AbortProtocolAndBanParty(1)), Err(AbortProtocolAndBanParty(0))]
case 3 (zero seed mismatch): [Err(FailedCheck("Consistency check 3 failed")), Err(FailedCheck("Consistency check 3 failed"))]
case 4 (identity splice, consistent seeds both sides): 2 verified signatures
case 4b (one-sided splice): [Err(AbortProtocolAndBanParty(1)), Err(AbortProtocolAndBanParty(0))]
case 5 (mismatched share generations): [Err(FailedCheck("Consistency check 3 failed")), Err(FailedCheck("Consistency check 3 failed"))]
```

## 5. Paste-ready TL;DR for Astra

Reviewed MODE-2-MINIMAL-SPEC.md and OT-POOL-MINIMAL-REVIEW-SPEC.md against the pin; both are
consistent with the code and I adopt them. All corrections in 356ac2c accepted and folded into my
notes with line references: zeta uses digest_i; the 139-152 check is party ids and no duplicate
round-1 sid check exists; local OT1 precedes the expected-key check; a withheld reveal is a timeout
burn without quarantine; neither mode closes O1; Mode 2 is a typed operation because the refresh
flag gates eight places in run_inner. New evidence, five cases, typed and bounded: rebuilt and
identity-spliced keyshares sign with verified signatures; mixed or one-sided OT material gives
AbortProtocolAndBanParty on both sides; mismatched zero seed and mismatched share generations give
FailedCheck check 3 on both sides. Requested additions: generation agreement before sign::run as an
incident-safety rule with a test, since the freeze mapping would turn an honest restart into an
incident; an optional retry when the local round-2 reveal was never sent; authenticated retirement
notices for stuck PREPARED peers; repeated first-run failures into the incident policy; Mode 1 under
the same state machine; the generation id in the recovery context. For the pool spec: freeze TTL,
capacity, budget and ledger; map the evidence package to existing driver and unit tests; note the
zero seed is bound through the completed transcript; record the error classes above.
