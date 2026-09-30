# Minimal Mode 2 derived key generation specification

Draft v1, 2026-10-11. Proposed contract for PairKey and Silence review; not an
implementation or a claim that O1 is closed. This refines Mode 2 in
[DERIVED-SHARES-VIA-MIGRATION.md](DERIVED-SHARES-VIA-MIGRATION.md) using the
[v3 contract qualifications](CONSTRUCTOR-SECURITY-CONTRACT.md#reconciliation-of-claudes-migration-and-pool-review).

Use root-derived additive contributions, a single native creation attempt per
wallet ID, and ordinary expected-key migration for recovery. Keep complete native
packages in RAM. There is no OT pool, custom share conversion or seed splice.
Creation failures may cost a wallet ID; preserving an interrupted native
transcript is deliberately outside this minimal design.

## 1. Fixed scope

- Two enrolled parties, threshold two, ranks zero; at most one statically
  malicious participant. The peer is not assumed to follow its root KDF.
- Retain the existing contribution and identity KDFs. Derive only the local
  additive contribution from the root; use fresh, independent OS randomness for
  every native creation, recovery and signing invocation.
- Keep Silence's pinned dependencies, curve, security parameters, OT/PPRF/RVOLE
  algorithms and signing checks unchanged. Initial derived-key generation needs
  a reviewed upstream API; it is not available merely by changing a wrapper
  argument. This draft authorizes no native patch or dependency upgrade.
- Apply only to new, never-disclosed contributions. Existing wallet records
  and addresses are not reinterpreted. Disclosure includes legacy Hello/Describe,
  failed ceremonies and another enrollment using the same root/role/key ID.
- Assume an authoritative, durable local journal and one cooperating execution
  authority per root/role namespace. Hostile snapshot rollback and uncoordinated
  copies of the same root are outside this contract.

## 2. Native operations

Prefer separate entry points or explicit operation types, not a caller-controlled
optional expected key on a generic retry path:

| Operation | Inputs beyond authenticated setup, fresh seed and relay | Required output and checks |
|---|---|---|
| `InitialDerivedKeygen` — proposed upstream API | Local root-derived additive scalar; no expected public key | Use the scalar as the polynomial constant and fresh remaining native randomness. Retain native commitment-before-reveal and proof/share checks; reject invalid/nontriviality failures. Derive Q inside the protocol and return a complete native keyshare. |
| `RecoverRecordedKey` — existing migration path | Local root-derived additive scalar, required recorded Q and chain code | Run native migration with its expected-Q and chain-code agreement checks; return a fresh complete native package for that same wallet. |

**Proposed chain-code policy:** initial mode uses native DKG's existing
chain-code generation, and recovery uses the recorded result. Initial mode must
therefore separate the constant-term override from migration's expected-key and
supplied-chain-code controls. No new chain-code hash is introduced. This is a
new-wallet policy, not compatibility with the current experimental deterministic
chain code. It requires Silence's API/security review.

Both peers authenticate the exact operation context before native execution:
protocol/configuration digest, record/KDF/chain-code policy versions, ordered
identities and roles, threshold/ranks, wallet ID, fresh attempt ID, and operation
kind. Recovery also binds the immutable public record digest. Derive native
InstanceId from a canonical, domain-separated digest of that context. Never
fall back from recovery to initial mode on an error or missing record.

## 3. Durable public state

The reservation key is the **local root namespace, role and wallet ID**. Changing
peer, ceremony ID or protocol version must not bypass an existing reservation,
because those changes do not make the root-derived contribution fresh.

| State | Durable contents | Allowed action |
|---|---|---|
| `UNSEEN` | Trusted journal establishes no reservation or prior disclosure | Start one initial attempt. Mere absence after storage loss is insufficient. |
| `RESERVED` | Creation context and attempt ID; written before native invocation or contribution disclosure | Run that one live initial invocation. Never launch a second invocation for this wallet ID. |
| `PREPARED` | Immutable candidate public record and own identity endorsement, saved after native success | Exchange/retransmit only final-record endorsements; no new native creation or signing. |
| `ACTIVE` | Candidate record plus both valid identity endorsements | Recover and sign subject to ordinary incident policy. |
| `RETIRED` | Wallet ID and terminal retirement marker | Refuse creation, recovery and signing for that ID. |

The public record contains wallet/creation IDs, ordered identities and roles,
protocol/configuration and format versions, threshold/ranks, Q and chain code.
It contains no private share, protocol RNG seed, OT seed or zeta seed. It does
not prescribe coordinates or public shares, which native recovery changes.
This needs a new record schema; the existing fixed-coordinate WalletRecord is
not silently reused.

Transitions are serialized under the existing authority model and durably
written with file and directory synchronization. A partial or contradictory
journal entry fails closed. Endorsements sign a domain-separated digest of the
entire record. An honest worker endorses exactly one candidate per reservation,
only after native success and durable preparation. No endorsement is released
before that preparation is durable.

## 4. First creation

1. Verify enrollment, versions, root-derived local identity, incident policy,
   trusted journal continuity and eligibility of the contribution namespace.
   Agree the creation context without disclosing contribution points.
2. Atomically reserve the wallet ID. Duplicate or concurrent requests cannot
   start a second invocation. Exchange authenticated readiness for that exact
   context only after reservation; enter native creation only after both are ready.
3. Run `InitialDerivedKeygen` once with fresh randomness. Do not expose a
   contribution-bearing Hello outside native commitment ordering.
4. After successful native completion, check output metadata and nonidentity Q,
   obtain its chain code, then durably store `PREPARED` and the local endorsement.
   The returned secret package is provisional RAM state and cannot yet sign.
5. Exchange endorsements of the exact candidate record. Reject a mismatching
   record; do not select a winner, overwrite the candidate or restart creation.
6. After obtaining both valid endorsements, durably activate the certificate.
   Only then expose a usable wallet/address or allow signing. An honest peer
   may still be `PREPARED` because an endorsement was lost; resend the same
   public certificate so it can activate. This guarantees neither simultaneous
   activation nor availability against a refusing peer.

## 5. Abort and retry rules

| Event | Required behavior |
|---|---|
| Preflight fails before reservation, without disclosure | Fix the preflight issue and try again; no native invocation has started. |
| Any failure, cancellation, timeout or restart in `RESERVED` | Retire the ID and discard provisional secrets. This includes uncertainty about whether R2 was revealed and failure before the first native message. Use a fresh eligible wallet ID for a new wallet. |
| Native succeeds but persisting `PREPARED` fails | No endorsement or usable address may be released. Remain blocked on storage failure; after recovery retire the reserved ID. Do not rerun initial mode. |
| Timeout or restart in `PREPARED` | Preserve the candidate and endorsement. Resend only that exact public exchange. If RAM secrets were lost, wait for activation, then recover using recorded Q. |
| Conflicting candidate/endorsement | Refuse activation and apply the existing attribution/incident policy. Never replace the candidate. An ordinary timeout is not evidence of cheating. |
| Duplicate completion request in `ACTIVE` | Return/resend the identical public certificate. No new initial invocation. |
| Request for a `RETIRED` ID | Refuse permanently under this root/role namespace. A new attempt ID, peer or version does not reopen it. |

There is no native transcript resume or deterministic RNG replay. `PREPARED`
does not automatically expire into `RETIRED`: the peer may already possess both
endorsements and be active. Keep its public state and allow exact endorsement
delivery. It may remain unavailable indefinitely if the peer refuses to finish.

## 6. Recovery and signing

Recovery requires the correct local root, a trusted `ACTIVE` public certificate,
and the applicable durable reservation/incident state. Roots-only **secret**
persistence does not mean roots-only recovery: public metadata must survive or
be restored with verified integrity and continuity. A missing record or an
unknown ledger history is not permission to run initial mode again. Do not
accept a peer's unsigned proposed Q as a replacement record.

Agree a fresh recovery context bound to the same public certificate. Run
ordinary migration with the local derived scalar, recorded Q and recorded chain
code, using fresh private randomness. Validate the complete output against the
record before use. Keep the whole package together; do not replace its native
seeds, coordinates or final session ID. Peers agree that recovery completed for
the same attempt before using that package generation for signing.

A restart or cache eviction discards the RAM package, not the wallet record.
Rebuild it through expected-key migration. In a warm-cache implementation,
serialize recovery/signing per wallet and require both peers to agree on the
package generation; otherwise discard and recover together. Cache reuse is
optional and needs that coordination rather than unilateral replacement.

On recovery/signing failure, discard the affected package and apply the existing
burn/quarantine/freeze policy and concurrent-session cutoff. A fresh recovery
attempt is allowed only if that policy permits it. Keep the original public
record; do not retire an established wallet merely for a transport failure,
rewrite its Q or return it to initial mode. Rebuilding from unchanged roots does
not claim proactive protection against eventual compromise of both roots.

## 7. Minimum acceptance checks

- Race two initial requests for one namespace: at most one native invocation.
- Crash at reservation, native completion and every preparation/activation
  write: no new initial run after reservation and no endorsement before durable
  preparation.
- Abort after R2 disclosure, then retry with a changed corrupt contribution:
  the retry is refused before native execution.
- Drop final endorsements or restart a prepared peer: finish only the same
  public record; recover after activation without reopening initial mode.
- Reject initial/recovery context mismatch, legacy-disclosed contributions,
  retired IDs and attempts to bypass reservations through another peer/version.
- From an active record, recover with fresh randomness: preserve Q/chain code,
  validate the fresh package and independently verify signatures and agreed
  public child keys. Reject wrong Q/chain code and forbid initial-mode fallback.
- Storage loss/rollback uncertainty and incident restrictions fail closed;
  recovery cannot clear an incident or revive retired state.

Silence must confirm the proposed native API, root-input/commitment composition,
chain-code policy, abort semantics and audit coverage before implementation.
O1, the remaining public child-key part of O2, O5 and O6 stay open; the removed
constructor and wallet-independent pool boundaries are not claims of proof.
The concrete native OT realization remains an upstream question. The 2026 paper
is supplementary only; no Silence parameter change is proposed.
