# OT pool review coverage

Draft review note, 2026-10-11, written by the Claude reviewer at the project owner's request. It
applies only if a wallet-independent OT pool is retained, that is option O-D of
[DECISION-KEYGEN-OT-SCOPE.md](DECISION-KEYGEN-OT-SCOPE.md) or a hybrid that takes the share from
native key generation and the OT seeds from a pool. The decision record recommends neither. This
note records what an internal review of the pool could establish and what it could not. Native pin
`af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`; theorem source DKLs23, eprint 2023/765. No exploit
is asserted.

Results of the review performed against this plan: [OT-POOL-REVIEW.md](OT-POOL-REVIEW.md).

## 1. Framing

The paper's own deployment model already separates OT setup from keys and messages.

- Section 8.2, stated as the assumption of the cost analysis: "we assume that setup for endemic OT
  extension is performed once per pair of parties, and reused thereafter in all instances of the
  protocol realizing F_EOTE among those two parties".
- Section 8.4: the one-time initialization of the signing protocol runs the key generation
  functionality and "two instances of F_RVOLE per pair of parties", and each party commits and
  releases a seed for the zero-sharing functionality.
- Section 3.1: the zero-sharing seeds "can be reused indefinitely".

Silence's implementation stores the OT seeds and the zero seed inside each keyshare and reuses them
for every signature under that key. PairKey's pool prepares the same material per pair of parties,
independent of any wallet, and consumes each entry once. Neither per-pair preparation nor single use
is a conceptual departure from the paper. What the paper does not supply is a proof for any
particular session-id and binding scheme, and the Trail of Bits review covered Silence's
per-keyshare arrangement only. A review of the pool is therefore a code-equivalence, binding and
single-use review against Silence's code, not a correspondence check against the paper.

## 2. Pool components

Paths are relative to `experiments/silence-dkls23`; native paths are relative to
`.local/silence-dkls23/sources/dkls23-af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src`.

| Component | Code |
|---|---|
| Coin flip for the zero seed | `src/pool_worker.rs:85-122`: commit over the setup digest, role and coin; reveal; verify; combine under `pairkey/pool/zero-seed/v1` |
| Base OT, both directions | `src/pool_worker.rs:125-141`: `EndemicOTReceiver::new` with `base_ot_sid(role, peer)`, `EndemicOTSender::process` with `base_ot_sid(peer, role)`, OS randomness |
| PPRF expansion | `src/pool_worker.rs:143-176`: `build_pprf` with `pprf_sid(role, peer)`, `eval_pprf` with `pprf_sid(peer, role)` |
| Session ids and digests | `src/pool.rs:91-130`: input digest over peers, configuration, boots and entry, labelled session ids; `273-275` completed digest; `227-248` consumption digest and package sid |
| Reservation, ownership, single use | `src/pool.rs:395-432` package checkpoint; `497-533` reserve before validation; tombstones; cross-process locks |
| Transport | `src/wire.rs:246-343`: HKDF-derived keys, AEAD with context, sender and label as associated data |
| Consumption into signing | `src/pool_worker.rs:365-437`: reserve, agreement check, package, instance id from the request digest, fresh seed, `sign::run` |
| Keyshare assembly | `patches/research-keyshare.rs` today; a byte splice in the hybrid |

## 3. Coverage matrix

| Item | Pool | Native reference | Method | Outcome |
|---|---|---|---|---|
| Base OT | exported EndemicOT calls per entry | `keygen/dkg.rs:296-300` and `446-450`: the same calls in rounds OT1 and R3 | side-by-side diff; same function, fresh randomness and a distinct session id give the same distribution; `endemic_ot.rs` omits the sid from `h_function_2` in both | closable |
| PPRF | `build_pprf`, `eval_pprf` with proof checks | `keygen/dkg.rs:463-467`, `539-543` | diff; test that a corrupted proof aborts and quarantines | closable |
| Session ids | hash of a label, the input digest, receiver and sender | `get_base_ot_session_id` and `get_all_but_one_session_id` over the final session id | prove uniqueness over entries, boots and wallets; same value on both sides; domain labels distinct; relate to TOB-SILA-5, the finding on one session id for all-but-one OT | closable |
| Zero seed | two committed coins combined | `keygen/dkg.rs:476-480`: the lower-indexed party samples it alone | for two parties the zero shares are negatives of each other, `sign/dsg.rs:876-914`, so secrecy from the peer is not a property; required properties are fixed before signing and indexed per signature by `digest_i`, the hash of both round-1 session ids and nonce commitments (`sign/dsg.rs:169-183`, `234`) | closable, low stakes |
| Seed-to-role mapping | sender seed from the base OT where the party was EndemicOT sender; sender seed feeds the RVOLE receiver | `sign/dsg.rs:1061-1075` and `rvole.rs` | a swapped-seed test must fail the RVOLE check | closable |
| Consumption binding | package sid into the keyshare final session id, then `final_session_id = SHA256(sid_0, sid_1, pkg)`, then `mta_session_id`, then SoftSpoken expansion, the correlation check, the gadget, theta and mu | `sign/dsg.rs:162-167`, `192`, `289`, `1061-1075`; `soft_spoken_ot.rs`; `rvole.rs` | trace, plus tests that a request disagreement retires the entry without using it (the reservation precedes agreement by design) and that both parties' agreement on the final session id and on `digest_i` is enforced (`sign/dsg.rs:283`, `368`, `393`); the check at `139-152` concerns party ids and there is no duplicate round-1 session-id check | closed, see OT-POOL-REVIEW.md |
| Single use and ownership | reserve removes before validation; RAM only; tombstones; locks | none | existing schedules and process-race suites; add crash at every step and double reserve | closable within the tested model; VM snapshot restore stays open |
| Transport | custom channel | native signed and encrypted messages | with attested TEEs, replace by the attested link; otherwise review key derivation, nonce handling, associated data and replay across entries | closable |
| Randomness | fresh seed per entry and per signing run; OS randomness in OT | protocol RNG from a fresh seed | no RNG state shared across entries or between OT and PPRF | closable |
| Keyshare assembly | constructor or splice | native layout in `keygen/keyshare/details.rs` | invariant list; byte-identical differential test against a native keyshare | closable |
| Failure attribution | pool errors | signing attribution audit in [SECURITY-REVIEW.md](SECURITY-REVIEW.md) | extend the exhaustive match to pool errors; quarantine per TOB-SILA-12 | closable |
| Zeroization | pool buffers and transcripts | inventory in [SECURITY-REVIEW.md](SECURITY-REVIEW.md) | unchanged limits | documented |

## 4. What the review cannot close

- Whether the compiled SoftSpoken plus Masny-Rindal stack realizes Functionality 5.1 with the
  ordering that Claim 6.7 relies on. Trail of Bits recorded the combination question as
  TOB-SILA-13, "Combining aspects of different protocols has unclear security implications".
  Silence's own flow shares it.
- The 2026/976 question about the correlation-check dimension. Upstream reference only.
- The audit-to-pin gap.
- Rollback of a confidential VM snapshot, which restores RAM and therefore the pool.

## 5. Tests to add

- Side-by-side fixture: run native DKG and the pool preprocessing from the same seeds through
  instrumented calls and compare the OT seed material byte for byte where the API allows.
- Corrupted PPRF proof, truncated reply and swapped seeds each fail at the intended check and
  trigger the intended quarantine scope.
- Session-id collision search across entries, boots and two wallets; assert all distinct.
- Request disagreement between parties fails before any entry is consumed, and the entry remains
  available.
- Crash at every step of reservation, checkpoint and consumption on either side; no entry is ever
  used twice and no entry is lost silently.
- Agreement on the final session id and on `digest_i` is enforced by native rounds 2 and 3; document that no duplicate round-1 session-id check exists and that freshness rests on each party's own round-1 id.
- Byte-identical splice test against a native keyshare.

## 6. Bounded conclusion

What such a review can honestly state: the pool produces OT material distributed as native DKG's,
bound uniquely to one authenticated request, consumed at most once under the tested failure model.
What it cannot state: that the compiled OT stack realizes Functionality 5.1, or that the parameter
question raised in 2026/976 is settled. Both are open for Silence's flow and PairKey's alike. The
statement is about custom code; option O-C' avoids having to make it.

## 7. TEE deployment notes

- An attested channel between the two enclaves can replace the custom setup channel entirely.
- Every open proof gap here needs an actively malicious peer. In a two-enclave deployment that
  requires a defeated attestation chain or a broken image, while the common enclave failure is loss
  of confidentiality, which exploits none of them. That is a risk-acceptance statement worth
  recording, not a reason to lower the design target below malicious security.
- A snapshot of a confidential VM restores its memory, so a RAM-only pool does not by itself solve
  rollback. Single use must be enforced by state that a restored snapshot cannot revive, or the
  deployment must exclude snapshots.
