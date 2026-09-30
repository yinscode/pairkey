# OT material rules: status at HEAD, remediation, rollback and randomness

2026-10-11. Applies to any design that holds OT seeds outside a single native keyshare's lifetime:
the Spike C pool, the shared-setup donor design, and a warm cache of native packages. Status is
assessed against the code at `73f318a`, which is the code at HEAD, using the evidence in
[OT-POOL-REVIEW.md](OT-POOL-REVIEW.md), [O3-O4-DEEP-DIVE.md](O3-O4-DEEP-DIVE.md) and
[CLAUDE-CO-REVIEW-SHARED-SETUP.md](CLAUDE-CO-REVIEW-SHARED-SETUP.md). "Good" means the rule is
implemented and evidenced; it is not a security certification.

## 1. Rules

| Rule | Why | If broken | Status at HEAD | Remediation or follow-up |
|---|---|---|---|---|
| Fresh session id for every extension: a fresh OS seed for every `sign::run`, never resumed, replayed, cached, or derived from a root or counter | the receiver's public matrix is the seed expansion XOR its secret choices; a repeated id cancels the expansion | the peer learns the XOR of your secret inputs across sessions, and the nonce repeats: fatal, even against a passive peer | Good: `fresh()` per attempt at `src/pool_worker.rs:434`, failed attempts abandoned, no resume path | Hedge the seed with the request context (section 3); journal instance ids on both sides; forbid snapshot and restore of signer processes (section 2); add a replayed-seed fault test asserting refusal |
| Seed roles exactly as native: sender seed to the MtA receiver, receiver seed to the MtA sender, both from one base-OT instance | the correlation holds only across one instance | inconsistent material ends in a peer ban; a consistent swap is harmless | Good: `Material::new` and `other_mut(1 - party)` match native; mixed and one-sided material rejected with `AbortProtocolAndBanParty` in the evidence tests | Keep the layout test in the suite as a regression guard |
| Fresh, independent base-OT randomness from the OS, never shared between entries or between OT and PPRF | base-OT secrecy | correlation secret exposed | Good: `OsRng` in both EndemicOT roles, `fresh()` for coins and the per-boot DH key | None beyond the randomness measures in section 3 |
| Every validation native performs: message decode, proof check in `eval_pprf`, agreement on the completed transcript | the only checks that catch a deviating peer | malformed material accepted | Good: same calls and same error mapping as native rounds OT1 and R3; driver schedules assert each diagnostic | None; keep the schedules |
| Unique, bound session ids: entry, boots, peers and configuration into the setup ids; consumption, including attempt, into the package id and so into the native session ids | separates entries, wallets and attempts | cross-context confusion or replay | Good: structural uniqueness argument in the pool review; channel keyed by the context; 20 mutation cases rejected | Document the argument as the uniqueness claim; a collision search proves nothing |
| Single use, or reuse only under unique session ids; retire the material after any attributable failure; quarantine the peer across every wallet sharing it; cut concurrent sessions | a selective-abort guess is visible only when wrong, so accumulation must stop at the first visible failure | leakage accumulates against one correlation secret | Partly good: single use enforced by reservation and ledger; attributable failures quarantine the pair-scoped identity and destroy the generation; concurrent cutoff is moot because the research worker is sequential; no rate limiting of unattributed aborts | Implement concurrent-session cutoff before any concurrent design; add a rotation period and an abort-cluster trigger for shared material; rate-limit timeouts |
| Masking seed fixed before signing | the masks must be a function of the session only | mask mismatch fails native check 3, a configuration freeze | Good: the coin flip completes in preprocessing, before any consumption | For a native donor or migration route, take the seed from native output and drop the coin flip |
| Material secrecy: seeds zeroized, never both parties' seeds on one host, no snapshot or rollback of the RAM or disk that holds them or their journals | the seeds are the key to the multiplication transcripts; journals carry quarantine and reservation state | a restored snapshot revives consumed material, replays randomness and forgets quarantines | Open: zeroization is best effort as inventoried in SECURITY-REVIEW.md; the harnesses hold both roots in one test process by design; snapshot and rollback protection is a listed production blocker | Section 2 |

## 2. Does strictly disallowing snapshot and restore resolve the last rule?

Mostly, if the prohibition is enforced by the platform rather than by policy. The rule covers three
different hazards, and the prohibition closes them unevenly:

- **Replayed randomness.** A restored snapshot replays the kernel and process RNG state. Modern Linux
  reseeds its CRNG when the hypervisor exposes a VM generation id that changes on restore; confirm
  this in the deployment kernel and hypervisor, because without it `OsRng` after a restore repeats.
  The seed hedge in section 3 makes the application safe even when entropy repeats, because a
  different message or attempt then yields a different seed, and the same message yields the same
  signature, which leaks nothing.
- **Revived consumed material.** With fresh randomness, reusing a revived entry produces a new session
  id and is within the paper's reuse model; the single-use rule is then defense in depth rather than
  the thing that prevents the leak. With replayed randomness it is the fatal case above, and a
  malicious peer can complete it by replaying its own earlier round-1 message to the rolled-back
  party, which produces the same nonce under a different message. The hedge blocks that too.
- **Forgotten journals.** Quarantines, reservations and commit-before-reveal records roll back with
  the disk. No local measure fixes this; the records that must not roll back need an external
  authority or the peer's own copy: the peer refuses a quarantined identity from its own records,
  refuses an instance id it has seen, and refuses a registration reveal for a wallet id it already
  holds a commitment for.

So: platform-enforced no-snapshot plus kernel reseeding on generation change plus the seed hedge plus
peer-side journals covers the class. A policy document alone does not, because the failure is silent.

## 3. How to avoid repeated randomness

1. **Source.** Draw every seed from `OsRng` at the moment of use, on a kernel that reseeds on VM
   generation change; where available mix a hardware instruction draw into the pool at boot.
2. **Hedge, never derandomize.** Use `seed = H(label, os_entropy, consumption_digest, attempt_counter)`
   for each `sign::run`, and the same shape for setup and key-generation seeds with their own context.
   Entropy stays in; context is added. If entropy accidentally repeats, a changed message, path,
   wallet or attempt still changes the seed, and an unchanged context reproduces the same signature
   rather than a second one with the same nonce. Do not drop the entropy term: a purely deterministic
   seed repeats honest randomness by design, which is why re-seeding native DKG from roots was rejected.
3. **Consume seeds by value.** `sign::run` takes the seed by value and the pool already wraps it in a
   zeroizing owner; never store a seed, a ChaCha state or a half-finished transcript.
4. **Monotonic attempt counter.** Persist and fsync a per-pairing counter before round 1 and feed it
   into the hedge; a counter regression after a restore is detectable locally and refuses signing until
   reconciled.
5. **Peer-side journal.** Record the instance ids and round-1 session ids seen from the peer; refuse a
   repeat. This protects an honest party from a rolled-back or replaying counterpart.
6. **Tests.** Inject a repeated seed in the scratch harness and assert that the peer refuses the repeated
   instance id and that the hedged seed differs when only the prehash differs; keep the choice-XOR
   negative control as a permanent regression test; add an entropy self-test at worker start.

## 4. A refill, by inputs and outputs

Inputs to each worker, the parent sends the same command to both: a `SetupInput` with version 1,
recipe 1, both identities, both boot generations, the configuration digest and a fresh random entry
id; a test-only fault label; the worker's enrollment state with both signed boots and its role; its
per-boot DH static secret; OS randomness for the coin and both base-OT roles; the `controls/pool-setups`
ledger directory; and the shared incident gate, which refuses the refill if the pairing is fenced.

Exchanged over the channel keyed by the input digest, one flight each: a 32-byte coin commitment, a
32-byte coin reveal, base-OT message 1 of about 17 KB, a reply with base-OT message 2 of about 17 KB
plus the PPRF of about 14 KB, and a 32-byte completed-transcript digest.

Outputs: an `AvailableEntry` in RAM only, holding the input, the completed digest, the sender seed of
32,768 bytes, the receiver seed of 32,832 bytes, the 32-byte zero seed and a 300-second expiry; a
`{role}-{entry}.retired` ledger file holding the input digest, created before the first message and
never removed; a `PoolStatus` to the parent with entry id, input digest, completed digest, entries
available and timings, which the parent checks for agreement between the two workers; on failure a
typed `Failure`, with the generation and all unused entries dropped.

## 5. The zero share in Spike C

During refill each party commits to a 32-byte coin as a hash of the input digest, its role and the
coin; after both commitments are held, both reveal and verify; the zero seed is a hash of a label,
the input digest and the two coins in role order. Both coins are in the completed transcript, so the
package id commits to the seed. At consumption the constructor writes the seed into `each(0)` of both
keyshares, the slot native signing reads for both parties in the two-party case. Inside signing,
party 0 subtracts and party 1 adds the reduced hash of the DSG label, the seed, `digest_i` and the
randomization label, so the masks differ per session and cancel exactly.

Native key generation runs no coin flip: the lower-indexed party samples the seed alone and sends it
encrypted in round 3, so the pool is closer to the paper's commit-and-release than native is. For two
parties the masks are negatives of each other, so the seed hides nothing from the peer. A withheld
reveal is a timeout burn without quarantine; the resulting bias is of no known value, an argument, not
a proof.

## 6. Per pair across wallets: cautions and validation

Cautions: session-id uniqueness becomes the whole game, so fresh hedged seeds, no replay and
instance-id journals on both sides, with the record digest and generation id in the package id;
failure scope is the pairing, so any attributable failure retires the setup generation on both sides,
quarantines the peer for every wallet and cuts every concurrent session, and a wallet change never
resets failure accounting; leakage accumulates until retirement, so rotate by time or count, retire on
the first visible failure and treat an abort cluster as grounds to rotate; the setup blob is key
material, since one party's seeds plus its transcripts yield its secret inputs, so seal it, never
co-locate both parties' blobs, and exclude or detect snapshot restore; fix roles per pairing and agree
the generation id before signing, keeping a mismatch a context burn; keep only the donor's seeds, zero
seed and session id, discard its share, never sign with it, and apply the normal incident policy to the
donor run; registration ordering, derivation binding and the compiled OT question are unchanged.

Validation: a soak across wallets and concurrent sessions asserting every final and MtA session id
distinct and the seeds byte-identical throughout; a replay drill showing the peer refuses a repeated
instance id and the hedged seed changes with the prehash alone; failure propagation from one wallet's
session to all wallets of the pairing on both sides; generation mismatch classified as a context burn
and reconciled; rotation with cross-generation mixing refused; the choice-XOR and selective-abort probes
as permanent regression tests with retirement asserted through the worker; quarantine scope across
wallets and restarts; and a reviewed statement from Silence that the compiled stack supports
fresh-session-id reuse across keys with a usage bound, which tests cannot supply.
