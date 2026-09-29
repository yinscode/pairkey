# PairKey DKLS23 Spike C — first-pass cryptographic review (Claude)

Target: commit `5a6c05ad0bbc24d4ed51b36f00d82ff3055c6280` on `silence-dkls23` (assurance diff base `cd9f901`).
Reviewed from a `git archive` snapshot of the exact commit plus the local compiled native tree
`.local/silence-dkls23/sources/dkls23-af5ada2a…` and the registry copies of `sl-oblivious 1.0.0-beta`
and `sl-mpc-mate 1.0.0-beta`. Written before seeing Astra's report. Nothing tracked was edited; tests
ran in a separate snapshot with their own target and temp directories.

Bottom line: no demonstrated exploit in the experiment code. The construction is not approvable because two
proof obligations are open at the level of the selected theorems, and one of them (the VOLE parameter
question) is inherited from the locked native library and would equally affect the v0.4 reference design.
Recommended decision: continue research with two concrete remediations (contribution commit-before-reveal;
upstream resolution of the OT/VOLE analysis), do not adopt.

Status legend used below: **S** supported under stated assumptions · **O** unresolved proof obligation ·
**D** demonstrated defect · **N** not inspected.

---

## 0. What was and was not inspected

Inspected directly (code, line-level):
- Experiment: `src/lib.rs`, `registration.rs`, `pool.rs`, `pool_worker.rs`, `pool_driver.rs`, `worker.rs`,
  `wire.rs`, `lifecycle.rs`, `authority.rs`, `main.rs`, `measure.rs`, `process_probe.rs`, all test files,
  `tests/*.rs`, `patches/research-keyshare.rs`, `patch-source.py`, `bootstrap.sh`, `Cargo.toml`,
  `Cargo.lock` (pins only), `POOLING.md`, `SECURITY-REVIEW.md`, `REVIEW.md`, `FOLLOWUP-PLAN.md`,
  `README.md`, `results-extended-assurance.json`, `docs/architecture-v0.4.md`.
- Native `sl-dkls23` at `af5ada2a`: `keygen/{dkg.rs,keyshare.rs,keyshare/details.rs,migration.rs,
  utils.rs,constants.rs,messages.rs,types.rs,mod.rs,pairkey_research.rs}`, `sign/{dsg.rs,mod.rs,
  messages.rs,constants.rs,types.rs}`, `setup.rs`, `setup/{sign.rs,keygen.rs,keys.rs}`, `proto.rs`,
  `proto/{signed.rs,encrypted.rs,scheme.rs,tags.rs}`, `pairs.rs`, `lib.rs`.
- `sl-oblivious`: `endemic_ot.rs`, `soft_spoken/{all_but_one.rs,soft_spoken_ot.rs,types.rs,mod.rs}`,
  `rvole.rs`, `params.rs`, `constants.rs`, `zkproofs.rs`, `label.rs`, `lib.rs`.
- `sl-mpc-mate`: `message.rs`, `bip32.rs`, `coord.rs`, `coord/simple.rs`, `coord/buffered.rs`.
- Papers: eprint 2026/976 (Asharov, "Revisiting DKLs Threshold ECDSA", version dated May 17, 2026,
  55 pages, read in full from the packet copy; text extracted with a local PDFKit tool because poppler
  is absent). eprint 2023/765 abstract page (received 2023-05-26, last revised 2023-12-14).
  Trail of Bits report (upstream `docs/ToB-SilenceLaboratories_2024.04.10.pdf`): summary, findings 5, 9,
  10, 12, 13, Appendix F (RVOLE supplemental review) and G (fix review).

Not inspected (N) — gaps are reported, not filled from memory:
- The full text of DKLs23 (eprint 2023/765). The PDF returns HTTP 403 from this environment for both
  the fetch tool and curl with a browser user agent; `dkls.info` only links back to eprint. Theorem
  numbers of DKLs23 are therefore cited only as restated by 2026/976 (Section 4.4 "Variant III: the
  protocol of [DKLs24]", footnote 1, Section 2.1) and as declared in the code comments
  (`rvole.rs`: "protocol 5.2 OT-Based Random Vector OLE"; `soft_spoken_ot.rs`: "Functionality 5.1",
  "Fiat-Shamir transform applied according to Section 5.1 of 2023/765").
- Groth–Shoup (EUROCRYPT 2022) on additive key derivation, Masny–Rindal 2019 (Endemic OT),
  Roy 2022 (SoftSpokenOT), KOS15, Lindell 2024. Cited only where 2026/976 cites them.
- `sl-oblivious/soft_spoken/mul_poly.rs` (GF(2^128) multiply), `sl-mpc-mate/math.rs`, k256/ecdsa
  internals, every other transitive crate in `Cargo.lock`, the Rust toolchain.
- Upstream GitHub existence of revision `af5ada2a` (no network to github.com from the sandbox).
  The tarball hash `e7301fa0…` matches the value pinned in `bootstrap.sh`; the pristine tarball plus
  `patch-source.py` reproduces the compiled tree byte-for-byte (see §6).
- Demos (`demo`, `pool-demo`, `compare`) were not rerun; the test suites were.

---

## A. Reconstructed protocol flow and threat model

### A.1 Actors and persistent state
- Two long-lived worker processes, roles 0 and 1, each reading only its own 32-byte root file
  (`main.rs:407-424` provisions roots with `OsRng`). Identity key: Ed25519 from
  `HKDF-SHA256(salt="pairkey/dkls-research/identity/v1", ikm=root, info=[role])` (`lib.rs:76-82`).
- A trusted local driver (`pool_driver.rs`) that spawns workers, pins the peer identity by CLI argument
  (`pool_driver.rs:67-76`, `pool_worker.rs:481`), relays frames, chooses setup entry ids, assembles the
  registration candidate, and fabricates consumption receipts/policy versions.
- An honest shared filesystem under `controls/`: `.authority.lock` flocks (`authority.rs`),
  `scopes/<pair>/{0,1}.quarantined` incident markers, `pool-setups/` and `entries/` tombstones,
  `wallets/*.prepared|*.wallet`.

### A.2 Boot and enrollment
Each worker draws a per-process X25519 static secret (`pool_worker.rs:469`), signs
`Boot{role, identity, generation, ephemeral=dh pubkey}` (`pool.rs:126-148`), receives `Enroll([Boot;2])`,
checks its own boot is unchanged and the peer identity equals the CLI pin (`pool_worker.rs:478-481`),
and creates `ReleaseGate(pair_scope_dir(identities, 1))` and a 2-slot `RamPool` keyed to peers and boot
generations (`pool_worker.rs:485-487`).

### A.3 Wallet-independent preprocessing (one pool entry)
`SetupInput{version, recipe, peers, boots(generations), configuration digest, entry}` (`pool.rs:66-116`).
`configuration()` hashes the native revision, parameter string, Cargo files, patch script and the covered
wrapper sources (`pool.rs:49-63`). Flow in `pool_worker.rs:72-225`:
1. Burn `entry` in `controls/pool-setups` before any exchange (`pool_worker.rs:294-301`).
2. `SetupChannel::bound`: key = `HKDF-SHA256(salt="…/setup-channel/v1", ikm=X25519(dh, peer boot
   ephemeral), info=input.digest())`; ChaCha20-Poly1305 with a fresh random 96-bit nonce per frame and
   AAD = JSON(context, sender role, label) (`wire.rs:262-342`). Each label is used once per context.
3. Zero-coin: commit `H("…/zero-commit/v1", input, role, coin)`, exchange, reveal, verify, derive
   `zero = H("…/zero-seed/v1", input, coin0, coin1)` (`pool_worker.rs:85-124`). Commitments are
   received before reveals are sent.
4. Base OT, both directions: this role is EndemicOT receiver with
   `sid = H("pairkey/pool/base-ot/v1", input, receiver=role, sender=1-role)` and EndemicOT sender with the
   mirrored sid (`pool_worker.rs:127-140`); `build_pprf` with `pprf_sid(sender=role, receiver=1-role)`
   yields `SenderOTSeed`, `eval_pprf` with `pprf_sid(1-role, role)` yields `ReceiverOTSeed`
   (`pool_worker.rs:144-176`).
5. Canonical transcript of the 8 validated bodies → `completed` (`pool.rs:252-285`); authenticated ACK
   exchange; mismatch is a peer violation (`pool_worker.rs:179-199`).
6. `AvailableEntry::agreed(input, completed, Material{sender, receiver, zero}, ttl=300 s)` inserted into the
   RAM pool (`pool.rs:363-383`, `469-493`). No wallet, path, message or nonce exists at this point.

### A.4 Registration (per wallet, replaces native DKG)
1. `Describe(key_id)` → `Hello` (`lib.rs:169-196`): contribution `a_r = reduce_512(HKDF-SHA512(salt=
   "…/root/v1", ikm=root, info=H("…/contribution/v1",(role,key_id))))`, zero rejected; Schnorr
   proof with challenge `H("…/possession/v1",(role,key_id,identity,contribution,commitment))`
   (`lib.rs:219-234`); fresh `boot`; Ed25519 signature over the whole Hello.
2. Driver forms `Manifest{identities, additive_public=[A,B], Q=A+B, chain_code=
   H("…/public-chain-code/v1",(key_id,Q))}` and `WalletRecord` v1 with fixed metadata
   (`registration.rs:47-65`); `Manifest::validate` checks points, `A+B=Q`, and `A/2 ≠ -B`
   (`lib.rs:96-114`).
3. `Register{record, hellos}`: worker validates both Hellos (PoK + signature), enrollment identities and
   boot ephemerals (`pool_worker.rs:250-268`), then `WalletStore::endorse` journals
   `Prepared{record, endorsement}` with create-new + fsync before releasing the `Endorsement`
   (`registration.rs:262-303`). Endorsement = fresh Schnorr proof of the same contribution with challenge
   `H(record digest, role, commitment)` and an identity signature over (record, role, commitment,
   response) (`registration.rs:143-177`).
4. `CommitWallet(RegisteredWallet)`: verify both endorsements and own journal, write immutable
   `<key>.wallet` (`registration.rs:307-335`). Driver requires both ACKs.
   There is no contribution commit-before-reveal stage (POOLING.md says so explicitly).

### A.5 Consumption and signing
`Request{Pooled, manifest, hellos, entry, attempt, path∈{m, m/7/3}, prehash, wallet_record}` and
`Consumption v2{input digest, completed, entry, wallet record digest, scheme, path, prehash, receipt,
policy_version, attempt}` (`pool.rs:171-249`). In `pool_worker.rs:338-464`:
1. `Request::validate`, route/peer/ephemeral pins, `check_local` (re-derive `a_r`, compare with manifest),
   load and verify the committed wallet, require `wallet_record == record.digest()`.
2. `RamPool::reserve(c)`: remove the entry from RAM before any fallible check, write the tombstone
   `entries/{role}-{entry}.retired` containing `c.digest()`, then check provenance
   (`pool.rs:497-533`). Ownership is consumed even on mismatch.
3. Authenticated agreement of `c.digest()` over a channel keyed by `c.digest()` (`pool_worker.rs:381-391`).
4. `into_package`: `s_0 = a/2`, `s_1 = -b`; `Keyshare::pairkey_research_two_party(party, s, [A/2, -B], Q,
   key_id, chain_code, setup_id = package_sid = H("pairkey/pool/package/v1", completed, c.digest()),
   zero, sender seed, receiver seed, extra = c.digest())` (`pool.rs:395-432`,
   `patches/research-keyshare.rs:7-48`).
5. Native `sign::run(setup, seed=OsRng fresh, wire)` with `InstanceId = c.digest()`, Ed25519 identity as
   message signer, chain path and prehash (`pool_worker.rs:414-437`). Output verified locally, low-S
   enforced, recovery id checked.

Native signing as compiled (`sign/dsg.rs`): R1 signed broadcast `{session_id, commitment(R_i), party_id,
enc_pk}`; `final_session_id = SHA256(sid_0 ‖ sid_1 ‖ keyshare.final_session_id)` (`dsg.rs:162-167`);
R2 encrypted P2P = RVOLE round 1 as receiver with `mta_session_id(final, sender=peer, receiver=me)`
(`dsg.rs:186-231`, `1061-1075`); `sk_i = λ_i·s_i + offset/2 + ζ_i` with λ = (2, −1) for x = (1, 2)
(`dsg.rs:236-257`, verified numerically); R3 encrypted P2P = RVOLE sender on `[r_i, sk_i]` plus opening of
`R_i`, `pk_i`, `Γ_u`, `Γ_v`, `ψ` (`dsg.rs:264-338`); checks: final sid, commitment, digest, `cond1/cond2`
(`dsg.rs:405-419`), `Σ pk_j == derived pk` (`dsg.rs:429`); R4 signed broadcast of partial `(s_0, s_1)`,
combine, verify (`dsg.rs:778-831`, `525-572`).

### A.6 Threat model used in this review
- One honest signer, one malicious peer with full control of its own code: it may ignore its KDF, choose
  its contribution after seeing the honest one, choose its R1 session id after seeing the honest one,
  send malformed or inconsistent protocol messages, abort selectively, and collude with the relay.
- Static corruption only (the peer is malicious from the start). Concurrent executions: many wallets and
  attempts per pairing, sequential per worker, concurrent across worker pairs.
- Platform assumptions taken as given (failures of these are platform failures, not protocol attacks):
  trusted driver for identity pins, enrollment, candidate records and policy receipts; honest local
  filesystem and cooperating processes; OS entropy; RAM-only secrets without snapshots/rollback; fixed
  roots, no refresh; licensing out of scope.
- Explicitly not claimed: protection against sequential compromise of both roots; adaptive corruption;
  cross-host authority; physical erasure.

---

## B. Assumption matrix

| # | Claim | Theorem / section | Exact code / encoding | Checkable argument | Status |
|---|---|---|---|---|---|
| 1 | Contribution scalars are negligibly biased and nonzero | n/a (KDF hygiene) | `lib.rs:64-75`: HKDF-SHA512 → 64 bytes → `Reduce<U512>`; zero rejected | Wide reduction bias ≤ 2^-256; `check_local` re-derives | S |
| 2 | Per-wallet contributions are computationally independent of each other and of the identity key | HKDF/HMAC-SHA512 as PRF with uniform 32-byte key | Distinct salts (`root/v1` vs `identity/v1`), distinct hash functions, `info` binds `(role, key_id)` with a versioned label | Standard PRF-domain-separation argument; roots must be uniformly random and independently provisioned (platform) | S |
| 3 | No algebraic relation between wallets (related-key) beyond BIP32 public tweaks | n/a | `lib.rs:66`; `bip32.rs:140-179`; `registration.rs:83-90` fixes `chain_code = H(key_id, Q)` | Tweaks are public, non-hardened only; child secret ⇒ wallet root secret, not the KDF root | S (scope statement) |
| 4 | Schnorr Hello proof is a sound PoK of the contribution | Fiat–Shamir Schnorr in ROM (knowledge soundness by rewinding) | `lib.rs:197-234`: challenge binds role, key_id, identity, contribution, commitment; `point()` rejects identity/non-canonical | Rogue-key choices `B = X − A` require knowing `x − a`; tested negative cases in `tests/invariants.rs:119-135`, `registration_tests.rs:137-161` | S for knowledge; see row 6 |
| 5 | Endorsement binds the final joint record | Same as 4 | `registration.rs:143-157`: challenge `H(record, role, commitment)`, signature over (record, role, commitment, response) | Equivocation across records needs a second valid proof under a different challenge; journals make retries deterministic | S |
| 6 | The key generation satisfies the keygen assumption of the selected signing theorem | 2026/976 §2.2 p.8 ("inputs valid and consistent… extracted during the key-generation", [Lin24]); Theorem 6.3/C.1, Simulator C.2 steps 3–4 (simulator receives `pk, pk0, pk1` from the functionality); DKLs23 keygen is a commit-release-complain ceremony per its abstract | `pool_driver.rs:322-364` reveals `A` before `B` is fixed; no commit stage; `A` is deterministic from the root | Extraction of `b` exists (row 4) but the honest share cannot be programmed toward an ideal key; aggregate key is `X + bG` with `b` adversarially chosen after seeing `X` | **O** (Finding 2) |
| 7 | Share conversion reproduces the native Lagrange secret | Linear algebra | `patches/research-keyshare.rs:24-25,39`; `dsg.rs:962-979` | λ_0 = x_1/(x_1−x_0) = 2, λ_1 = x_0/(x_0−x_1) = −1 ⇒ `2s_A − s_B = a + b`; verified mod n numerically | S |
| 8 | Constructor-produced package matches every field native signing reads | `dsg.rs` field usage | `research-keyshare.rs:29-47` vs `dsg.rs:85,165,187-195,233-257,287-291,876-914` | party_id, total/threshold, s_i, public_key, final_session_id, x_i, big_s, rank, zeta_seed (each[0], both parties), send/recv OT seeds (other(1−party)) all set; `extra` only read by the wrapper | S (local algebra only) |
| 9 | Directional OT seeds correlate correctly across parties | Native convention in `dkg.rs` | `dkg.rs:445-474` (sender seed = EndemicOT sender side, `other(j).send_ot_seed`), `dkg.rs:535-553` (receiver side); pool `pool_worker.rs:127-176`, constructor `research-keyshare.rs:44-46`; use sites `dsg.rs:195,291` | Role r's `send_ot_seed` comes from the base OT where r was EndemicOT sender with `base_ot_sid(receiver=1−r, sender=r)`, which is exactly the sid the peer used as receiver; mirrored for `recv_ot_seed`; PPRF sids mirrored likewise | S |
| 10 | Zero-share seed yields native zero-sum masks | `dsg.rs:876-914` | Party 0: `ζ_0 = −H(seed, sig_id)`; party 1: `ζ_1 = +H(seed, sig_id)`; both read `each(0).zeta_seed` | Sum is zero; in two-party signing the peer knows the seed anyway; 2026/976 §2.2 states F_zero is unnecessary for two parties | S |
| 11 | Signing session identifiers are unique and bound to consumption | ToB-SILA-9/10 remediation; UC sid uniqueness | `InstanceId = c.digest()` (`pool_worker.rs:415`); `package_sid` ⇒ `keyshare.final_session_id` ⇒ `final_session_id` (`dsg.rs:162-167`) ⇒ `mta_session_id` (`dsg.rs:1061-1075`) | `attempt` and `entry` are fresh random; message ids hash the instance (`message.rs:101-116`) | S (binding), see row 15 for grinding |
| 12 | The consumption context reaches the actual OT-extension PRG and Fiat–Shamir inputs | `soft_spoken_ot.rs`, `rvole.rs` | sid enters seed expansion (`soft_spoken_ot.rs:142-145, 299-309`), the matrix hash that yields χ (`:137-155, 178-191, 316-371`), output randomization (`:237-246, 419-442`), gadget vector (`rvole.rs:42-54`), θ transcript (`rvole.rs:141-160, 286-319`) and µ (`rvole.rs:197-225, 331-345`) | Traced; not merely a wrapper hash. The extension's own `Round1Output (u, x, t)` is **not** hashed into θ or g | S (propagation); gap noted in Finding 3 |
| 13 | RVOLE is the DKLs23 Protocol 5.2 instance with ℓ=2, ρ=1, m=512, g chosen from sid at onset | 2026/976 §4.4 (Variant III), Theorem B.17; ToB Appendix F | `params.rs` (`L = 256 + 2·128`), `rvole.rs:40-54, 246-348` | Structure matches 2026/976 Protocol 4.2 with g from sid only | S (identification) |
| 14 | m = 512 OTs give the intended statistical security | 2026/976 Theorem 4.4 / B.17: `m ≥ log q + 7s + 2log(s+1) + 2s·log(e·m/s)`; DKLs24 formula `m ≥ log q + 2s` (2026/976 §2.1, footnote 1) | `params.rs: LAMBDA_S = 128` | Solving B.17 at m=512, log q=256 gives s ≈ 12; Variant I would give s ≈ 85; Variant II needs m ≥ 548 even for s=12. The implementation's naming implies s=128 under the DKLs24 bound that 2026/976 argues is unjustified (Appendix A experiment) | **O** (Finding 1) |
| 15 | The final signing sid is not adversarially selectable | Variant III assumes g fixed at onset from sid; Variant II treats adversarial hash choice (+2κ) | `dsg.rs:98, 162-167`: own `session_id` is random but sent in the clear in R1; a peer can wait for the honest R1 and then choose its own | One-sided grinding of `final_session_id`, hence of g and all MtA sids, is possible for the malicious party | **O** (Finding 4, native) |
| 16 | The Endemic-OT-hybrid attack of 2026/976 §4.5 does not apply | §4.5 ("Use Sender Random OT"), Claim B.8 | VOLE sender's `v_0/v_1` are `H(sid, j, ζ_j)` and `H(sid, j, ζ_j ⊕ Δ)` (`soft_spoken_ot.rs:419-442`), fixed by base-OT seeds and the receiver's `u` before Q is chosen | The sender cannot pick `T1 − T0` after χ; a bad (A, χ) pair costs 2^-κ per RO query. No written theorem that SoftSpokenOT+EndemicOT realizes F_RSOT (ToB-SILA-13 partially resolved) | O (argument sketched, not proven) |
| 17 | Base-OT material is used once and never across sessions | 2026/976 §2.1 p.5–6 and [vdP23] recommend per-signature base OTs | Non-Clone `AvailableEntry`/`ReservedEntry` (`pool.rs:343-362`), RAM removal before validation (`pool.rs:510`), tombstones, `seen` set, generation discard on any failure (`pool_worker.rs:512-519`) | Cross-session selective failure (ToB-SILA-12) is structurally removed; partial leakage of Δ in one session is harmless because Δ is only used through RO hashing and is never reused | S (within platform assumptions) |
| 18 | Fresh private signing randomness per attempt; combined API only | DKLs23 requires fresh seeds; 2026/976 §2.2 on pre-signature hazards | `pool_worker.rs:434-437`, `worker.rs:351-363`: `fresh()`→ChaCha20Rng seeds φ_i, r_i, blind, sid, ephemeral X25519 | No presign export; nonce never revealed before the message is fixed | S |
| 19 | Native message authenticity and confidentiality | Transport layer, not protocol theorem | R1/R4 Ed25519 `verify_strict` via `SignedMessage` (`proto/signed.rs`, `wire.rs`/`pool_worker.rs:37-41`); R2/R3 `AeadX25519<ChaCha20Poly1305>` with enc_pk authenticated by R1 signature (`scheme.rs:375-397`, `encrypted.rs`) | Unauthenticated frames are ignored (ToB-SILA-14), which only costs liveness | S |
| 20 | Failure classification never accuses on transport evidence, always quarantines on authenticated violations | DKLs23 abort guidance as restated by ToB-SILA-12 | `lifecycle.rs:91-138`; exhaustive test `tests/invariants.rs:263-323` | Aggregate checks (`FailedCheck`, `K256Error`) freeze instead of accusing; conservative | S |
| 21 | Honest party's R4 partial may enable the peer to finish a signature while the honest side records failure | Protocol fact, DKLs23 has no fairness | `dsg.rs:791-803` sends before verifying | Authorization layers must not infer "no signature" from a failed attempt (already noted in REVIEW.md) | S (model statement) |
| 22 | Historical audit covers this revision | ToB report targets `dkls23-rs 1510c2f`, `sl-crypto a6b0147`, fix review Jan 2024 | Pinned `af5ada2a` is later; constructor, migration patch and pool are new | Not covered; ToB App. F also recommends λ_c = 128 for primitive consistency | N (by scope) |

---

## C. Findings (ordered by impact)

### Finding 1 — Locked RVOLE parameters are only supported at roughly 12 bits of statistical security by the newer analysis (unresolved proof obligation, native, affects v0.4 too)
- Where: `sl-oblivious/src/params.rs` (`L = KAPPA + 2·LAMBDA_S = 512`), `rvole.rs:42-54` (g from sid at
  onset), `rvole.rs:286-305` (θ from sid and Q only). Consumed by `dsg.rs:209-214, 303-311`.
- What: the compiled VOLE is exactly 2026/976 Variant III (Section 4.4, Theorem B.17). Its sufficient
  condition is `m ≥ log q + 7s + 2log(s+1) + 2s·log(e·m/s)`. At m = 512 the largest integer s satisfying
  it is 12; the paper's own worked instance needs 1405 OTs for s = 60 (Section 5.3.1, Table 1). The
  implementation's constant names encode the DKLs24 condition `m ≥ log q + 2s` with s = 128, and
  2026/976 Section 2.1 and Appendix A argue that condition does not hold because the sender may fix
  constraints on w after g is known.
- Adversary and prerequisites: malicious peer acting as MtA sender in one signing attempt, willing to be
  detected with probability 2^-|c| for |c| imposed constraints; a detected attempt quarantines the pairing
  (`lifecycle.rs:104-106`), so the game is one-shot per pairing in this design. The quantity at stake is
  the closeness to uniform of the honest receiver's β, which is what makes `cond1/cond2`
  (`dsg.rs:405-419`) binding on the sender's nonce and key-share inputs before the honest R4 partial is
  released.
- What this is not: not a demonstrated attack. B.17 is a sufficient bound; the real security of m = 512
  is unknown. The paper's small-parameter experiment shows the DKLs24 bound is too liberal but gives no
  full-scale estimate.
- Scope: this is inherited from the locked native library and would equally affect the reference
  architecture's native-DKG path. It is not caused by the keygen replacement or by pooling.
- Smallest remediation: none inside the experiment under the "parameters stay fixed" decision. Upstream
  question for Silence Laboratories: which variant and which s they claim for m = 512, and whether they
  will move to Variant II (m ≥ 696 and hashing the OT transcript into χ and g) or Variant I.

### Finding 2 — The registration ceremony does not provide what the selected signing arguments assume of key generation (unresolved proof obligation, construction)
- Where: `pool_driver.rs:322-364` (`describe` collects both Hellos; a malicious peer can delay its Hello
  until it has seen the honest contribution), `lib.rs:169-196` (Hello is independent of the peer),
  `registration.rs` (no commitment stage). POOLING.md acknowledges the absence of commit-before-reveal.
- What the arguments need: 2026/976 proves two-party signing "assuming the parties' inputs are valid and
  consistent, following [Lin24]… the simulator knows the adversary's share… extracted during the
  key-generation" (Section 2.2, p. 8), and Simulator C.2 receives `(pk, pk0, pk1)` from the ideal
  functionality, i.e. the aggregate key is ideally distributed. DKLs23's own keygen (per its abstract) is
  a commit-release-and-complain ceremony. Both therefore assume a keygen in which the simulator can
  extract the adversary's share and still make the aggregate key equal an externally given key.
- What the implementation provides: extraction of `b` is available from the Fiat–Shamir Schnorr proof
  (rewinding in ROM; challenge context `lib.rs:219-234`, record-bound variant `registration.rs:143-151`).
  Programming is not: the honest contribution `A` is revealed first, so the aggregate key is
  `X + b·G` for an adversarially chosen `b` that may depend on `X`. The standard reduction to ECDSA
  unforgeability does not go through directly; what is needed is an argument for ECDSA under an
  adversarially chosen additive tweak applied after seeing the base key (the Groth–Shoup line of work,
  not inspected here).
- What is covered: rogue-key cancellation (`B = X − A`, `B = −A`, copying `A`, forcing a constant
  polynomial) is excluded by the PoK and by `Manifest::validate` (`lib.rs:107-112`). Independence of
  roots and KDF compliance of the peer are provisioning assumptions and are not, and cannot be, proven by
  the scalar proof; the honest party's own security does not depend on the peer's KDF except through the
  key-distribution issue above.
- Smallest remediation: add a contribution commit-before-reveal stage to registration (each worker first
  releases `H(label, key_id, role, identity, Hello)`; reveal only after both commitments are acknowledged
  and journaled). In the proof this lets the simulator extract `b` before choosing the honest
  (pseudorandom, hence programmable in a PRF hybrid) contribution, restoring the [Lin24]-style argument.
  Public keys of honestly registered wallets do not change; wallets already registered without it keep the
  weaker argument.

### Finding 3 — Fiat–Shamir challenges of the VOLE and the OT extension do not bind the concrete OT transcript (unresolved proof obligation, native)
- Where: `rvole.rs:286-305` (θ ← sid, a_tilde), `rvole.rs:42-54` (g ← sid), `soft_spoken_ot.rs:137-191`
  (χ ← sid, u).
- What: 2026/976 footnote 2 and Section 4.5 require, in the plain model, hashing the entire concrete OT
  transcript into χ and g. The pooled route does bind the base-OT transcript indirectly (EndemicOT
  msg1/msg2 and PPRF bodies are in `completed`, which feeds `package_sid`, hence `sid`), but the
  extension's `Round1Output` is not bound anywhere in the challenge derivations. The attack of Section
  4.5 itself does not apply, because the VOLE sender's `T0/T1` are RO outputs fixed by material that
  predates Q (row 16). That is a sketch, not a theorem, and ToB-SILA-13 recorded the absence of a
  specification/proof for the combined SoftSpoken/KOS/DKLs23 extension.
- Smallest remediation: upstream algorithm change (include `Round1Output` in the θ and g transcripts).
  Nothing to change in the experiment under the current decision.

### Finding 4 — The final signing session id is one-sidedly selectable by the malicious party (unresolved, native)
- Where: `dsg.rs:98` (random `session_id`), `dsg.rs:105-137` (sent in the clear in R1; receive and send
  are independent), `dsg.rs:162-167` (`final_session_id`).
- What: a malicious peer can observe the honest `sid_0` and grind its `sid_1`, choosing among many
  `final_session_id` values and therefore among many gadget vectors and MtA sids. Variant III's theorem
  treats g as fixed at onset from a sid; adversarial choice among hash outputs is the extra power that
  Variant II handles with +2κ OTs. The research code cannot prevent this; `package_sid` binds but does not
  commit the per-signature contributions.
- Smallest remediation: upstream (commit to `session_id` in R1, open in R2, or derive g and χ after the
  OT round). Report as an upstream question.

### Finding 5 — Collector exception can hide any failure kind from a role that already produced a result (minor, fixture)
- Where: `pooled_process_tests.rs:341-359`.
- What: once the fixture's own `published` marker exists, every later `Frame::Failure` from a role that
  already replied with a `Result` is dropped without checking its phase, kind or detail. The intended case
  is the worker loop's `pool incident cutoff` control burn (`pool_worker.rs:492`, `509`). The regression
  at `pooled_process_tests.rs:933-1007` covers presence/absence of publication but not the kind.
- Remediation: assert the ignored frame is `Phase::Control`/`FailureKind::Quarantined` with the cutoff
  detail, allow at most one, and record it in the evidence JSON.

### Finding 6 — Schedule evidence files are deterministic summaries (minor, assurance methodology)
- My fresh run regenerated all 130 schedule JSON files byte-identical to the hashes listed in
  `results-extended-assurance.json`. That confirms the assertions, but it also means the hash inventory
  cannot distinguish a fresh run from a copied one. Adding a run nonce, timestamps and host identity to
  each record would make the inventory evidential.

### Finding 7 — Driver-trust surface should be stated as a platform gate (note)
- Peer identity pin by CLI (`pool_driver.rs:71`), enrollment boot pair, registration candidate assembly,
  consumption receipt and policy version (`pool_driver.rs:465-471`) are all trusted inputs. A malicious
  driver can pair an honest worker with an attacker identity; nothing cryptographic prevents that. This
  matches the documented scope; production needs registry-pinned identities.

### Observations (no action required for this review)
- `endemic_ot.rs:100-113`: the OT output key derivation `h_function_2(batch_index, pk)` omits the session
  id; separation relies on the DH points being session-specific. Negligible, upstream nit.
- The SetupChannel DH key is per process generation, not per exchange; forward secrecy inside a generation
  is a RAM-only assumption (documented).
- Fixed paths `m` and `m/7/3`, 300 s entry TTL, two slots, 1024 ids per generation are research limits.
- ToB Appendix F recommends λ_c = 128 to match the 128-bit primitives (X25519, ChaCha20); the
  implementation uses 256 base OTs. Informational.

---

## D. Constructor security contract and composition argument

### D.1 Contract of `Keyshare::pairkey_research_two_party` (`patches/research-keyshare.rs`)
Checked locally (lines 20-26): `party ∈ {0,1}`; `secret ≠ 0`; `Q ≠ O`; `S_0, S_1 ≠ O`; `S_0 ≠ S_1`;
`2·S_0 − S_1 = Q`; `secret·G = S_party`. Written without checks (lines 29-46): `n = t = 2`, `extra`,
`key_id`, `chain_code`, `final_session_id`, `x = (1, 2)`, ranks 0, `each(0).zeta_seed`, `other(1−party).{send,recv}_ot_seed`.

Caller obligations (established by `pool_worker.rs`/`registration.rs` or by platform assumptions):
1. Authentic agreed public record: both signers endorsed the same `WalletRecord`; the local `secret`
   is re-derived from the root and matched to the record (`check_local`). Established by registration,
   subject to Finding 2.
2. Directional correlations: `send_ot_seed` was produced by this party as EndemicOT sender in the base OT
   whose sid the peer used as receiver, and vice versa; both sides hold the same `completed` digest. Established
   by `preprocess` plus the ACK; the constructor cannot verify it.
3. Zero seed shared by both parties and fresh per entry: established by the commit/reveal coin; secrecy
   from third parties by the AEAD channel; bias is irrelevant for two parties.
4. `final_session_id` unique per consumption: `package_sid` includes `attempt` and `entry` (fresh).
5. Single use: the entry's seeds are moved, not copied; ownership is consumed before validation; tombstones
   persist; incident markers fence both roles. Native `Keyshare` remains `Clone`; nothing in the wrapper clones it.
6. Fresh signing seed per attempt; combined `sign::run` only.

### D.2 Native keygen properties: inherited, replaced, dropped
| Native DKG property (`dkg.rs`) | In Spike C |
|---|---|
| Uniform secret from summed random polynomials with Feldman VSS and DLog proofs (`:208-291, 608-621, 640-693`) | Replaced by deterministic root contributions with Schnorr PoK; consistency check `2S_0 − S_1 = Q` plays the role of `check_secret_recovery` for x = (1, 2) |
| Commit-then-open of session ids, polynomial commitments and x_i (`:217-224, 237-243, 340-407`) | Dropped (Finding 2) |
| Random distinct x_i (`:213, 253-262`) | Fixed (1, 2); nothing in signing needs x_i secrecy |
| Joint random chain code via commit/open (`:333-337, 560-569, 597-601`) | Deterministic public `H(key_id, Q)`; public derivation only |
| Base OT with sids from DKG `final_session_id` and party ids over encrypted P2P (`:293-327, 445-461`) | Base OT with sids from `SetupInput` digest over the AEAD setup channel; same role convention |
| PPRF sids per direction (`:463-474, 539-553`) | Same shape from `SetupInput` |
| Unilateral zeta seed by the lower party, encrypted (`:476-480, 555-557`) | Two-party coin flip |
| `final_session_id = H(sid_0 ‖ sid_1)` random (`:265-269`) | `package_sid`, deterministic but unique per consumption |
| `key_id` derived from the public key (`:722`, `setup/keygen.rs:202-205`) | `key_id` is the KDF input; the public key is derived from it (reversed, harmless) |
| `extra` from setup | Consumption digest |

### D.3 Composition argument — steps and where it stops
1. Hybrid 1 (PRF): replace HKDF outputs `a_r` and identity seeds by independent uniform values. Loss:
   PRF advantage of HMAC-SHA512 under a uniform 256-bit key. Requires the provisioning assumption that
   roots are uniform and independent.
2. Hybrid 2 (transport): replace the Ed25519/AEAD-protected native channel and the SetupChannel by
   authenticated (R1/R4) and secure (R2/R3, setup) channels. Loss: EUF-CMA of Ed25519, IND-CCA of
   X25519+ChaCha20-Poly1305 under the key derivations in `scheme.rs` and `wire.rs`. Requires the identity
   pin and enrollment to be honest (driver).
3. Hybrid 3 (base OT): replace each pooled EndemicOT+PPRF instance by an ideal (all-but-one) base-OT
   functionality with the given sids. Requires MR19's UC security of Endemic OT over authenticated
   channels and the all-but-one PPRF proof of Roy22 Figs. 13–14 (both not inspected). The single-use
   discipline makes each instance a fresh session.
4. Hybrid 4 (VOLE): replace the two per-signature RVOLE executions by F_RVOLE. This needs (a) a theorem
   that SoftSpokenOT with Endemic/all-but-one base OTs realizes the OT functionality assumed by the VOLE
   theorem (ToB-SILA-13 open), and (b) 2026/976 Theorem B.17 at the locked m = 512, which only yields
   s ≈ 12 (Finding 1), and (c) an accounting for adversarial sid selection (Finding 4). **Stops here.**
5. Hybrid 5 (commitments, zero shares): F_Com from the hash commitment of R_i and the coin flip. Standard ROM.
6. Hybrid 6 (signing): invoke the DKLs23 two-party signing theorem (not inspected) or 2026/976 Theorem
   6.3 for a key `(pk, pk0, pk1)` produced by an ideal keygen. The registration provides extraction but
   not an ideally distributed aggregate key (Finding 2). **Stops here.** With commit-before-reveal the
   simulator can extract `b` and set `A := X − B` in Hybrid 1's uniform world, which closes this step for
   newly registered wallets.
7. Multi-wallet/concurrency: distinct `sid`s per attempt and per entry, sequential commands per worker, and
   independent contributions per wallet (Hybrid 1) give the UC composition its distinct-session
   precondition; BIP32 public tweaks move the final step to an additive-derivation ECDSA statement
   (Groth–Shoup, not inspected).

No reduction or theorem number is invented above; the two blocked steps are exactly Findings 1–4.

---

## E. Remaining questions and scoped decision

Questions for upstream (Silence Laboratories) or an expert reviewer:
1. For m = 512, ℓ = 2, ρ = 1, g from sid: which analysis and which statistical level do you claim, given
   2026/976 Theorem B.17 and Appendix A? Will the library move to Variant II (m ≥ 696, OT transcript in χ
   and g) or Variant I?
2. Is there a written proof that the compiled SoftSpokenOT (all-but-one PPRF, K = 4, 64 trees,
   S = 128, M = 4) with EndemicOT base OTs realizes a sender-random OT functionality, as Theorem B.17 and
   Section 4.5 require? Status of ToB-SILA-13.
3. Is adversarial selection of `session_id` in R1 (hence of `final_session_id`, g and MtA sids) within the
   model of the DKLs23 signing theorem, or should R1 commit to it?
4. Does the DKLs23 UC signing theorem admit a keygen that outputs `X + bG` with `b` chosen by the
   adversary after `X`, or does it require an ideal keygen? If the former, under which assumption
   (additive-derivation ECDSA)?
5. Audit scope: no report covers `af5ada2a`, the migration abort patch, the duplicate-party-id fix or the
   research constructor.

Decision: **continue research; remediate; do not adopt.**
- Do now, in the experiment: add contribution commit-before-reveal to registration (Finding 2
  remediation); tighten the collector exception (Finding 5); make evidence records non-deterministic
  (Finding 6).
- Do before any adoption decision: obtain written upstream answers to questions 1–4. If the answer to
  question 1 does not support the intended level at m = 512, that blocks every DKLS23 path in the
  project, including the v0.4 reference proposal, not only Spike C.
- Keep as separate platform gates (unchanged from the project's own list): hostile host, snapshots and
  rollback, cross-host authority, physical erasure, hardware entropy, production authorization, licensing.

No production approval is implied by model agreement, passing tests or reproduced evidence.

---

## 6. Verification record (fresh, isolated)

- Snapshot: `git archive 5a6c05ad` extracted to a scratch directory; hashes of all 35 experiment and docs
  files match `MANIFEST.json`; all 64 vendor hashes match the compiled tree and the registry sources.
- Native modifications: the compiled tree differs from the pristine tarball in exactly five hunks:
  `Cargo.toml` (feature `pairkey-research-faults`), `keygen/keyshare.rs` (`include!("pairkey_research.rs")`),
  `keygen/dkg.rs` (feature-gated PPRF fault hook), `keygen/migration.rs` (best-effort abort send),
  `sign/dsg.rs` (duplicate party-id comparison `w[0].1 != w[1].1`). Running `bootstrap.sh` on the pristine
  tarball in the snapshot reproduced the compiled tree byte-for-byte (`PATCHED_SOURCE_IDENTICAL`).
  Signing arithmetic and `sl-oblivious` parameters are unchanged; the dsg.rs hunk changes an abort path
  (a self-id assertion panic becomes `InvalidMessage`).
- `bootstrap.sh test --locked --offline`: 31 + 1 + 8 + 15 runtime tests passed plus 2 compile-fail
  doc tests (55 + 2). With `--features research-faults`: 31 + 18 + 8 + 14 passed plus 2 (71 + 2);
  the process matrix took 329 s. Union 74 distinct tests, matching the claim.
- 130 schedule records regenerated under `PAIRKEY_ASSURANCE_EVIDENCE_DIR`; names identical to the
  committed inventory, all `passed: true`, all byte-identical to the committed hashes (see Finding 6).
- Clippy `-D warnings` in both feature configurations and `cargo fmt --check` passed. Release build and
  demos were not rerun.
- Environment limits: no outbound access to github.com; eprint PDF downloads blocked (HTTP 403).
- Working-tree note: while this review ran, eight tracked files under `experiments/silence-dkls23/`
  (`REVIEW.md`, `lifecycle.rs`, `pooled_process_tests.rs`, `extended_process_tests.rs`, `lib.rs`,
  `pool_worker.rs`, `worker.rs`, `process_probe.rs`) were modified in the checkout between 23:32 and
  23:46 local time by another actor. This review did not touch tracked files; all findings refer to the
  immutable commit `5a6c05ad`, and none of those uncommitted edits were reviewed.
