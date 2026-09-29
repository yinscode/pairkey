# PairKey DKLS23 Spike C — first-pass cryptographic review (Claude), revision 2

Target: commit `5a6c05ad0bbc24d4ed51b36f00d82ff3055c6280` on `silence-dkls23` (assurance diff base `cd9f901`).
Reviewed from a `git archive` snapshot of the exact commit plus the compiled native tree
`.local/silence-dkls23/sources/dkls23-af5ada2a…` and the registry copies of `sl-oblivious 1.0.0-beta` and
`sl-mpc-mate 1.0.0-beta`. Written before seeing Astra's report. No tracked file was edited; tests ran in a
separate snapshot with their own target and temp directories.

Revision 2 (this file): the DKLs23 paper (eprint 2023/765, version dated December 14, 2023, 76 pages) is
now the primary theorem source; it was supplied by the user and read in full. Eprint 2026/976 is treated
as reference context only. Revision 1 is kept beside this file as `CLAUDE-FIRST-PASS-REPORT-v1.md`.

Bottom line: no demonstrated exploit in the experiment code, and the locked native parameters satisfy the
rule DKLs23 itself states for its VOLE. The construction is still not approvable, because the replacement
of key generation does not realize the key-generation functionality that DKLs23's signing theorem assumes
(Functionality 3.2), and DKLs23's own key-generation protocol shows what is missing: a commit-then-reveal
ordering, not a proof of knowledge. A second obligation, inherited from the native library, is that the
compiled OT-extension stack is assumed, not proven, to realize DKLs23's endemic OT-extension functionality.
Recommended decision: continue research, add the commit-before-reveal stage, obtain the upstream statement
on the OT-extension assumption, do not adopt yet.

Status legend: **S** supported under stated assumptions · **O** unresolved proof obligation ·
**D** demonstrated defect · **N** not inspected.

---

## 0. What was and was not inspected

Inspected directly (code, line level):
- Experiment: `src/lib.rs`, `registration.rs`, `pool.rs`, `pool_worker.rs`, `pool_driver.rs`, `worker.rs`,
  `wire.rs`, `lifecycle.rs`, `authority.rs`, `main.rs`, `measure.rs`, `process_probe.rs`, all `*_tests.rs`,
  `tests/*.rs`, `patches/research-keyshare.rs`, `patch-source.py`, `bootstrap.sh`, `Cargo.toml`,
  `Cargo.lock` (pins), `POOLING.md`, `SECURITY-REVIEW.md`, `REVIEW.md`, `FOLLOWUP-PLAN.md`, `README.md`,
  `results-extended-assurance.json`, `docs/architecture-v0.4.md`.
- Native `sl-dkls23` at `af5ada2a`: `keygen/{dkg.rs,keyshare.rs,keyshare/details.rs,migration.rs,utils.rs,
  constants.rs,messages.rs,types.rs,mod.rs,pairkey_research.rs}`, `sign/{dsg.rs,mod.rs,messages.rs,
  constants.rs,types.rs}`, `setup.rs`, `setup/{sign.rs,keygen.rs,keys.rs}`, `proto.rs`,
  `proto/{signed.rs,encrypted.rs,scheme.rs,tags.rs}`, `pairs.rs`, `lib.rs`.
- `sl-oblivious`: `endemic_ot.rs`, `soft_spoken/{all_but_one.rs,soft_spoken_ot.rs,types.rs,mod.rs}`,
  `rvole.rs`, `params.rs`, `constants.rs`, `zkproofs.rs`, `label.rs`, `lib.rs`.
- `sl-mpc-mate`: `message.rs`, `bip32.rs`, `coord.rs`, `coord/simple.rs`, `coord/buffered.rs`.
- Papers. Primary: DKLs23 "Threshold ECDSA in Three Rounds", eprint 2023/765, version dated December 14,
  2023 (the latest eprint revision per the archive page), sections 2.2, 3, 4, 5, 6, 7 and 8 read in full.
  Reference: eprint 2026/976 (Asharov, May 17, 2026), read in full. Trail of Bits report (upstream
  `docs/ToB-SilenceLaboratories_2024.04.10.pdf`): summary, findings 5, 9, 10, 12, 13, appendices F and G.

Not inspected (N):
- Roy22 (SoftSpokenOT), Masny–Rindal 2019 (endemic OT), KOS15, Impagliazzo–Naor 1996 Proposition 1.1,
  Groth–Shoup 2022, Lindell 2022. Cited only as DKLs23 cites them.
- `sl-oblivious/soft_spoken/mul_poly.rs`, `sl-mpc-mate/math.rs`, k256/ecdsa internals, other transitive
  crates, the Rust toolchain.
- Upstream GitHub existence of revision `af5ada2a` (no network to github.com from the sandbox). The
  tarball hash matches the value pinned in `bootstrap.sh`, and the pristine tarball plus `patch-source.py`
  reproduces the compiled tree byte for byte (section 6).
- Demos (`demo`, `pool-demo`, `compare`) were not rerun; both test suites were.

About the audit. The Trail of Bits assessment (engagement November–December 2023, fix review January
2024) covered `dkls23-rs 1510c2f` and `sl-crypto a6b0147`: DKG, DSG, base OT (MR19), OT extension,
pairwise multiplication (replaced by the RVOLE of DKLs23 Protocol 5.2 during the fix review, appendix F),
zero sharing and messaging. Fourteen of fifteen findings were resolved and TOB-SILA-13 (no explicit
specification/proof for the combined SoftSpokenOT variant) partially. That evidence supports the native
signing and OT code lineage. It does not cover the pinned revision `af5ada2a` itself, the research
constructor, the registration ceremony, the pool, the migration abort patch or the duplicate-party-id
fix. This report treats the audit as evidence for the native path and as silent on the custom parts.

---

## A. Reconstructed protocol flow and threat model

### A.1 Actors and persistent state
- Two long-lived workers, roles 0 and 1, each reading only its own 32-byte root (`main.rs:407-424`).
  Identity key: Ed25519 from `HKDF-SHA256(salt="pairkey/dkls-research/identity/v1", ikm=root,
  info=[role])` (`lib.rs:76-82`).
- A trusted local driver (`pool_driver.rs`) that spawns workers, pins the peer identity by CLI argument
  (`pool_driver.rs:67-76`, `pool_worker.rs:481`), relays frames, chooses setup entry ids, assembles the
  registration candidate and fabricates consumption receipts and policy versions.
- An honest shared filesystem under `controls/`: `.authority.lock` flocks (`authority.rs`),
  `scopes/<pair>/{0,1}.quarantined`, `pool-setups/` and `entries/` tombstones, `wallets/*.prepared|*.wallet`.

### A.2 Boot and enrollment
Each worker draws a per-process X25519 secret (`pool_worker.rs:469`), signs `Boot{role, identity,
generation, ephemeral}` (`pool.rs:126-148`), receives `Enroll([Boot;2])`, checks its own boot is unchanged
and the peer identity equals the CLI pin (`pool_worker.rs:478-481`), and creates
`ReleaseGate(pair_scope_dir(identities, 1))` and a two-slot `RamPool` (`pool_worker.rs:485-487`).

### A.3 Wallet-independent preprocessing (one pool entry)
`SetupInput{version, recipe, peers, boots, configuration, entry}` (`pool.rs:66-116`); `configuration()`
hashes the native revision, parameter string, Cargo files, patch script and the covered wrapper sources
(`pool.rs:49-63`). In `pool_worker.rs:72-225`:
1. Burn `entry` in `controls/pool-setups` before any exchange (`pool_worker.rs:294-301`).
2. `SetupChannel::bound`: key = `HKDF-SHA256(salt, X25519(dh, peer boot ephemeral), info=input.digest())`;
   ChaCha20-Poly1305, fresh random 96-bit nonce per frame, AAD = (context, sender role, label)
   (`wire.rs:262-342`). Each label is used once per context.
3. Zero-coin commit, exchange, reveal, verify; `zero = H("…/zero-seed/v1", input, coin0, coin1)`
   (`pool_worker.rs:85-124`). Commitments are received before reveals are sent. This is the
   F_Zero realization DKLs23 describes in section 3.1 (pairwise commit and decommit of seeds, then
   combine), whereas native DKG lets the lower-indexed party choose the seed unilaterally (`dkg.rs:476-480`).
4. Base OT in both directions: EndemicOT receiver with `sid = H("…/base-ot/v1", input, receiver=role,
   sender=1-role)` and sender with the mirrored sid (`pool_worker.rs:127-140`); `build_pprf` with
   `pprf_sid(role, 1-role)` gives `SenderOTSeed`, `eval_pprf` with `pprf_sid(1-role, role)` gives
   `ReceiverOTSeed` (`pool_worker.rs:144-176`). This is the one-time setup of DKLs23 section 8.1 (λc
   base OTs from MR19 feeding Roy22's extension), executed per entry instead of once per pair.
5. Canonical transcript of the eight validated bodies → `completed` (`pool.rs:252-285`); authenticated
   ACK; mismatch is a peer violation (`pool_worker.rs:179-199`).
6. `AvailableEntry::agreed(input, completed, Material{sender, receiver, zero}, ttl 300 s)` inserted into
   the RAM pool (`pool.rs:363-383, 469-493`). No wallet, path, message or nonce exists yet.

### A.4 Registration (per wallet; replaces F_RelaxedKeyGen)
1. `Describe(key_id)` → `Hello` (`lib.rs:169-196`): contribution `a_r = reduce_512(HKDF-SHA512(salt=
   "…/root/v1", ikm=root, info=H("…/contribution/v1",(role,key_id))))`, zero rejected; Schnorr proof
   with challenge `H("…/possession/v1",(role,key_id,identity,contribution,commitment))` (`lib.rs:219-234`);
   fresh `boot`; Ed25519 signature over the Hello.
2. Driver forms `Manifest{identities, [A,B], Q=A+B, chain_code=H("…/public-chain-code/v1",(key_id,Q))}`
   and `WalletRecord` v1 (`registration.rs:47-65`); `Manifest::validate` checks points, `A+B=Q`,
   `A/2 ≠ −B` (`lib.rs:96-114`).
3. `Register{record, hellos}`: each worker validates both Hellos, enrollment identities and boot
   ephemerals (`pool_worker.rs:250-268`), journals `Prepared{record, endorsement}` with create-new and
   fsync before releasing the `Endorsement` (`registration.rs:262-303`): a fresh Schnorr proof with
   challenge `H(record digest, role, commitment)` plus an identity signature (`registration.rs:143-177`).
4. `CommitWallet`: verify both endorsements and own journal, write immutable `<key>.wallet`
   (`registration.rs:307-335`); the driver requires both ACKs.
   There is no contribution commitment stage (POOLING.md says so). The honest contribution is revealed
   as soon as `Describe` is answered.

### A.5 Consumption and signing
`Request{Pooled, manifest, hellos, entry, attempt, path, prehash, wallet_record}` and `Consumption v2`
(`pool.rs:171-249`). In `pool_worker.rs:338-464`: validate request, pins and `check_local`; load and
verify the committed wallet; `RamPool::reserve(c)` removes the entry before any fallible check and writes
the tombstone with `c.digest()` (`pool.rs:497-533`); authenticated agreement of `c.digest()`
(`pool_worker.rs:381-391`); `into_package`: `s_0 = a/2`, `s_1 = −b`, `Keyshare::pairkey_research_two_party(
party, s, [A/2, −B], Q, key_id, chain_code, setup_id = H("pairkey/pool/package/v1", completed, c.digest()),
zero, sender seed, receiver seed, extra = c.digest())` (`pool.rs:395-432`, `patches/research-keyshare.rs`);
native `sign::run(setup, seed = OsRng, wire)` with `InstanceId = c.digest()`, identity key as message
signer, chain path, prehash (`pool_worker.rs:414-437`); output verified, low-S, recovery id checked.

Native signing as compiled (`sign/dsg.rs`) against DKLs23 Protocol 3.6 (p. 17–20):
- Step 5–6: `r_i`, `φ_i`, blind factor, own session id from the ChaCha20 seed; R1 signed broadcast
  `{session_id, H(sid_i, R_i, blind), party_id, enc_pk}` (`dsg.rs:88-118`) realizes the F_Com commit to
  `R_i` (section 3.1 folklore: oracle image of value and salt); `final_session_id = SHA256(sid_0 ‖ sid_1 ‖
  keyshare.final_session_id)` (`dsg.rs:162-167`).
- Step 7: `sk_i = λ_i·s_i + offset/2 + ζ_i` with λ = (2, −1) for x = (1, 2) (`dsg.rs:236-257`); R2 encrypted
  P2P = F_RVOLE `sample` side (Protocol 5.2 step 1) with `mta_session_id(final, sender=peer, receiver=me)`
  (`dsg.rs:186-231, 1061-1075`); R3 encrypted P2P = Protocol 5.2 step 3 on `a = [r_i, sk_i]`, plus the
  decommitment of `R_i`, `pk_i`, `Γ_u`, `Γ_v`, `ψ` (`dsg.rs:264-338`).
- Step 8: checks `χ·R_j − Γ_u = d_u·G`, `χ·pk_j − Γ_v = d_v·G` (`dsg.rs:405-419`), `Σ pk = derived pk`
  (`dsg.rs:429`), commitment and digest consistency; on failure the native code returns
  `AbortProtocolAndBanParty` and the wrapper quarantines the pair for all wallets and attempts
  (`lifecycle.rs:104-106`, `pool_worker.rs:512-519`), which is the "fail in all concurrent sessions and
  refuse future sessions with P_j" requirement of step 8.
- Step 10: R4 signed broadcast of partial `(s_0, s_1)`, combine, `ECDSAVerify` before output
  (`dsg.rs:778-831, 525-572`).
The implementation runs the general t-party protocol with t = n = 2; the two-message variant of section
3.5 and the pipelining/presigning options of section 3.3 are not used.

### A.6 Threat model used in this review
- DKLs23 section 2.2: malicious PPT adversary, **static** corruption of up to t−1 parties (here: one
  malicious peer, one honest signer), UC framework, authenticated point-to-point channels, asynchronous
  network, no broadcast, no guaranteed output. Adaptive corruption is not covered by Theorem 4.1 and is
  not claimed here. Concurrency and multiple wallets are covered by UC composition under distinct
  session ids (Functionality 3.1 requires fresh `sid` and `sigid`).
- The malicious peer controls its own code: it may ignore its KDF, choose its contribution after seeing
  the honest one, choose its R1 session id after seeing the honest one, send malformed messages, abort
  selectively, and collude with the relay.
- Platform assumptions taken as given: trusted driver for identity pins, enrollment, candidate records
  and policy receipts; honest local filesystem and cooperating processes; OS entropy; RAM-only secrets
  without snapshots or rollback; fixed roots, no refresh; licensing out of scope.
- Not claimed: protection against sequential compromise of both roots; cross-host authority; physical
  erasure; presigning security (section 3.3's GS22 warning does not apply because only the combined
  API is used).

---

## B. Assumption matrix

| # | Claim | Theorem / section (DKLs23 unless stated) | Exact code / encoding | Checkable argument | Status |
|---|---|---|---|---|---|
| 1 | Contribution scalars are negligibly biased and nonzero | KDF hygiene (outside the paper) | `lib.rs:64-75`: HKDF-SHA512 → 64 bytes → `Reduce<U512>`; zero rejected | Bias ≤ 2^-256; `check_local` re-derives | S |
| 2 | Per-wallet contributions are computationally independent of each other and of the identity key | HKDF/HMAC-SHA512 as PRF with uniform 32-byte key | Distinct salts, distinct hashes, `info` binds `(role, key_id)` | Standard PRF domain separation; roots uniform and independently provisioned (platform) | S |
| 3 | No algebraic relation between wallets beyond BIP32 public tweaks | Outside Theorem 4.1 (signs under `pk = P(0)`); additive derivation is GS22 territory (cited by DKLs23 §3.3, not inspected) | `bip32.rs:140-179`; `registration.rs:83-90`; `dsg.rs:247-254` (offset split by `1/t`) | Public, non-hardened tweaks; child secret ⇒ wallet secret, not the KDF root | S for the derivation algebra; O for the ECDSA-with-additive-derivation assumption |
| 4 | Schnorr Hello proof is a sound proof of knowledge | Fiat–Shamir Schnorr in ROM (outside the paper; DKLs23 §7 p. 57 notes PoKs are not needed by its keygen) | `lib.rs:197-234`; `point()` rejects identity and non-canonical encodings | Rogue-key choices `B = X − A` need `x − a`; negative tests `tests/invariants.rs:119-135`, `registration_tests.rs:137-161` | S (for knowledge) |
| 5 | Endorsement binds the final joint record | Same | `registration.rs:143-157` | Equivocation across records needs a second proof under a different challenge; journals make retries deterministic | S |
| 6 | Key generation realizes F_RelaxedKeyGen | Functionality 3.2 (p. 14): corrupt contribution `adv-poly` is received **before** the honest polynomial `p̂` is sampled, so `pk = P(0)` is uniform; Simulator 4.2 step 5 (p. 27) programs the honest share from `pk` and `adv-poly`; Protocol 7.1 (p. 58–59) realizes it by committing contributions to `F_Com(n)` then decommitting; Theorem 7.2 (p. 60); §7 p. 57–58: no proof of knowledge needed, only uniform `pk` and consistent shares | `pool_driver.rs:322-364` reveals `A` in the `Describe` reply; a peer can delay its own Hello until it has seen `A`; no commitment stage | The honest contribution is pseudorandom (fine in a PRF hybrid), but it is revealed before the adversary's is fixed, so `pk` is `X + B` for an adaptively chosen `B` and the simulator cannot program the honest share. PoKs do not restore the ordering | **O** (Finding 1) |
| 7 | Share conversion reproduces Protocol 3.6 step 7's Lagrange secret | Protocol 3.6 step 7 (`sk_i = p(i)·lagrange(P,i,0) + ζ_i`) | `research-keyshare.rs:24-25,39`; `dsg.rs:962-979` | λ_0 = 2, λ_1 = −1 for x = (1, 2) ⇒ `2s_A − s_B = a + b`; verified mod n | S |
| 8 | Constructor package matches every field native signing reads | `dsg.rs` field usage | `research-keyshare.rs:29-47` vs `dsg.rs:85,165,187-195,233-257,287-291,876-914` | All fields native signing reads are set; `extra` is read only by the wrapper | S (local algebra only) |
| 9 | Directional OT seeds correlate correctly | Native convention `dkg.rs` | `dkg.rs:445-474, 535-553`; pool `pool_worker.rs:127-176`; constructor `research-keyshare.rs:44-46`; use `dsg.rs:195,291` | Role r's `send_ot_seed` comes from the base OT in which r was EndemicOT sender with the sid the peer used as receiver; mirrored for `recv_ot_seed` and the PPRF sids | S |
| 10 | Zero seed yields F_Zero masks | Functionality 3.4 and its §3.1 realization (commit and decommit pairwise seeds) | `dsg.rs:876-914`: `ζ_0 = −H(seed, sig_id)`, `ζ_1 = +H(seed, sig_id)`, both read `each(0).zeta_seed` | Sum zero; the research coin flip matches the paper's realization more closely than native DKG's unilateral seed | S |
| 11 | Session identifiers are fresh and bound to consumption | Functionality 3.1 (fresh `sid`, `sigid`); Functionality 3.5 (`sid = P_B‖P_A‖sid'` fresh) | `InstanceId = c.digest()`; `package_sid` ⇒ `keyshare.final_session_id` ⇒ `final_session_id` (`dsg.rs:162-167`) ⇒ `mta_session_id` (`dsg.rs:1061-1075`) | `attempt` and `entry` fresh random; both parties' random R1 session ids contribute | S |
| 12 | Consumption context reaches the actual OT-extension PRG and Fiat–Shamir inputs | Protocol 5.2 (`θ = RO(sid, ã)`, `µ = RO(sid, µ)`), §5.1 (`χ = H(u)`) | sid in seed expansion (`soft_spoken_ot.rs:142-145, 299-309`), matrix hash for χ (`:137-191, 316-371`), output randomization (`:237-246, 419-442`), gadget (`rvole.rs:42-54`), θ (`rvole.rs:141-160, 286-319`), µ (`rvole.rs:197-225, 331-345`) | Traced; not merely a wrapper hash | S |
| 13 | The compiled RVOLE is Protocol 5.2 with ℓ = 2, ρ = 1, ξ = 512 | Protocol 5.2 (p. 39–41): `ξ = κ + 2λs`, `ρ = ⌈κ/λc⌉`, θ ∈ Z_q^{ℓ×ρ}, η ∈ Z_q^ρ, µ ∈ {0,1}^{2λc}; footnote a: `g` may be a reused CRS | `params.rs` (`L = 256 + 2·128`, `RHO = 1`, `LAMBDA_C = 256`); `rvole.rs:40-54, 246-348`; ToB appendix F confirms the mapping with two index typos fixed | Structure and dimensions match; `g = RO(sid)` is a public gadget vector as allowed by footnote a | S |
| 14 | Locked parameters meet the paper's requirement | Protocol 5.2 and Lemma 6.2: Claim 6.5 / 6.10 use Impagliazzo–Naor Prop. 1.1 part 2 with `ξ − κ = 2λs` to bound the distance by `2^-λs`; final bound `ξ·Q·2^-λc + Q²·2^-2λc-1 + 8·2^-λs + 2·2^-2λc` (p. 52); §8.5 uses λs = 80 concretely | `L = 512` ⇒ λs = 128; `LAMBDA_C = 256` ⇒ ρ = 1, µ hash 512 bits | Under the primary theorem the implementation is at or above the paper's concrete choices. Reference note: 2026/976 §2.1, §5.3, Appendix A argue the IN96 step does not cover constraints chosen after `g` is known and would require ≈1405 OTs for s = 60; at 512 OTs its Theorem B.17 supports s ≈ 12. That is a dispute about the paper's analysis, not a conformance defect of the implementation | S under DKLs23; open upstream question (see E) |
| 15 | Adversarial choice of the signing sid is harmless | Protocol 5.2 footnote a (g may be a CRS known in advance); Functionality 3.1 lets the environment choose `sigid` | `dsg.rs:98, 162-167`: a peer can choose its R1 session id after seeing the honest one | Under DKLs23 the gadget vector may already be public and fixed, so one-sided grinding of `final_session_id` adds no power the proof does not already grant. It matters only under the 2026/976 critique | S under DKLs23 (reference note only) |
| 16 | SoftSpokenOT + MR19 realize F_EOTE as Theorem 6.1 assumes | Functionality 5.1 (p. 39); §5 recommends Roy22 with the §5.1 one-message modification and MR19 base OTs; §8.1; Theorem 6.1 (p. 42) | `soft_spoken_ot.rs`, `all_but_one.rs`, `endemic_ot.rs` | DKLs23 gives no proof for this realization; it cites Roy22 and MR19 (not inspected). ToB-SILA-13 is partially resolved for lack of an explicit specification. Additionally, Claim 6.7 (p. 50) assumes `α0, α1` are fixed before the adversary computes `θ`; Functionality 5.1 as written does not force that order for a corrupt Alice (2026/976 §4.5 exhibits the gap in the hybrid). In the compiled realization Alice's outputs are RO images of base-OT material and the receiver's `u`, all fixed before `ã`, so the order holds concretely; this is an argument to be written, not a theorem | **O** (Finding 2) |
| 17 | Base-OT material used once, never across sessions | §8.2 assumes reuse "once per pair"; single use is a conservative deviation; Theorem 6.1 is per `sid` | Non-Clone `AvailableEntry`/`ReservedEntry` (`pool.rs:343-362`), RAM removal before validation (`pool.rs:510`), tombstones, `seen`, generation discard on failure (`pool_worker.rs:512-519`) | Cross-session selective failure (ToB-SILA-12) is removed by construction; partial leakage of Δ in one session is harmless because Δ is only used through RO hashing and never reused | S |
| 18 | Fresh randomness per attempt; no presigning | Protocol 3.6 steps 5–6; §3.3 GS22 warning | `pool_worker.rs:434-437`, `worker.rs:351-363`: `fresh()` → ChaCha20Rng → `r_i`, `φ_i`, blind, sid, ephemeral X25519 | Combined `sign::run` only; the nonce is never revealed before the message is fixed | S |
| 19 | Authenticated channels (§2.2) | §2.2 assumes authenticated point-to-point channels | R1/R4 Ed25519 `verify_strict` via `SignedMessage`; R2/R3 `AeadX25519<ChaCha20Poly1305>` with `enc_pk` authenticated by R1; setup channel `wire.rs:262-342` | Unauthenticated frames are ignored (ToB-SILA-14), costing only liveness | S |
| 20 | Failure handling matches Protocol 3.6 step 8 and Hybrid H2 | Step 8 (p. 19–20); H2 (p. 32): at most `(t−1)(n−t+1)` failed checks before no honest party signs with a corrupt one | `lifecycle.rs:91-138`; scope across wallets/attempts (`lifecycle.rs:143-158`); test `tests/invariants.rs:263-323` | The pair-wide quarantine is stronger than the per-`sid` blacklist the paper requires; aggregate checks freeze rather than accuse (conservative) | S |
| 21 | Message agreement (Functionality 3.1 step 5) | Step 5: differing message hashes yield failure | Consumption binds `prehash` and both sides authenticate it before signing; final `ECDSAVerify` | A disagreeing peer causes failure, never a bad output | S |
| 22 | R4 partial may let the peer finish a signature while the honest side records failure | Protocol 3.6 steps 9–10 give no fairness | `dsg.rs:791-803` | Authorization layers must not infer "no signature" from a failed attempt (already in REVIEW.md) | S (model statement) |
| 23 | Audit covers this revision | ToB report scope (above) | Pinned `af5ada2a` is later; constructor, migration patch and pool are new | Not covered; ToB appendix F also recommends λc = 128 to match the 128-bit primitives | N (by scope) |

---

## C. Findings (ordered by impact)

### Finding 1 — The registration ceremony does not realize DKLs23's key-generation functionality (unresolved proof obligation, construction)
- Where: `pool_driver.rs:322-364` (`describe` collects both Hellos; the honest contribution is in the
  reply as soon as the honest worker answers), `lib.rs:169-196` (Hello is independent of the peer),
  `registration.rs` (no commitment stage). POOLING.md states there is no commit-before-reveal.
- What the primary theorem needs: Theorem 4.1 (p. 25–26) is proven in the hybrid model with
  Functionality 3.2 F_RelaxedKeyGen (p. 14). That functionality receives the corrupt parties'
  contribution (`adv-poly`, given in the group for the corrupt shares) **first**, then samples the honest
  polynomial uniformly, so the public key `P(0)` is uniform and independent of the adversary's choice.
  Simulator 4.2 step 5 (p. 27) relies on exactly this: it takes `pk` from F_ECDSA, and computes the honest
  contribution as `P̂(i) = P(i) − P̌(i)·G`. Section 7 (p. 57–58) explains that the signing protocol does
  **not** need the adversary's shares to be extracted ("the secret key shares are rerandomized and
  extracted afresh by F_RVOLE for each signature"), only that "the public key is uniformly sampled, and
  that the honest parties' shares are distributed consistently with the corrupt parties' shares". Protocol
  7.1 (p. 58–59) achieves this with a commit step (2) to `F_Com(n)` and `F_Com(2)` and a decommit step (3),
  and Simulator 7.3 step 2 reads the corrupt commitments before fixing the honest polynomial.
- What the implementation provides: knowledge of `b` via Fiat–Shamir Schnorr (more than DKLs23 asks),
  agreement on the record, deterministic honest contributions (acceptable: in a PRF hybrid they are
  uniform, which is what F_RelaxedKeyGen samples). What it lacks is the ordering: the honest `A` is
  revealed before `B` is fixed, so the aggregate key is `X + b·G` with `b` possibly dependent on `X`, and
  the simulator of Theorem 4.1 cannot program the honest share. Theorem 7.2 does not apply because its
  protocol is not run.
- What is covered: rogue-key cancellation (`B = X − A`, `B = −A`, copying `A`, forcing a constant
  polynomial) is excluded by the PoK and by `Manifest::validate` (`lib.rs:107-112`). Independence of
  roots and KDF compliance of the peer are provisioning assumptions and are not, and cannot be, proven by
  the scalar proof; DKLs23 does not need them from the adversary either.
- Impact and prerequisites: no concrete attack is exhibited. The consequence is that unforgeability of
  wallets registered this way is not covered by Theorem 4.1; it would need a separate argument for ECDSA
  under a key `X + b·G` with `b` chosen after `X` (additive-key-derivation flavour, GS22 line, not
  inspected). Prerequisite for the adversary: control the timing of its Hello relative to the honest one,
  which a malicious worker or relay has.
- Smallest remediation: add a contribution commit-before-reveal stage mirroring Protocol 7.1 steps 2–3:
  each worker first releases `H(label, key_id, role, identity, salt, Hello)`, both commitments are
  journaled and acknowledged, then the Hellos are revealed and checked against the commitments. With that
  ordering the registration realizes F_RelaxedKeyGen in the PRF hybrid (the honest contribution is uniform
  and independent of the committed adversarial one), the Schnorr proofs become optional defence in depth,
  and public keys of honestly registered wallets do not change. Wallets already registered without it
  keep the weaker argument.

### Finding 2 — The compiled OT-extension stack is assumed, not proven, to realize F_EOTE (unresolved proof obligation, native)
- Where: `soft_spoken_ot.rs`, `all_but_one.rs`, `endemic_ot.rs`; consumed by `rvole.rs` via
  `dsg.rs:209-214, 303-311`.
- What: Theorem 6.1 (p. 42) proves Protocol 5.2 in the F_EOTE-hybrid non-programmable-RO model.
  DKLs23 only suggests realizing F_EOTE with Roy22's SoftSpokenOT, modified per §5.1, over MR19 base OTs
  (§5 p. 39, §8.1), citing those papers for security; no composed proof is given, and ToB-SILA-13 recorded
  the absence of an explicit specification for Silence's variant. Separately, Claim 6.7 (p. 50) argues
  "α0 and α1 are fixed and then the adversary computes θ", while Functionality 5.1 lets a corrupt Alice
  supply `alice-messages` whenever she likes, so the order is an assumption on the realization rather
  than a property of the hybrid (2026/976 §4.5 makes this explicit; reference only). In the compiled
  realization the sender's extended outputs are `H(sid, j, ζ_j)` and `H(sid, j, ζ_j ⊕ Δ)`
  (`soft_spoken_ot.rs:419-442`), fixed by base-OT seeds and the receiver's `u` before `ã` is chosen, so the
  ordering does hold concretely and the §4.5 attack is not available. None of this is written down as a
  theorem for the exact code.
- Also relevant: §5.1 requires replacing the statistical parameter of the SoftSpoken check by the
  computational one under Fiat–Shamir; the implementation uses a 128-bit check field (`S = 128`), which is
  the conventional computational level for secp256k1 even though `LAMBDA_C = 256` elsewhere (ToB appendix F
  remark).
- Smallest remediation: none inside the experiment. Upstream question: a written argument that the
  compiled SoftSpokenOT (all-but-one PPRF, K = 4, 64 trees, S = 128, M = 4) over MR19 realizes
  Functionality 5.1, including the output-fixing order used by Claim 6.7. Hashing the extension's
  `Round1Output` into `θ` and `g` (2026/976 footnote 2) would make the order explicit; that is an
  upstream algorithm change, not a parameter change.

### Finding 3 — Parameter adequacy of ξ = 512 is supported by DKLs23 and disputed by the reference paper (open upstream question, not a conformance defect)
- Under DKLs23: Protocol 5.2 sets `ξ = κ + 2λs`; the implementation's 512 OTs correspond to λs = 128,
  above the paper's concrete λs = 80 (§8.5), and `ρ = ⌈κ/λc⌉ = 1` for the implementation's λc = 256. Lemma
  6.2's distance bound is `ξ·Q·2^-λc + Q²·2^-2λc-1 + 8·2^-λs + 2·2^-2λc` (p. 52). Row 14: supported.
- Reference (2026/976 §2.1, §5.3, Appendix A, Theorem B.17): the Impagliazzo–Naor step is said not to
  cover adversarial constraints chosen after `g` is known; under that paper's conservative bound 512 OTs
  support s ≈ 12 and s = 60 needs 1405 OTs. This is a dispute about DKLs23's analysis (and therefore
  about every deployment of this library, including the v0.4 reference path), not something the
  experiment introduced or can fix while parameters are locked.
- Action: record as an upstream question (section E); no parameter patch proposed.

### Finding 4 — Collector exception can hide any failure kind from a role that already produced a result (minor, fixture)
- Where: `pooled_process_tests.rs:341-359`. Once the fixture's own `published` marker exists, every later
  `Frame::Failure` from a role that already replied with a `Result` is dropped without checking phase,
  kind or detail. The intended case is the worker loop's `pool incident cutoff` control burn
  (`pool_worker.rs:492, 509`); the regression at `pooled_process_tests.rs:933-1007` checks presence and
  absence of publication but not the kind.
- Remediation: assert the ignored frame is `Phase::Control`/`FailureKind::Quarantined` with the cutoff
  detail, allow at most one, and record it in the evidence JSON.

### Finding 5 — Schedule evidence files are deterministic summaries (minor, assurance methodology)
- A fresh run regenerated all 130 schedule JSON files byte-identical to the hashes in
  `results-extended-assurance.json`. That confirms the assertions but means the inventory cannot
  distinguish a fresh run from a copy. Add a run nonce, timestamps and host identity to each record.

### Finding 6 — Driver-trust surface should be stated as a platform gate (note)
- Peer identity pin by CLI (`pool_driver.rs:71`), enrollment boot pair, registration candidate assembly,
  consumption receipt and policy version (`pool_driver.rs:465-471`) are trusted inputs. A malicious driver
  can pair an honest worker with an attacker identity. This matches the documented scope; production needs
  registry-pinned identities.

### Observations (no action required)
- `endemic_ot.rs:100-113`: the OT output key derivation omits the session id (only batch index and DH
  point); negligible, upstream nit.
- The R1 commitment salt is 256 bits; §3.1's folklore commitment uses a 2λc salt, i.e. 512 bits at
  λc = 256 or 256 bits at λc = 128. Consistent with the ToB appendix F remark that the code mixes λc = 256
  with 128-bit primitives.
- Native DKG chooses the zero-sharing seed unilaterally (`dkg.rs:476-480`); the research coin flip is the
  §3.1 realization. Harmless either way for two parties.
- The SetupChannel DH key is per process generation; fixed paths `m` and `m/7/3`, 300 s entry TTL, two
  slots and 1024 ids per generation are research limits.

---

## D. Constructor security contract and composition argument

### D.1 Contract of `Keyshare::pairkey_research_two_party` (`patches/research-keyshare.rs`)
Checked locally (lines 20–26): `party ∈ {0,1}`; `secret ≠ 0`; `Q ≠ O`; `S_0, S_1 ≠ O`; `S_0 ≠ S_1`;
`2·S_0 − S_1 = Q`; `secret·G = S_party`. Written without checks (lines 29–46): `n = t = 2`, `extra`,
`key_id`, `chain_code`, `final_session_id`, `x = (1, 2)`, ranks 0, `each(0).zeta_seed`,
`other(1−party).{send,recv}_ot_seed`.

Caller obligations, mapped to DKLs23's hybrid functionalities:
1. F_RelaxedKeyGen output: an agreed public key with consistent shares, produced so that the public key
   is uniform and independent of the adversary's contribution. Partially met (agreement, consistency,
   `check_local`); the ordering property is missing (Finding 1).
2. F_EOTE one-time setup: correctly correlated directional seeds from an authenticated base-OT run with
   fresh sids; both sides holding the same `completed` digest. Met by `preprocess` and the ACK; the
   constructor cannot verify it.
3. F_Zero seed shared by both parties and fresh per entry. Met by the coin flip over the AEAD channel.
4. Fresh `sid`/`sigid` per consumption. Met by `package_sid` and the per-signing random session ids.
5. Single use of the F_EOTE setup. Met by linear ownership, tombstones and incident fencing within the
   platform assumptions; native `Keyshare` remains `Clone`, nothing in the wrapper clones it.
6. Fresh signing seed per attempt and combined `sign::run` only. Met.

### D.2 Native keygen properties: inherited, replaced, dropped
| Native DKG property (`dkg.rs`) | DKLs23 role | In Spike C |
|---|---|---|
| Commit-then-open of session ids, polynomial commitments and `x_i` (`:217-224, 237-243, 340-407`) | Protocol 7.1 steps 2–3 ordering | Dropped (Finding 1) |
| Uniform secret from summed random polynomials with Feldman checks and DLog proofs (`:208-291, 608-693`) | F_RelaxedKeyGen output distribution and consistency; the DLog proofs exceed what the paper needs | Deterministic root contributions plus Schnorr PoK; `2S_0 − S_1 = Q` replaces `check_secret_recovery` for x = (1, 2) |
| Random distinct `x_i` (`:213, 253-262`) | Shamir coordinates | Fixed (1, 2); nothing in signing needs `x_i` secrecy |
| Joint random chain code via commit/open (`:333-337, 560-569, 597-601`) | Outside the paper | Deterministic public `H(key_id, Q)` |
| Base OT with sids from the DKG final sid and party ids (`:293-327, 445-461`) | §8.1 one-time setup | Base OT with sids from `SetupInput`, same role convention, per entry |
| PPRF sids per direction (`:463-474, 539-553`) | Part of the Roy22 setup | Same shape from `SetupInput` |
| Unilateral zeta seed by the lower party (`:476-480, 555-557`) | F_Zero realization (§3.1 asks both parties to contribute) | Two-party coin flip (closer to §3.1) |
| `final_session_id = H(sid_0 ‖ sid_1)` (`:265-269`) | Part of `sid` | `package_sid`, deterministic but unique per consumption |
| `key_id` from the public key (`:722`) | Outside the paper | `key_id` is the KDF input |

### D.3 Composition argument in DKLs23's hybrid model — steps and where it stops
Target statement: the pooled two-party signer realizes F_ECDSA (Functionality 3.1) with n = t = 2 by
Theorem 4.1, after replacing each hybrid functionality by the implemented realization.
1. **PRF hybrid.** Replace HKDF outputs `a_r` and identity seeds by independent uniform values. Loss: PRF
   advantage of HMAC-SHA512 under a uniform 256-bit key. Needs uniform, independently provisioned roots.
2. **Authenticated channels (§2.2).** Replace Ed25519-signed and AEAD-protected native frames and the
   setup channel by authenticated (R1/R4) and secure (R2/R3, setup) channels. Loss: EUF-CMA of Ed25519 and
   IND-CCA of X25519 + ChaCha20-Poly1305 under the derivations in `scheme.rs` and `wire.rs`. Needs honest
   identity pins and enrollment (driver).
3. **F_Com.** The R1 hash commitment to `R_i` with a 256-bit blind is the §3.1 folklore commitment in the
   ROM; the zero-coin commitment likewise.
4. **F_Zero.** The coin flip realizes the §3.1 construction; `get_zeta_i` produces the zero-sum masks.
5. **F_EOTE.** Replace each per-entry MR19 + PPRF + SoftSpoken instance by Functionality 5.1 with the given
   sids. Needs the Roy22 and MR19 results and the output-fixing order used by Claim 6.7. **Stops here**
   (Finding 2). Single use makes every instance a fresh session, which is stronger than the §8.2 reuse
   assumption.
6. **F_RVOLE.** Given step 5, Theorem 6.1 applies to Protocol 5.2 with ℓ = 2, ρ = 1, ξ = 512, λs = 128,
   λc = 256; distance bound per Lemma 6.2 (p. 52) and perfect simulation against a corrupt Bob (Lemma 6.11).
   The reference paper's objection to the IN96 step is carried as an open question (Finding 3).
7. **F_RelaxedKeyGen.** The registration must deliver a uniform public key with the adversary's
   contribution fixed first (Functionality 3.2 steps 1–2). It does not. **Stops here** (Finding 1). With
   commit-before-reveal, step 1's uniform honest contribution plus extraction of the committed adversarial
   point gives exactly Functionality 3.2's interface, and Theorem 7.2's argument carries over.
8. **Signing.** With steps 3–7, Theorem 4.1 gives statistical UC security of each wallet's signing instance
   against one static corruption; UC composition covers concurrent attempts and wallets under distinct
   `sid`/`sigid`, which rows 11 and 17 supply. BIP32 additive derivation moves the final statement to
   ECDSA with public additive tweaks (row 3), outside Theorem 4.1.

No reduction or theorem number is invented above; the two blocked steps are Findings 1 and 2, and
Finding 3 is a dispute about step 6 between the primary and the reference paper.

---

## E. Remaining questions and scoped decision

Questions for upstream (Silence Laboratories) or an expert reviewer:
1. Is there a written argument that the compiled SoftSpokenOT (all-but-one PPRF, K = 4, 64 trees,
   S = 128, M = 4) over MR19 base OTs realizes Functionality 5.1, including the order "OT outputs fixed
   before θ" used in Claim 6.7? Status of ToB-SILA-13.
2. Position on 2026/976's objection to the Impagliazzo–Naor step for ξ = κ + 2λs: does Silence maintain
   the DKLs23 bound at 512 OTs, or plan a change (more OTs, or deriving `g`/`θ` after the OT round)?
3. Does any audit cover revision `af5ada2a`, the migration abort patch and the duplicate-party-id fix?
4. For the project: confirm that the intended security statement for registered wallets is Theorem 4.1
   via Functionality 3.2 (then commit-before-reveal is required), rather than a separate additive-key
   argument.

Decision: **continue research; remediate; do not adopt yet.**
- Do now, in the experiment: add the contribution commit-before-reveal stage (Finding 1 remediation,
  modelled on Protocol 7.1 steps 2–3); tighten the collector exception (Finding 4); make evidence records
  non-deterministic (Finding 5).
- Do before any adoption decision: obtain written upstream answers to questions 1–3.
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
  tarball in the snapshot reproduced the compiled tree byte for byte. Signing arithmetic and `sl-oblivious`
  parameters are unchanged; the dsg.rs hunk turns a self-id assertion panic into `InvalidMessage`.
- `bootstrap.sh test --locked --offline`: 31 + 1 + 8 + 15 runtime tests passed plus 2 compile-fail doc
  tests (55 + 2). With `--features research-faults`: 31 + 18 + 8 + 14 passed plus 2 (71 + 2); the process
  matrix took 329 s. Union 74 distinct tests, matching the claim.
- 130 schedule records regenerated under `PAIRKEY_ASSURANCE_EVIDENCE_DIR`; names identical to the
  committed inventory, all `passed: true`, all byte-identical to the committed hashes (Finding 5).
- Clippy `-D warnings` in both feature configurations and `cargo fmt --check` passed. Release build and
  demos were not rerun.
- Environment limits: no outbound access to github.com; eprint PDF downloads blocked (HTTP 403); the
  user-supplied DKLs23 PDF was copied into the packet folder via Finder because the sandbox cannot read
  `~/Downloads`.
- Working-tree note: while this review ran, eight tracked files under `experiments/silence-dkls23/`
  (`REVIEW.md`, `lifecycle.rs`, `pooled_process_tests.rs`, `extended_process_tests.rs`, `lib.rs`,
  `pool_worker.rs`, `worker.rs`, `process_probe.rs`) were modified in the checkout between 23:32 and 23:46
  local time by another actor. This review did not touch tracked files; all findings refer to the
  immutable commit `5a6c05ad`, and none of those uncommitted edits were reviewed.
