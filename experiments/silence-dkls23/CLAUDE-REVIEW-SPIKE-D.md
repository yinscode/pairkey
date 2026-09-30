# Claude review of Spike D on `codex/spike-d`

2026-10-12. Reviewed the uncommitted tree in the Codex worktree, branch `codex/spike-d` based on
`9ec3890`: the five tracked-file changes and the eleven new files, the design note
`SPIKE-D-DONOR-DESIGN.md`, the report `SPIKE-D-REPORT.md` and the ignored evidence directory. Every
code claim below was checked against the pinned native source `af5ada2a` and `sl-oblivious
1.0.0-beta`. Both full suites were rerun independently from a hashed copy of the uncommitted tree in
an isolated snapshot, see section 6. No exploit is asserted; this is not a security approval.

## 1. What was built, and how it relates to the brief

The report states that the owner's correction replaced the brief's migration route with a donor route,
so I review the donor route on its own terms. It is the shared-setup design co-reviewed in
[CLAUDE-CO-REVIEW-SHARED-SETUP.md](CLAUDE-CO-REVIEW-SHARED-SETUP.md), with one improvement over what I
assumed there: the donor material is RAM-only and rotated by a fresh native DKG, so persisted secrets
remain roots only. The flow is derivation version 2, commit-then-reveal registration with journals,
one native DKG per pair for an unused donor key whose OT seeds and zero seed are extracted by fixed
layout, a transient package per attempt through the research constructor, native signing with a hedged
seed, and a failure policy that retires the donor on every failure and fences the pairing on
attributable ones.

Consequences of the choice, relative to the brief's migration route:
- Kept: the research constructor, so O2 applies; shared OT and zero-seed material across wallets, so the
  cross-wallet composition question O3/O4 applies; registration in PairKey code, so O1 applies with the
  ordering now in place.
- Gained: roots-only persistence with a flat per-wallet cost after one donor DKG per boot, and donor
  material produced by audited key generation rather than by the exported-primitive pool. Spike C's
  pool is strictly dominated by this route.
- Lost: the removal of O2 and of the splice that migration would have given, at the price of one
  migration per wallet per boot.

This is a legitimate option. It belongs in the decision record beside O-C' as a new option, and the
choice between them turns on whether the constructor and the cross-wallet composition question are
acceptable obligations to carry to Silence in exchange for the flat cold-wallet cost.

## 2. Verified against the native source

| Claim | Check | Result |
|---|---|---|
| Extraction offsets: header 172, two party entries of 98, zero seed at offset 66 of entry 0, OT region at 368 | `keygen/keyshare/details.rs`, my layout test | correct; runtime size checks fail closed |
| The donor keyshare is dropped after extraction and the copies are zeroized | `material.rs:86-99`, `Clearing` drop | correct; native `ZeroizeOnDrop` clears the share |
| Round-1 guard parses the native signed frame correctly | `proto/signed.rs:24, 112-133, 187-194`: layout `hdr, payload, trailer, signature`, signature over everything before the last 64 bytes; `MESSAGE_HEADER_SIZE` is 36; `SignMsg1` is 97 bytes with the session id first | correct; the soak's observed final session ids confirm the guard captured real frames |
| Reconstructed final session id equals native | `sign/dsg.rs:162-167` | correct, same fold order |
| Registration order: reserve, own commitment journaled, exchange, peer commitment journaled, ordered acknowledgement, reveal release journaled, reveal, verify, prepare, endorse, activate | `d_worker.rs:149-241` | correct; no reveal before the peer commitment is durable |
| Reserved-only state on restart retires the wallet slot | `d_worker.rs:128-130`, `journal.rs:114-119` | correct |
| Generation agreement precedes native signing; both instance ids journaled with create-new; counter issued before the seed | `d_worker.rs:376-410` | correct |
| Hedged seed keeps entropy and binds instance, counter, role and operation | `d.rs:288-305` | correct |
| Every command failure retires the donor; retirement failures surface as errors while RAM is still cleared | `d_worker.rs:93-103, 582` | correct, the text-match defect is gone |
| Failure classification | `lifecycle.rs` mappings reused; matrix test asserts action and persisted incident | peer violations quarantine the pairing, aggregate failures freeze, context and transport burn without quarantine |
| Derivation v2 binds pairing, namespace, epoch, version, role and wallet id, and checks the root's identity against the wallet | `d.rs:65-93` | correct |

## 3. Findings

1. **Design, medium.** The constructor and the shared donor material are custom composition. The
   report says so; the decision record and the Silence questions should carry it as a distinct option
   with O2, O3 and O4 attached, and the donor pattern should be added to the questions as the concrete
   case. Not a defect in the code.
2. **Test gap, medium.** No test shows that an incident raised during one wallet's attempt fences a
   different wallet's next attempt with the same peer, nor that it survives a worker restart. The gate is
   pairing-scoped, so this should already hold; assert it, since pairing-wide scope is the central
   safety property of a shared donor.
3. **Robustness, low.** The guard treats a duplicate delivery of the peer's authenticated round-1 frame
   as a replay, which burns the attempt and the donor. Correct for the exactly-once research transport;
   a production transport with at-least-once delivery needs deduplication in front of the guard.
4. **Growth, low.** The round-1, instance and abort journals add files per signature and the rate check
   scans a directory per command. Public data, no security issue; a retention rule is needed before any
   long soak in production shape.
5. **Lifecycle, low.** When one side reaches prepared and the other retires, the prepared side keeps a
   dead record forever. An authenticated retirement notice from the peer would let it retire too;
   retirement only reduces availability, so the notice cannot be abused.
6. **Policy, low.** Every failure, including a registration context mismatch, costs a donor DKG. The
   rate limit bounds forced churn to three transport events per minute. Acceptable; note it in the
   operational limits.
7. **Scope, informational.** The Schnorr possession proof is not load-bearing under section 7 of the
   paper; it is harmless identity binding. The chain code keeps the version-1 rule, which is right for
   this route. Records are pinned to source bytes through the configuration digest, so any code change
   invalidates every record; deliberate, but it needs a versioning policy before anything long-lived.
8. **Evidence semantics, informational.** Distinct aggregate `r` values across 1,000 signatures is a
   weak witness for nonce freshness, as the report says. The strong guarantees are the own-side round-1
   journal, which refuses a repeated session id before it is sent, and the hedge, both tested directly.

No security defect was found in the code paths reviewed. The sequential worker means the concurrent
native attempts in the tests exercise the package construction, not a multiplexed service.

## 4. The report's priority gaps, assessed

1. Shared donor OT and zero-share security across wallets, paths and concurrent sessions, including
   constructor assumptions: agreed, and it is the O3 lemma plus the zero-seed sharing, which only Silence
   or a composition reviewer can close. The implementation already enforces what the rules require:
   fresh session ids, retirement on failure, bounds, pairing-wide fencing.
2. Carrying a malicious but accepted donor setup into signing: worth one scratch test to document that an
   accepted setup with a leaked base choice signs normally, which is the leaky-correlation model, not a
   defect; the mitigation is retirement on the first visible failure and the bounds, both present.
3. Overlapping worker processes: real for a production service, moot for the sequential worker; the
   pairing-wide gate and the instance journals are the right primitives, and finding 2 above is the first
   test to write.
4. Registration extraction and adaptive selection: the ordering is implemented; what remains is the
   written mapping to Functionality 3.2, the same obligation as before.
5. Rollback, cross-host authority, power loss and memory remnants: documented limits, unchanged.

## 5. Latency, as measured by the report

At zero injected delay: registration 95 ms once per wallet, donor DKG 134 ms once per pair per boot or
rotation, warm signature 77 ms. The warm path is two authenticated context exchanges plus journal
writes plus the four native rounds; folding the generation and instance exchanges into one message, or
into the request itself, would bring it toward Spike C's 25 ms online figure. At 50 ms delay the warm
signature is 384 ms against 653 ms for Spike A's per-attempt refresh.

## 6. Independent rerun

A copy of the uncommitted worktree's experiment directory was overlaid on a `git archive` of
`9ec3890` in an isolated snapshot, with the native archive copied in and file hashes recorded, and
both suites were run through `bootstrap.sh test --locked --offline` with separate temporary and
evidence directories.

Default features: 75 passing test entries, no failures, exit=0; per binary: ok. 47 passed; 0 failed; 4 ignored; 0 measured; 0 filtered out; finished in 10.03s;ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s;ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 2.04s;ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 100.05s;ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s;ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s;

Fault-enabled features: 103 passing test entries, no failures, exit=0; per binary: ok. 47 passed; 0 failed; 4 ignored; 0 measured; 0 filtered out; finished in 9.54s;ok. 30 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 327.24s;ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 2.05s;ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 98.84s;ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s;ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.29s;

The counts match the report: 73 runtime tests plus 2 compile-fail checks in the default configuration, 101 runtime tests plus 2 compile-fail checks with faults enabled. Hashes of every source, manifest and script in the copied tree are in `review-evidence/spike-d-claude-rerun.output.txt` together with the filtered logs. Clippy, formatting and the soak and benchmark binaries were not rerun here.

## 7. Recommendation

Accept the branch as an experiment and commit it. Record the route in the decision record as a new
option beside O-C', with the trade stated: roots-only persistence and flat per-wallet cost, against the
constructor and the cross-wallet composition question. Add the tests in finding 2 and the dedup note in
finding 3 before any concurrent or networked variant. Carry the donor pattern, the zero-seed sharing
and a usage bound into the Silence questions. Spike C's pool can be retired in favour of this route.

## 8. Paste-ready TL;DR for Sol

Reviewed `codex/spike-d` against the pin and reran both suites independently from a hashed copy.
Verified: extraction offsets and zeroization; the round-1 guard's frame parsing against
`proto/signed.rs` and its final-session reconstruction; registration ordering with journals;
reserved-only retirement; generation agreement, instance journals and counter before the seed; the
hedge; donor retirement on every failure with truthful errors; the failure classification; derivation
v2. No security defect found. Findings: add a cross-wallet and cross-restart fence test; dedupe
duplicate deliveries before the guard for any at-least-once transport; retention for the per-signature
journals; a peer retirement notice for the stuck-prepared case; a configuration versioning policy
before anything long-lived. The route is the shared-setup design with RAM-only donor material, which
is a better trade than I assumed: roots-only persistence, flat per-wallet cost, donor material from
audited key generation, strictly dominating Spike C's pool. It keeps the constructor, so O2, and the
cross-wallet composition question, so O3 and O4, which go to Silence. Recommend committing and adding
the route to the decision record beside O-C'.
