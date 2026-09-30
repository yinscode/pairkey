# Derived share flow and native OT reuse

2026-10-11. Design recommendation for the pinned Silence implementation,
`af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`. No registration, implementation,
native parameter or dependency change. Read with the
[O3/O4 review](O3-O4-DEEP-DIVE.md) and
[migration analysis](DERIVED-SHARES-VIA-MIGRATION.md).

The smallest custom composition surface is root-derived additive contributions,
an agreed public record, native migration, and reuse of the complete native
package. This removes the custom constructor and wallet-independent pool from
that candidate route. It does not close derived-input assumptions, migration
audit coverage, or the inherited compiled OT realization question.

## Share representation and generation

For the two-party, threshold-two, rank-zero configuration:

| Route | Input | Output |
|---|---|---|
| Original Spike C | Root-derived additive contributions a and b | Locally constructed Shamir representation plus pooled material |
| Native DKG | Fresh random polynomial contributions | Native Shamir shares and a complete signing package |
| Native refresh | Existing Shamir shares, coordinates and public metadata | Fresh shares for the same key and fresh OT/zero seeds |
| Native migration | Additive contributions, expected public key and chain code | Fresh native Shamir shares and a complete signing package |

Spike C registration records A=aG, B=bG and Q=A+B. Package construction uses
s0=a/2 at coordinate 1 and s1=-b at coordinate 2. Reconstruction is
2*s0-s1=a+b. These are evaluations of a degree-one polynomial with constant
a+b; algebraic validity alone does not establish the native generation
protocol's commitment, provenance or malicious-peer guarantees.

Native refresh converts an existing share to an additive contribution using
its reconstruction coefficient: c_i=lambda_i*s_i. Migration accepts c_i
directly and enters the same core. That core samples fresh polynomials,
overrides their constants with c_i, commits and verifies contributions,
distributes evaluations and validates the resulting shares. Pass a and b
directly to migration; manufacturing Shamir shares merely to convert them back
adds no benefit. The resulting native shares need not equal a/2 and -b.

Source anchors: `src/pool.rs:406`, `src/worker.rs:261`; in the pinned native
crate, `src/keygen/key_refresh.rs:269`, `src/keygen/migration.rs:64`, and
`src/keygen/dkg.rs:207`.

Migration requires an agreed Q and chain code. The existing registration
contract does not become equivalent to native DKG merely by switching the
consumer. Ordinary DKG does not accept root-derived constants; the proposed
[Mode 2 API](MODE-2-MINIMAL-SPEC.md) separates that change from recovery.
The upstream README marks migration unaudited, despite its shared refresh core.

Ordering precision: native OT1 is prepared and fed to the relay before the
expected-key check. That check precedes processing peer OT1 and constructing
OT2/PPRF replies (`dkg.rs:293-340, 418-469`). Do not describe it as occurring
before any OT message is sent.

## Creation and reuse of native OT material

1. DKG, migration or refresh performs base OT in both directions.
2. Native PPRF construction and verification produce the two directional seed
   sets retained in the keyshare, alongside its share, coordinates, zero seeds,
   public metadata and native session identity.
3. Signing reads these seed sets and performs fresh session-specific extensions;
   it does not repeat base OT. SenderOTSeed feeds RVOLEReceiver, and
   ReceiverOTSeed feeds RVOLESender.
4. Each signing invocation uses fresh RNG input. Native signing combines fresh
   R1 session contributions with the package session ID and derives directional
   MtA identifiers. RVOLE samples fresh online choices.

Source anchors in the pinned native crate: `src/keygen/dkg.rs:445-550` and
`src/sign/dsg.rs:75-98, 162-213, 289-313`. These are implementation facts, not
a completed malicious-security reduction.

Section 8.2 of the [2023 paper](https://eprint.iacr.org/2023/765) assumes setup
once per party pair and reuse across extension instances in its cost model.
That supports investigating reuse; it does not by itself prove arbitrary
cross-wallet transplantation of the compiled seed representation.

## Proposed reuse rules for PairKey

- Keep the complete native package together and agree its generation with the
  peer. Reuse it for that wallet's native signing and supported child paths;
  do not splice its seeds into unrelated wallet packages.
- Use fresh private entropy and a unique protocol instance for every new
  signing attempt. Stored setup seeds are reusable; signing nonces,
  presignatures and attempt-specific RVOLE state are not.
- Preserve native session derivation and peer/role mappings. Treat a package
  replacement as a coordinated generation change, not a unilateral cache update.
- On an attributable ban-triggering failure, stop current and affected concurrent
  sessions and quarantine the peer under the incident contract. Fresh OT,
  migration or refresh must not clear that incident.
- An ordinary transport failure does not establish cheating. Abandon interrupted
  attempt state; any permitted new invocation uses fresh randomness and IDs.
  The stricter Mode 2 draft discards the affected cached package on failure.
- Rotate material through native refresh, which regenerates shares, OT seeds
  and zero seeds together. Retire the previous generation after coordinated
  replacement. Rebuilding from unchanged roots does not provide proactive
  protection against eventual compromise of both roots.
- Protect package secrets and RNG/state continuity. RAM-only caching requires
  rebuilding after restart; it does not protect against hostile snapshots.
- Do not claim an unlimited concrete lifetime. Request the permitted usage
  bounds, concurrency assumptions and exact failure scope from Silence.

The present Spike C pool still has its single-use rule. Native package reuse is
a different route, not permission to unreserve or recycle a consumed pool entry.

## Recommended candidate and remaining questions

Derive contributions, establish the public record, run native migration, retain
the whole package and call native signing. With roots-only secret persistence,
cache the package in RAM and recover it after restart using the recorded Q and
chain code. Public metadata and incident-state continuity remain necessary.

This is a recommendation, not approval to change registration or deploy the
construction. Resolve the derived-input/first-registration contract, obtain
explicit migration coverage, retain the O5 failure authority, and resolve O6
audit-to-pin correspondence. O3's exact compiled OT functionality and fixing
order remain an upstream question even when the wallet-independent pool is
removed. Keep Silence parameters and dependencies unchanged.
