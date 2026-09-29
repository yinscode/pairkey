# DKLS23 root-only persistence research spikes

Isolated workspace on branch `silence-dkls23`. This directory is not a member of
the PairKey production workspace. FROST, the parent Cargo.lock, Solana programs
and architecture v0.4 are unchanged. These are local research experiments;
none of these routes is adopted as the production ECDSA backend.

## Reproduce

From the project root, with Rust 1.88 or newer:

```sh
bash experiments/silence-dkls23/bootstrap.sh build --release --features research-faults --locked
bash experiments/silence-dkls23/bootstrap.sh test --features research-faults --locked --offline
bash experiments/silence-dkls23/bootstrap.sh clippy --all-targets --features research-faults --locked --offline -- -D warnings
target/silence-dkls23/release/dkls-spike demo .local/silence-dkls23/my-run 3
target/silence-dkls23/release/dkls-spike pool-demo .local/silence-dkls23/my-pool-run 3
target/silence-dkls23/release/dkls-spike compare .local/silence-dkls23/my-comparison 3
```

Bootstrap downloads a checksummed source archive at revision
`af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7` into ignored `.local`, applies the
documented research patches, and uses a separate target directory and
lockfile. Crates `sl-oblivious` and `sl-mpc-mate` are pinned to `1.0.0-beta`;
all transitive resolutions are locked. The first build requires network access.
Use `--offline` on later builds when the archive and crates are cached.

Choose a new ignored output directory for a clean run. Roots already present
there are intentionally reused to exercise restart. Existing incident records
and reservation tombstones are never cleared by the demo. Rerunning a completed
fault suite in the same directory can therefore refuse earlier than expected.

The output is `evidence.json`, containing public manifests, verified signatures,
timings and refusal diagnostics. Root files are random development secrets,
mode 0600 in a mode-0700 directory. They are unsealed local fixtures, not TEE
provisioning. Never commit the run directory or use these keys for assets.

## Spike A: transient migration packages

Each side derives an additive contribution from its own provider root using
HKDF-SHA512, scheme-specific labels, key ID and role, with wide reduction modulo
the secp256k1 order. Public contributions are proven and identity signed. Their
sum pins the aggregate public key. The public chain code is deterministically
bound to the key ID and aggregate public key, then included in the manifest pin.

Each attempt runs `migration::run` with fresh private randomness, the pinned
aggregate key and chain code. The library performs interactive resharing and OT
setup and creates fresh packages. It then runs the complete signing entry point
with a separate fresh private seed. Packages are dropped; nothing is serialized
to disk. Migration shares and coordinates may change between attempts even
though the input contributions and root/child public keys remain stable.

Migration is explicitly outside the repository's advertised audit coverage.
This route tests reconstruction from roots through an existing interactive API.
It is not the direct deterministic-share construction and is not a low-latency
baseline with cached setup.

## Spike B: deterministic shares with fresh OT

For additive contributions `a_A` and `a_B`, library participant IDs are 0 and 1,
coordinates are 1 and 2, ranks are zero, and threshold is 2:

```text
s_A = a_A / 2       S_A = s_A G
s_B = -a_B         S_B = s_B G
Q = a_A G + a_B G = 2 S_A - S_B
```

The added typed constructor checks this weighted relation, the local secret
relation, participant bounds, nonidentity points and nonconstant sharing. It
fixes the supported metadata instead of exposing generic setters. Remote OT
correlation and malicious setup security cannot be checked by this constructor.

Both processes establish a fresh identity-authenticated X25519 channel bound to
the manifest, boots, route, entry, attempt, path and exact prehash. A commit/reveal
coin exchange supplies the zero-share seed. Two native EndemicOT exchanges, one
in each direction, plus native PPRF expansion create matching SenderOTSeed and
ReceiverOTSeed material. The package is built in RAM, full `sign::run` generates
the signature, and application-owned secrets are dropped. Native signing math
is unchanged. The known duplicate-party-ID comparison is corrected separately. A feature-gated native fixture corrupts a migration PPRF proof before encryption; native arithmetic remains unchanged.

This baseline generates OT setup synchronously for every attempt. It does not
implement a wallet-independent background pool. The extra coin exchange,
reservation and readiness messages are included in total latency. The pool's
key-independent composition and failure security remain questions for review.

## Spike C: deterministic shares with idle preprocessing

Two long-lived workers authenticate signed boot identities and ephemeral DH
keys. Each two-slot pool entry runs fresh native EndemicOT/PPRF and zero-coin
commit/reveal before any wallet or message is selected. Canonical setup inputs,
ordered validated transcript and authenticated completion ACKs bind provenance.
The later consumption context binds that provenance to the wallet public pin,
path, exact prehash, mock policy receipt/version and fresh attempt ID.

Reservation removes seeds from availability and fsyncs an irreversible public
tombstone. Authenticated peer agreement precedes reconstruction of deterministic
shares and one transient native package. Consumption enters the native signing
InstanceId, package `extra_data`, and package final SID, which the native library
folds into its signing/MtA SIDs. A fresh private signing seed is generated only
then; the worker calls full `sign::run` and independently verifies its output.
The pool contains no ECDSA nonce or presignature. Native parameters and signing
math are unchanged.

Idle refill is scheduled automatically by the trusted driver, separately from
the measured online interval. Each worker serializes commands; there is no
concurrent sign/refill wire multiplexing. A full or empty pool refuses; expiry,
substitution, cancellation, timeout, disconnect or other failure burns affected
ownership and discards the generation. Incidents also fence available/reserved
entries and remain effective across complete worker replacement. See `POOLING.md`
for the exact encoding, native SID mapping and remaining security questions.

## Process and lifecycle boundaries

In A/B each operation creates two distinct worker processes; in C a pair serves multiple wallets/paths; each reads only its own
root file. The parent coordinates public registration and relays signed native
MPC messages and encrypted custom setup messages. The parent is a trusted local
test driver, not a production authorization service. Roots are provisioned by
that driver; no aggregate signing scalar is reconstructed by the experiment.

Both workers check their own root against the public manifest and authenticate
the peer's boot evidence and share possession proof. This is a development
registration experiment, not proof of KDF compliance by a malicious participant
or a complete production commit/reveal registration ceremony. The manifest is
pinned in the parent and compared across complete process replacements.

Before setup, each side creates and fsyncs an irreversible public reservation
record. The record never returns to availability. Cancellation, failure and
restart leave it retired. Fresh retries use new IDs, setup and signing randomness.
No reusable presignature API is exposed.

Failures carry structured phase, kind, authenticated peer attribution, incident
action, publication-attempt/persistence outcome, and a separate abort-send-failure
flag. Migration preserves the original violation even when its abort send fails. Direct setup parsing after successful AEAD,
commit/reveal violations and native migration/signing violations use the same
policy. Unattributed aggregate/local errors freeze configuration. See the
failure-policy table in `REVIEW.md`.

An incident is scoped by ordered stable peer identities and fixed protocol
configuration, spanning wallets, paths, attempts and both routes. A shared gate
serializes native Sink output handoff (including R4 partials) with publication,
not just final result delivery. Publication stops the local gate before fsync
and wakes active native signing futures. The same-process regression pauses two
actual signings immediately before R4, publishes an incident, then verifies
no affected R4 reaches the actual transport queue after cutoff. A positive control
observes both ordinary R4 handoffs; a deliberate test-only gate bypass observes
both late handoffs, even when cancellation returns an error. Unused future ownership is denied by the same gate.

The cutoff is transport-queue handoff under the shared gate's lock. Material
queued before publication is already considered released and may arrive later;
it cannot be recalled. Gates acquired for the same authority path and signer role share one lock in a
process; integration must use that shared authority consistently. The A/B harness creates one attempt per worker
process; C uses long-lived sequential workers; the concurrent in-process test uses the shared primitive directly.
Across processes, each handoff checks its scoped durable marker, but this is
now serialized with publication under an advisory OS lock held through the actual
queue handoff. Both role markers deny use of the pairing; idle workers poll the
authority every 100 ms for cancellation. This applies only to cooperating
processes sharing one honest local filesystem. Cross-host/replica authority and
snapshot protection remain required before production adoption.

The parent handles stdout termination and closed pipes separately from worker
failures. It preserves structured terminal diagnostics through either abort
ordering and gives both streams a bounded two-second drain grace before killing
workers. A drain timeout explicitly reports unknown missing diagnostics and
persistence; it is not evidence of a protocol violation. Host crashes can still
prevent detection from reaching durable authority.

Incident publication is applied once per failure; the outer handler only reports
that result. An existing marker is checked for a complete 32-byte record and
re-synced with its parent directory. An empty/partial marker keeps the gate closed
but never counts as confirmed persistence. A new explicit publication can confirm
a complete earlier record only after actually repeating the durability operations.

The filesystem ledger assumes an honest authority and does not resist rollback.
Tombstones remain burned after cancellation, errors and replacement; an explicit
test establishes that rewinding the ledger permits reuse. TEE snapshots remain
untested. `extra` and `final_session_id` provide binding; they do not prevent
package reuse.

Fault injection is disabled by default. The full demo requires the explicit
`research-faults` Cargo feature, which also gates the native migration fixture.
A default build refuses a nonempty fault request; no product integration is added.

## Validation and measurements

The demo alternates three wallet key IDs, root and `m/7/3` paths, both routes,
and repeated fresh process pairs. It independently checks native ECDSA signatures,
low-S encoding, recovery IDs and public child derivation. It also checks four
concurrent same-wallet process pairs, mismatched operation/metadata bindings,
malformed authenticated OT, corrupted OT correlations, duplicate native party IDs,
cancellation, fresh cancellation retry, reused reservations and durable incidents.
The regression suite also covers structured failure policy, terminal ordering, closed pipes, same-process partial-release fencing and pooling-specification ownership. See `REVIEW.md` for the current counts.

Timings are wall-clock measurements on this computer. `setup_ms` includes each
route's interactive setup; `signing_ms` covers full signing plus local verification;
`wall_ms` includes worker launch, boot registration, IPC and readiness. Wire counts
include library subscription messages and custom setup frames; they are not a
claim about network flights or RTTs. JSON framing adds overhead. This is not a
Phala/Oyster, cross-region, production authorization or throughput benchmark.

See `results-authority.json` for the local cross-process authority follow-up.
`results.json`, `results-pool.json` and `results-comparison.json` preserve the
pre-authority A/B/C evidence at `4d2e21c`; `results-lifecycle.json` preserves
the independently reviewed c33a1e1 lifecycle run. `results-baseline.json` contains
the original measurements. `REVIEW.md` documents results/failure policy;
`POOLING.md` documents the implemented research context/ownership design;
`SECURITY-REVIEW.md` retains the source inventory and open gates.

## Open gates

Passing signatures establishes functional compatibility, not malicious security.
The locked Silence OT/VOLE parameters stay unchanged. Upstream resolution of the
2026/976 analysis and coverage of the custom composition remain open. The pinned
candidate and dependencies are not certified by the historical audit. The
constructor, registration, zero-sharing exchange, single-use setup composition,
failure taxonomy and retry rules require independent review.

Opaque upstream EndemicOT, RNG and signing intermediates may leave memory copies.
Explicit Rust clearing and worker termination do not prove physical erasure.
Hardware entropy, real attestation, clone/snapshot protection, authoritative
incident controls, recovery and address-preserving refresh are not implemented.
Public additive child derivation shares the root family's compromise scope.

The included Silence license and NOTICE apply to this standalone research
resulting program. Research without current monetization does not establish
commercial or future product rights. No commercial license has been asserted.

Sources: [migration](https://github.com/silence-laboratories/dkls23/blob/af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src/keygen/migration.rs),
[package](https://github.com/silence-laboratories/dkls23/blob/af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src/keygen/keyshare.rs),
[signing](https://github.com/silence-laboratories/dkls23/blob/af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/src/sign/dsg.rs),
[audit](https://github.com/silence-laboratories/dkls23/blob/af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7/docs/ToB-SilenceLaboratories_2024.04.10.pdf),
[2026 analysis](https://eprint.iacr.org/2026/976).
