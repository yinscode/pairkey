# Security evidence and outstanding gates

This inventory describes the locked experiment, not a security certification.

## Exact OT/VOLE realization

Cargo metadata identifies compiled `sl-oblivious 1.0.0-beta`. Its lockfile archive
checksum is `31034fa1be3d6b14e26d173b555e0a58b1c1a2bc6ba13ee1ef4c86f39b29b191`.
The inspected archive's following files match the actual registry source byte
for byte. Native DKLS is pinned at `af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7`.

| Compiled code | Role and constants | SHA-256 |
|---|---|---|
| `src/params.rs` | KAPPA=256, LAMBDA_C=256, LAMBDA_S=128, S=128; L_BATCH=2, RHO=1, OT_WIDTH=3; K=4, Q=16; L=512, L_PRIME=640, M=4, 64 PPRF trees | `f6bfeeab0d25ef47f404c78acaccf1578f8afb9776c7c74669386fce432549ab` |
| `src/endemic_ot.rs` | 256 base OTs per direction, secp256k1-based EndemicOT | `3dcc95332a5d6d063a12988f33c55397f8ce1984d749084615c347808de878fc` |
| `src/soft_spoken/all_but_one.rs` | BuildPPRF/evalPPRF with proof checking; cites figures 13–14 of ePrint 2022/192 | `e2876d196689ead18d2e61d54e491507cddd68821dc7b8ebedfb83cf25148aa8` |
| `src/soft_spoken/soft_spoken_ot.rs` | SoftSpoken extension, polynomial correlation check, width-three outputs | `726a0aa845db21291e7617445fa9b80a72d603917e2c893a2afd0fdecf0299d4` |
| `src/rvole.rs` | Source identifies original protocol 5.2; transcript-generated scalar gadget vector, two batched inputs and one check row, theta and mu verification | `4052a0ddd30d8c2446fccb7865bc8c5ea2d3a60f1c21449d7a06fd6b6fa224c1` |

Both routes feed this same implementation into native signing; migration builds
seeds through native DKG, while direct setup uses the exported base-OT/PPRF API.
Fresh seed generation does not repair insufficient VOLE parameters.

**Locked parameters stay unchanged, per the project decision.** We follow the
existing Silence parameter set rather than inventing a patch from the newer
paper. This choice is distinct from establishing historical audit coverage for
this exact revision, dependencies, migration API and custom direct setup.

The full [2026/976 paper](https://eprint.iacr.org/2026/976) is now available locally
at `/Users/user/Downloads/2026-976.pdf` (55 PDF pages, SHA-256
`48922c9af9dc759716207d01492967d3b826f6c52f7913839ad3b07a0e11b784`).
Sections 2.2–2.3 and 4.2–4.6 discuss VOLE variants, concrete OT counts and
challenge/transcript assumptions. These theoretical results do not by themselves
establish a concrete attack against this locked Silence implementation or
certify its security. Translating its exact extension, gadget distribution,
field/check dimensions and transcript construction into the paper's assumptions
requires qualified implementation analysis and upstream resolution. Parameter
names alone do not establish a concrete security level. Keep vendor/auditor
confirmation and independent review open; no OT/VOLE code or constants changed.
The earlier HTTP-403 explanation is retired.

## Zeroization inventory

| Material | Current treatment | Remaining limitation |
|---|---|---|
| Root read buffer, root owner, identity seed, wide KDF output and contribution scalar | `Zeroizing` ownership | HKDF/hash internal state and compiler copies unverified |
| DH seed/static secret and derived channel key | `Zeroizing` seed/key; upstream static-secret clearing | Cipher internals and shared-secret copies require dependency audit |
| Proof nonce and wide entropy | Explicit nonce owner; entropy buffer owner | Copy-valued expression/return temporaries may remain |
| Coins, reveal copy, ordered coin tuple and common zero seed | `Zeroizing` owners; some hash tuples pass references | Native/serde stack copies still possible |
| Application `digest` JSON buffer | Now `Zeroizing<Vec<u8>>` (it can serialize coin material) | Hash state/serde intermediates unverified |
| Setup plaintext serialization/decryption buffers | `Zeroizing<Vec<u8>>` | Deserialization temporaries and serde internal buffers unverified |
| Base-OT serialized peer input and OT reply Vec fields | Peer input clearing; OtReply Drop clears msg2/PPRF | Fixed-size decoded copies and msg1/msg2/PPRF local temporaries not all cleared |
| SenderOTSeed/ReceiverOTSeed owners | Clearing wrapper wipes underlying bytes on Drop | Passing/copying to native packages and opaque intermediates require review |
| Native key package | Native ZeroizeOnDrop; duplicate-ID byte fixture buffer cleared | `as_slice`/construction and Arc/drop timing require dependency review |
| Setup/signing seed owners | Independent fresh `Zeroizing` values per attempt | By-value API copies; native ChaCha RNG state and nonce/VOLE state clearing unverified |
| EndemicOT receiver, sender/receiver outputs; SoftSpoken/RVOLE objects | Opaque upstream ownership | No complete clearing guarantee; no claim of physical erasure |
| Native MPC frames, worker/parent JSON IPC and queued frames | Current ordinary Vec buffers | May contain plaintext R4 contributions; release fencing does not erase transport copies |
| Full ECDSA signatures and public manifests | Public outputs intentionally retained | No secret-erasure requirement for these public values |

KDF wide reduction is **negligibly biased wide reduction**, not unbiased sampling.
Explicit clearing is best effort, not proof that compiler, allocator, OS, crash
dumps or hardware snapshots leave no copies. Roots remain the only persisted
signing secret; that statement is separate from memory-erasure completeness.

## Native error attribution audit

Pinned `proto/tags.rs` verifies signed messages or decrypts peer messages before
calling handlers. Bad signatures/decryption are ignored and eventually become
transport/missing-message/timeout failures. Handler parse/proof failures return
native error variants. In this fixed, validated two-party setup the only remote
participant is attributable; this reasoning must not be generalized to n-party
signing or a different native revision without re-audit.

Signing errors audited exhaustively: InvalidMessage, InvalidCommitment,
InvalidDigest, InvalidFinalSessionID, FailedCheck, K256Error, InvalidPreSign,
MissingMessage, SendMessage, AbortProtocol and AbortProtocolAndBanParty.
Migration errors are also exhaustively matched. Aggregate/local errors freeze
configuration without naming a guilty peer. Context disagreement and peer abort
alone do not establish cheating. The demo's fault selection is a trusted research
fixture, never authorization or evidence by itself.

## Production blockers

Keep recovery and address-preserving refresh, real attestation/provisioning,
hardware entropy, authoritative cross-replica incident/reservation controls,
rollback/snapshot protection, licensing for the intended application, exact
2026 OT/VOLE mapping and independent cryptographic review open. Local root-file
reconstruction demonstrates operator restart; it does not demonstrate user
recovery. Architecture v0.4 remains the reference; neither spike is adopted.
