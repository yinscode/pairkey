# ADR 001: experimental FROST construction for the local platform

Status: adopted for controlled local tests only. Architecture v0.4 remains the reference. This decision does not establish production suitability or replace its recovery design.

The platform plan governs implementation order over the older Hyperliquid MVP. Ed25519/FROST and exact-byte Solana COMMIT come first. ECDSA, SESSION, SIMULATE, consumer authentication, agents, Hyperliquid, and recovery implementation remain later phases.

## Objects and invariants

A **provider root** is a persistent, independent 32-byte secret for one signing domain. A **worker** is a replaceable process that reconstructs shares from that root and public metadata; its pending signing nonces exist only in memory. Worker statelessness does not mean there are no persistent secrets, no public registry state, or no memory rollback risk.

A **namespace** is an immutable tuple of protocol version, scheme, authorization network identity, registry program, original derivation authority, namespace identifier, and enclave-set identity. Its current controller can be governed independently of its immutable derivation authority. A **derived account** adds a destination domain and bounded sequence of path components. A **request** permanently authorizes the hash and length of exact bytes for that account. An **attempt** adds a fresh random identifier. An enclave-set identity binds the two independently enrolled participant identities; an endpoint hostname alone is insufficient.

For participant IDs A=1 and B=2, each side derives its scalar with HKDF-SHA512 from its own root, a fixed salt, a scheme/version label, the canonical namespace digest, and its role. Public interpolation uses `P = 2*S_A - S_B`. No participant or relay computes the aggregate secret. Registration requires both role-bound possession proofs, prime-order nonidentity public shares, the interpolation check, and agreement authenticated by the enrolled domain identities.

Account derivation hashes a fixed label, canonical namespace, root public key, and account path with SHA512, then reduces the 64-byte output modulo the Ed25519 scalar order. Each side adds that same public tweak to its scalar; the SDK computes `P + t*G`. This is a custom derivation/proof ceremony. It is not RFC 9591 functionality and is not established as audited by a constructor accepting these packages.

Canonical public data uses Borsh, bounded vectors, fixed-length identities, explicit enums, and a protocol version. Digests are SHA256 with domain separation and length framing. Exact-message authorization uses SHA256 over `pairkey/exact-message/v1`, little-endian u32 message length, and original bytes. Allowed message lengths are 1–1232 bytes; destination transactions may impose stricter limits. Signing always passes original bytes to FROST, never their authorization hash.

## COMMIT and failures

Initial COMMIT records are append-only permanent approvals for those bytes. Repeating a signature is allowed. A different transaction blockhash, nonce, recipient, or any other byte requires a new approval. No destination-independent exactly-once execution guarantee, business-policy parsing, cancellation, expiry, or aggregate budget is implied. Response records cache a verified result.

Mutable namespace freezing and enclave-set retirement, when enabled, require current independent observations in both workers. Provider responses are trusted inputs, not consensus proofs. A local validator or mock view cannot establish the production state-provider assumptions. Coordinators supply references and bytes; each worker checks its own chain view, owner, PDA, namespace metadata, and request digest.

Fresh OS randomness drives each local proof and FROST nonce; production requires validated protected provider entropy. Round-two nonce state is atomically removed before validation, so even invalid finishes burn the attempt. Crashes abort rather than resume attempts. Each worker holds at most 64 pending attempts; cancellation removes abandoned nonces. Cryptographic inconsistency is an incident requiring refusal and investigation; it is not silently retried as a timeout.

## Root durability, upgrades, and loss

Each provider must expose a stable application identity whose secret survives authorized worker replacement. Domain A and B must have independently controlled, timelocked release authorities, separate approvers and credentials, and independently validated image measurements. Registry upgrades are another authority and must be governed explicitly. No one administrative authority may release both roots to arbitrary replacement code.

Without recovery, permanent loss of either provider root strands all namespaces derived from the pair. Changing a root changes addresses. Local development root files demonstrate replacement with intact provisioning only; they do not implement recovery or hardware secrecy.

The proposed Phase 9 escrow covers an entire provider root, not an owner. For B recovery, B's escrow must require live A authorization plus an independent cold authority C, a registry recovery record, timelock, cancellation opportunity, and an approved replacement B′ attestation. Derive independent wrapping contributions scoped to B's stable application identity and recovery epoch; reconstruct the wrapping key only inside B′ using confidential attested channels from A and C. Mirror the design independently for A. Neither C alone nor one operator approval releases a root. Exact cryptographic envelope, historical escrow bounds, approver deployment, and measured recovery are unresolved release gates. No address-preserving refresh is claimed for independent KDF roots.

## Dependency boundary and gates

Pinned FROST release: `frost-ed25519 = 2.2.0`, default features disabled, serialization and cheater detection enabled for protocol messages. The application does not serialize secret key packages. Host compiler baseline: Rust 1.88.0. Native output is a 64-byte Ed25519 signature, to be checked by Dalek and the Solana verifier.

The upstream NCC audit description names v0.6.0 and covers key generation and signing. Version 2.2.0 and PairKey's injected KDF shares, Schnorr possession proofs, package reconstruction, public tweaks, channels, and authorization are not asserted to be covered by that audit. Upstream licenses are MIT or Apache-2.0; dependency lockfile is included with the implementation. See [upstream audit scope](https://github.com/ZcashFoundation/frost#ncc-audit) and [FROST source](https://github.com/ZcashFoundation/frost).

**Unmet production gates:** independent custom-cryptography review; real Phala/Oyster attestation, provisioning/restart and upgrade probes; entropy, clock, snapshot/cloning and nonce fencing evidence; independently governed root release; selected loss policy and recovery implementation. The user has no provider accounts yet and authorized continuing local work. No hardware properties are inferred from local tests.

Dependency selection correction: core 2.1.0 is yanked. Pinning all three FROST crates at 2.2.0 incorporates the refresh-threshold security fix; refresh is not exposed by this wrapper. [Upstream 2.2.0 release](https://zfnd.org/frost-2-2-0-release/).

Historical escrow bound: if escrow is encrypted using contributions derivable from a static peer root and static C key, extracting both contributions permits offline recovery of the other root from retained ciphertext. Timelocks and replacement-attestation checks govern honest release; they do not revoke extracted historical material. An extracted pair of provider roots is a permanent signing quorum for all existing derived accounts, regardless of registry controls. No refresh claim changes that bound.
