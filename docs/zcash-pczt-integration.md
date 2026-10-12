# Zcash PCZT signing integration contract

Status: **testnet alpha, library only**. A feature-gated source adapter validates
a restricted v6 Ironwood PCZT, computes its shielded sighash, and inserts an
externally produced spend authorization signature. The two-party randomized
RedPallas signature verifies with Orchard 0.16. No PairKey worker, hosted
endpoint, or published SDK accepts this request yet. The alpha does not offer
ZIP 2005 quantum recoverability. Raw RedPallas `signMessage` signatures do not
authorize Orchard transactions.

## Account setup before receiving funds

PairKey must enroll an Orchard-protocol-compatible threshold spend-authorizing
key and return its matching spend-validating key. The wallet needs a matching
full viewing key and address to discover notes and derive witnesses. The current
library test constructs those components locally, but PairKey has no supported
account-enrollment or wallet setup API. Do not deposit funds into a purported
PairKey escrow address while that API and the hosted signing flow are absent.

This alpha intentionally defers ZIP 2005 recovery enrollment. For a new FROST
account that claims future quantum recoverability, ZIP 2005 requires the
participants to privately agree on `sk` and derive `nk`, `qsk`, `qk`, and
`rivk_ext` with `use_qsk = true` and the jointly generated `ak`. An arbitrary
wallet-supplied `nk` and `rivk` cannot establish that property. An account
created by the alpha must be described as **not guaranteed to be recoverable**
under a future Zcash Recovery Protocol. This limitation does not prevent an
otherwise valid v6 spend-authorization signature today. The Recovery Protocol
itself remains a future proposal; alpha signing does not implement it.

The source adapter normalizes the registered RedPallas public key and FROST
shares to Orchard's even-Y encoding and signs with the action's randomizer.
It checks a caller-provided full viewing key against that normalized key.
This does not establish ZIP 2005's private `sk` / `qsk` enrollment or prove
that the viewing key was derived from it. The current Orchard dependency does
not expose that enrollment path.

## Signing request

The wallet/prover constructs a ZIP-374 PCZT with all fields needed to inspect
the spend and output. The source alpha accepts a version-6 transaction in a
version-2 PCZT, with exactly one Ironwood action containing one real spend and
one output; transparent, Sapling, and Orchard bundles are rejected. It is
testnet-only and caps the serialized PCZT at 256 KiB. The older
Orchard pool can still be spent from, but NU6.3 forbids new value entering it
and restricts its actions to the same address. A version-5 Orchard-only adapter
would therefore be a migration/withdrawal slice, not a new shielded escrow
payment. A future request should
carry these fields in one recoverable signing job:

| Field | Supplied by | Purpose |
| --- | --- | --- |
| `network`, `branch_id` | Wallet | Select the Zcash consensus rules and transaction-version digest. |
| `pczt_bytes` | Wallet/prover | Exact PCZT attachment, including Ironwood actions and signer context. |
| `pczt_commitment` | Client | Domain-separated hash and byte length committed by the Solana approval. |
| `full_viewing_key` | Wallet/account setup | Link the note and action to the registered PairKey spend-validating key; disclose only the viewing context needed by the signer. |
| `expected_outputs`, `max_fee`, `expiry` | Application policy | Values the approving controller can inspect and enforce. |
| `job_id` | PairKey | Recover the same PCZT and signature after an uncertain response. |

The PCZT can exceed the 1,232-byte Solana approval limit. Its bytes therefore
need a size-bounded attachment carried to **both** workers; the exact approval
contains a domain-separated commitment to those bytes. Each worker hashes its
own received attachment and independently parses the PCZT. A caller-supplied
ZIP-244 digest alone is insufficient.

The wallet/prover provides the spend randomizer and enough note/output context
for the workers to verify the exact spend in a signer-redacted PCZT or accompanying
wallet context. The note witness and proof data may remain with the prover if
the selected transaction version permits signing before proving. It never
provides the spend-authorizing secret key to PairKey. PairKey's two shares
produce the randomized Orchard spend authorization signature. The PCZT signer
role inserts that signature. The wallet/prover remains responsible for proof
generation, bundle binding authorization, transaction extraction, broadcast
and confirmation.

## Checks before a threshold signature

Both workers must independently verify PCZT syntax and consensus branch,
commitment, registered full viewing key, each action's randomized key and
spend randomizer, note/nullifier/value commitments, recipients, change,
fee and expiry. They then compute the version-appropriate shielded sighash from the
validated PCZT, sign only that digest with randomized FROST shares, and
verify the resulting signature against the action's randomized key. Reject
unsupported pools, actions, incomplete wallet context, preexisting
signatures and any mismatch with the approved output and fee policy.

The source test suite (`cargo +1.90 test -p pairkey-signing --features
zcash-pczt-tests`) now builds a version-6 Ironwood PCZT using Zcash's
transaction builder, validates its fee/output rules, signs it with two PairKey
RedPallas shares, inserts the signature, and rejects altered attachment bytes
or payout policy. The fixture deliberately does not establish a ZIP 2005
`use_qsk` account; it tests transaction signing only. The tested dependency path
requires Rust 1.90, while the repository baseline still targets Rust 1.88.
An initial **non-recoverable testnet alpha** can defer ZIP 2005 key enrollment.
It still requires an account setup API, an attachment transport that keeps
viewing/note data out of public receipts, a worker and SDK signing flow,
upstream ZIP-374 and transaction-version digest vectors, and an end-to-end
Ironwood testnet spend assembled by an independent wallet/prover. Until those
checks pass, the hosted Zcash transaction capability remains disabled. Add
ZIP 2005 enrollment before claiming future recoverability for new escrow funds.
