# Destination transaction adapters

## Implemented

### Solana

Input is the canonical serialized legacy or v0 transaction message. The adapter
parses and reserializes it, validates bounds, and requires the PairKey-derived
Ed25519 key in the required static signer set. Workers sign the exact message
bytes. The browser inserts the 64-byte signature at that signer position. The
application owns blockhash selection, address lookup tables, fee payer choice,
other signatures, broadcast, and confirmation.

### EVM

Input is a typed legacy native transfer: chain ID, nonce, gas price, gas limit,
20-byte recipient, and value. The EIP-155 adapter binds a selected chain ID to
the derived key and exact approval, validates the chain and gas bounds, computes
the signing hash, normalizes the ECDSA signature,
and returns complete signed RLP bytes. Contract calls, calldata, EIP-1559, access
lists, and arbitrary RLP are outside this adapter.

The hosted v2 API now has an explicit `evm_chain` key selector. It preserves the
existing Base Sepolia selector and derives a separate account destination for
each EIP-155 chain ID. The browser client accepts `chainId` with `chain: 'evm'`.
The deployment advertises this with `evm_chain_selection`; an older deployment
will reject the new selector. This is chain selection for the existing legacy
native-transfer adapter, not general EVM transaction support.

### EIP-712 typed data

The hosted API accepts an `EvmTypedData` request containing the complete JSON
object and selected chain ID. The approval commits to every JSON byte. Both
workers parse the complete type graph, domain and values with Alloy, check
`domain.chainId` against the derived EVM destination, and compute the EIP-712
signing hash. A caller-supplied digest is not accepted. The signature is checked
as low-S recoverable ECDSA; the browser API also returns `evmSignatureHex` with
`v` set to 27 or 28. JSON is limited to 1,000 UTF-8 bytes to fit the hosted
approval bound. Applications must choose exact domain and message values.

This is a typed-data signature, not an EVM transaction. Aave lending still
needs an EVM transaction adapter for calldata, contract addresses, token
allowance and EIP-1559 fees. Hyperliquid actions have their own exact encoding
and signing schemes; generic EIP-712 support alone does not make them valid.

### NEAR

Input is a canonical Borsh `Transaction`. The adapter validates account IDs,
nonce, block hash, bounded actions, and that the transaction's Ed25519 access key
is the derived key. Workers sign SHA-256 of the unsigned transaction and return a
Borsh `SignedTransaction`. Account creation and access-key installation remain an
application setup step.

## Bitcoin Taproot PSBT · source preview

The source now contains a restricted BIP-174/BIP-371 adapter in
`crates/pairkey-signing/src/bitcoin_psbt.rs`. The hosted request is
`bitcoin_psbt: { spend: { network: "testnet", psbt, outputs, max_fee_sats,
max_fee_rate_sat_vb } }`, where `psbt` and every `script_pubkey` are byte arrays.
It accepts a canonical PSBT v0 with **one** PairKey-owned Taproot key-path
input, one or two exact outputs, `SIGHASH_DEFAULT`, both witness and complete
non-witness UTXO data, and no script-path or unrelated metadata. The previous
transaction ID and witness UTXO must agree. Each worker independently checks
ownership, outputs and fee caps and computes the BIP-341 sighash. The service
returns a signed PSBT and finalized raw transaction bytes. The browser client
can broadcast with a callback or a Bitcoin JSON-RPC `sendrawtransaction` URL.

This is a repository source preview. The public service and published npm SDK
must be updated together before this path is available on pairkey.com. A PSBT
above the 1,232-byte exact-approval envelope is rejected even if it is below
the adapter's 1,024-byte PSBT field limit. Multi-input PSBTs, script-path
spends, mainnet, arbitrary sighash modes and wallet coin selection are outside
the first adapter. The application still has to inspect the exact recipient and
change outputs, outpoint, sequence and locktime before approval and verify the
funding transaction against a trusted Bitcoin node.

### Bitcoin adapter requirements for expansion

A safe Bitcoin transaction API needs more than a 32-byte digest:

1. Accept a PSBT or a typed transaction plus every spent output's amount and
   scriptPubKey.
2. Restrict supported inputs initially to Taproot key-path spends controlled by
   the derived x-only key.
3. Validate network, input ownership, UTXO commitments, outputs, change, absolute
   fee, fee rate, locktime, sequence, and allowed sighash type.
4. Compute BIP-341 sighashes inside both workers from the complete validated
   transaction context.
5. Bind policy to each input, recipient outputs, maximum fee, and change rules.
6. Return signatures by input index and assemble/finalize the PSBT without changing
   committed fields.

The original `signMessage` format remains a PairKey-tagged message signature,
not a Taproot spend signature or BIP-322 message signature.

## Zcash PCZT adapter · testnet library alpha

A safe Zcash transaction API must define the supported pool and authorization
roles. A new shielded escrow after NU6.3 should use the Ironwood pool in a
version-6 transaction and version-2 ZIP-374 Partially Created Zcash Transaction
(PCZT). An Orchard-pool withdrawal can be a smaller first signing test, but
cannot serve as a new Orchard-pool escrow payment. The adapter needs:

1. A wallet/prover-produced PCZT with network and branch ID. Use the upstream
   `pczt` and Orchard implementations for canonical parsing and role boundaries.
2. Note commitments, nullifiers, recipients, values, fee, expiry, and bundle
   commitments validated against application policy. Version-6 witnesses and
   anchors may be added later by the wallet/prover.
3. The transaction-version-appropriate signature digest and Orchard-protocol
   spend-authorization rules implemented independently in both workers.
4. Orchard-compatible account setup and randomized spend authorization
   keys/signatures rather than using a raw RedPallas message signature as an
   interchangeable spend signature. The testnet alpha explicitly defers
   ZIP-2005-compatible recovery enrollment and makes no recovery guarantee.
5. Orchard signature contributions inserted into the PCZT, followed by the
   wallet/prover's proof and binding-signature assembly and extraction. Check
   canonical transaction results against upstream ZIP-374 and ZIP-244 vectors.

The feature-gated `pairkey-signing` library now validates a restricted v6
Ironwood PCZT, computes its shielded sighash, and inserts a threshold RedPallas
spend signature. It accepts one real Ironwood action and one output, on testnet,
in a PCZT v2 of at most 256 KiB. The worker, hosted API, published SDK, and
wallet/prover integration are still absent. The released `signMessage` result
remains an application signature and cannot authorize a shielded spend.

The PCZT library exposes shielded sighashes and an external-signature
insertion API, but that alone is insufficient. PairKey must bind the full PCZT
to an exact approval without exceeding the current 1,232-byte envelope, link
its RedPallas authorization key to an Orchard full viewing key, verify the
PCZT action's randomized key against its spend randomizer, and evaluate visible
note values, recipients, fee and change before issuing a threshold signature.
For version-6 transactions, anchors and witnesses may be supplied after
signing, so they are prover checks rather than fields committed by the
spend-authorization signature.
The present worker and SDK do not provide those checks or PCZT assembly.
The proposed wallet-to-PairKey request fields and account setup sequence are
specified in [Orchard PCZT signing integration contract](zcash-pczt-integration.md).
