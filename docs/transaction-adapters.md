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
20-byte recipient, and value. The existing EIP-155 adapter validates the supported
chain and gas bounds, computes the signing hash, normalizes the ECDSA signature,
and returns complete signed RLP bytes. Contract calls, calldata, EIP-1559, access
lists, and arbitrary RLP are outside this adapter.

### NEAR

Input is a canonical Borsh `Transaction`. The adapter validates account IDs,
nonce, block hash, bounded actions, and that the transaction's Ed25519 access key
is the derived key. Workers sign SHA-256 of the unsigned transaction and return a
Borsh `SignedTransaction`. Account creation and access-key installation remain an
application setup step.

## Bitcoin adapter requirements

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

Until this exists, the current Bitcoin signature is a PairKey message signature,
not a Taproot spend signature or BIP-322 message signature.

## Zcash adapter requirements

A safe Zcash transaction API must define the supported pool and authorization
roles. An initial Orchard implementation needs:

1. A wallet/prover-produced transaction plan with network and branch ID.
2. Note commitments, witnesses, nullifiers, recipients, values, fee, expiry, and
   bundle commitments validated against application policy.
3. ZIP-244 transaction digest and Orchard spend-authorization rules implemented
   independently in both workers.
4. Correct randomized spend authorization keys/signatures rather than using the
   static RedPallas message key as an interchangeable spend signature.
5. Proof and binding-signature assembly with a canonical transaction result and
   test vectors from the protocol implementation.

Until these requirements are implemented, PairKey's RedPallas result is a message
signature and cannot authorize a shielded spend.
