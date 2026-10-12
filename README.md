<p align="center">
  <a href="https://pairkey.com"><img src="website/mark.svg" width="72" alt="PairKey"></a>
</p>

<h1 align="center">PairKey</h1>

<p align="center">
  Programmable keys for every application.<br>
  Connect an authority, choose a chain, and ask PairKey to sign.
</p>

<p align="center">
  <a href="https://pairkey.com"><strong>Website</strong></a> ·
  <a href="https://pairkey.com/demo"><strong>Live demo</strong></a> ·
  <a href="https://pairkey.com/docs.html"><strong>Documentation</strong></a> ·
  <a href="https://pairkey.com/docs/quickstart.html"><strong>Quickstart</strong></a> ·
  <a href="https://pairkey.com/docs/supported-chains.html"><strong>Supported chains</strong></a>
</p>

PairKey gives a Solana account, Solana program, passkey, or OIDC identity a
stable set of keys across multiple chains. The application approves one exact
request, two signers produce the destination signature, and the application
decides where to send it.

There is no complete private key for the application to store. Developers use
one client for key derivation, message signing, transaction signing, delivery,
and recovery.

## The short version

```js
import * as web3 from '@solana/web3.js';
import {PairKeyClient} from './website/pairkey-client.mjs';

const pairkey = new PairKeyClient({web3, storage: localStorage});

// 1. Choose who controls the keys.
await pairkey.connect({
  source: 'account',
  wallet: window.phantom.solana,
  namespace: 'org/acme/treasury',
});

// 2. Derive a stable key for a chain and purpose.
const key = await pairkey.key({chain: 'sui', path: [0]});
console.log(key.address);

// 3. Approve and sign one exact request.
const signed = await pairkey.signMessage({
  chain: 'sui',
  path: [0],
  message: 'Approve order 1842',
});

console.log(signed.jobId, signed.signatureHex);
```

That same `key`, `signMessage`, `signTransaction`, `signAndSend`, and `recover`
interface works after connecting any authority source.

The browser package is prepared for its first npm release. Until it is
published, use [the SDK source in this repository](website/pairkey-client.mjs)
and follow the [package usage guide](website/PACKAGE-README.md).

## Why developers use PairKey

- **One API for four authority sources.** Accounts, programs, passkeys, and
  OIDC identities use the same key and signing methods.
- **One authority can control many chain keys.** Namespace, destination, and
  path select stable keys without a registration transaction.
- **Every approval binds the exact request.** Chain, path, payload, request ID,
  expiry, and current policy revision are checked before signing.
- **Policy is optional and reusable.** Start without creating a policy account;
  add destination, path, payload, application, or budget rules when needed.
- **Broadcast stays in the application.** PairKey signs; your application keeps
  control of its destination RPC and confirmation rules.
- **Recovery does not sign again.** A job ID retrieves the original threshold
  result and saved transaction bytes after a timeout or reload.

## One lifecycle

```text
Account · Program · Passkey · OIDC
                 │
                 ▼
       namespace + chain + path
                 │
                 ▼
          stable public key
                 │
                 ▼
        approve exact request
                 │
                 ▼
          signer A + signer B
                 │
                 ▼
      signature → send or recover
```

The namespace gives a key a business or security purpose. For example:

```text
org/acme/treasury + Sui + path [0]  → operating account
org/acme/treasury + Sui + path [1]  → reserve account
user/alice/trading + EVM + path [0] → trading account
```

Changing policy does not rotate a key. Changing the authority, PairKey
deployment, namespace, destination, or path selects a different key. See
[Keys and namespaces](https://pairkey.com/docs/keys-and-namespaces.html).

## Choose an authority

| Authority source | What identifies it | How one request is approved | Start here |
| --- | --- | --- | --- |
| Solana account | Wallet public key | Wallet message signature | [Account quickstart](https://pairkey.com/docs/quickstart-account.html) |
| Solana program | Program and controller PDA | Read-only program evaluation or on-chain commit | [Program quickstart](https://pairkey.com/docs/quickstart-program.html) |
| Passkey | Credential key, RP ID, and origin | WebAuthn assertion binds a fresh ephemeral approval key | [Passkey quickstart](https://pairkey.com/docs/quickstart-passkey.html) |
| OIDC | Issuer, audience, and subject | ID token binds a fresh ephemeral approval key | [OIDC quickstart](https://pairkey.com/docs/quickstart-oidc.html) |

Passkey and OIDC use a fresh ephemeral key to authenticate one exact PairKey
request. That ephemeral key does not hold destination assets and does not change
the stable derived address.

## Sign a transaction

Your application builds the destination transaction with the chain's normal
SDK. PairKey authenticates the exact canonical payload and returns the native
signed form.

```js
// Sign and assemble without contacting a destination RPC.
const signed = await pairkey.signTransaction({
  chain: 'solana',
  path: [0],
  transaction,
});

// Or sign, submit, and return the destination status.
const sent = await pairkey.signAndSend({
  chain: 'solana',
  path: [0],
  transaction,
  connection,
});

console.log(sent.transactionId, sent.status);
```

`signTransaction` never broadcasts. `signAndSend` uses the connection, RPC URL,
or custom broadcast callback supplied by the application.

## Supported chains

| Destination | Message signing | Transaction signing | `signAndSend` |
| --- | --- | --- | --- |
| Solana | Ed25519 | Legacy and v0 transaction messages | Solana connection |
| EVM | EIP-191 with secp256k1 | Restricted EIP-155 legacy native transfer | EVM RPC URL |
| NEAR | Ed25519 | Canonical Borsh transaction | NEAR RPC URL |
| Sui | Ed25519 application message | BCS `TransactionData` | Sui client |
| Bitcoin | BIP-340 tagged message digest | Adapter pending | Adapter pending |
| Zcash | RedPallas message signature | Adapter pending | Adapter pending |

The public deployment advertises current capabilities at
[`GET /api/v2/config`](https://pairkey.com/api/v2/config). See
[Supported chains](https://pairkey.com/docs/supported-chains.html) for working
examples for all three operations on every destination.

## Recover an uncertain result

PairKey stores the public signing job before approval and the exact signed
transaction before the first broadcast attempt. If an RPC response is lost,
recover the same job instead of creating another signature:

```js
const recovered = await pairkey.recover(sent.jobId);

if (sent.status === 'unknown') {
  await pairkey.recoverAndSend(sent.jobId, {
    chain: 'solana',
    connection,
    rebroadcast: true,
  });
}
```

A completed signing job, an RPC submission ID, and finalized destination
execution are separate states. Check the destination before replacing an
uncertain transaction with a new nonce or blockhash.

## Add policy when the application needs it

Authentication answers **who approved this request**. Policy answers **what that
authority is allowed to approve**.

Standard rules can restrict destination, derivation path, payload size, prefix,
availability, or remaining approvals. A Solana controller program can enforce
application state such as membership, recipient, amount, proposal status,
allowance, or a consumable nonce.

Program approval has two modes:

- `pairkey_approve` evaluates immutable program logic without broadcasting an
  authorization transaction.
- `pairkey_approve_commit` changes application state and records the exact
  approval through CPI in one Solana transaction.

Read [Policy and rules](https://pairkey.com/docs/policy.html) and the
[program-controlled key guide](https://pairkey.com/docs/quickstart-program.html).

## Explore the repository

| Path | Purpose |
| --- | --- |
| [`website/`](website/) | Browser SDK, live site, demo, and generated documentation |
| [`sdk/`](sdk/) | Rust SDK and hosted approval types |
| [`programs/pair-registry/`](programs/pair-registry/) | Namespace, rules, and approval records on Solana |
| [`programs/example-controller/`](programs/example-controller/) | Program-controlled policy and approval example |
| [`crates/pairkey-signing/`](crates/pairkey-signing/) | Chain signing adapters and native digest rules |
| [`crates/pairkey-worker/`](crates/pairkey-worker/) | Independent signer protocol and authorization checks |
| [`crates/pairkey-coordinator/`](crates/pairkey-coordinator/) | Threshold job coordination and recovery |
| [`docs/`](docs/) | Architecture, implementation evidence, deployment, and review boundaries |

Useful technical references:

- [Hosted approval API](docs/offchain-approval-api.md)
- [Hosted deployment evidence](docs/offchain-approval-deployment.md)
- [Architecture v0.4](docs/architecture-v0.4.md)
- [Transaction adapters](docs/transaction-adapters.md)
- [Multi-suite signing](docs/multi-suite-signing.md)
- [Implementation status and remaining gates](docs/implementation-status.md)

## Run the checks

Fast checks for the browser SDK, documentation, and chain signing adapters:

```sh
node --test website/*.test.mjs
python3 website/check-site.py
cargo test -p pairkey-signing --locked
cargo test -p pairkey-sdk --locked
```

The complete local platform requires Rust 1.88.0, Python 3.12+, curl, and the
repository's pinned Agave, Anvil, and SBF tools:

```sh
python3 scripts/install-ci-tools.py
source .local/ci-tools/env.sh
bash experiments/silence-dkls23/bootstrap.sh build --release --locked
bash scripts/build-programs.sh
bash scripts/ci.sh
```

See [CI and local EVM sessions](docs/ci-and-evm-sessions.md) and
[Operator testnet setup](https://pairkey.com/docs/testnet.html) for the full
environment and deployment flow.

## Development deployment status

The hosted v2 endpoints are served under `https://pairkey.com/api/v2`. Its
[public configuration](https://pairkey.com/api/v2/config) describes the active
deployment, and the [live demo](https://pairkey.com/demo) exercises it.

The current public deployment runs two development signer processes on one host
and reports `hardware_backed: false`. It does not yet demonstrate independent
hardware-backed TEEs, separate provider governance, production attestation,
rollback resistance, independent state sources, external cryptographic review,
or permanent root-loss recovery. Do not submit confidential messages or valuable
funds to the development service.

Read [Security and status](https://pairkey.com/docs/security.html) before relying
on PairKey in a production design.
