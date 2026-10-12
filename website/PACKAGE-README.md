# `@pairkey/sdk`

Browser SDK for PairKey hosted v2 programmable threshold keys. One client supports
Solana account, Solana program, passkey, and OIDC authorities.

```sh
npm install @pairkey/sdk @solana/web3.js
```

Until the first npm release is available, use the source from
[the PairKey repository](https://github.com/yinscode/pairkey/tree/main/website).

## Connect and derive a key

```js
import * as web3 from '@solana/web3.js';
import {PairKeyClient} from '@pairkey/sdk';

const pairkey = new PairKeyClient({web3, storage: localStorage});
await pairkey.connect({
  source: 'account',
  wallet: window.phantom.solana,
  namespace: 'org/acme/treasury',
});
const key = await pairkey.key({chain: 'solana', path: [0]});
```

Named namespaces are case-sensitive NFC strings. The SDK maps the label to the
protocol's stable 32-byte namespace ID. You can pass `namespaceId` directly for
compatibility.

## Sign and send a transaction

```js
const signed = await pairkey.signTransaction({
  chain: 'solana', path: [0], transaction,
});
const sent = await pairkey.signAndSend({
  chain: 'solana', path: [0], transaction, connection,
});
console.log(sent.transactionId, sent.status);
```

Solana legacy and v0 messages, EIP-155 legacy native transfers on chain 84532,
and canonical NEAR transactions are supported. Bitcoin Taproot/PSBT and Zcash
transaction adapters are not implemented. Message signing remains available on
all five configured suites.

The SDK stores the public signing job before approval and the exact signed
transaction before broadcast. If the destination RPC times out, keep the returned
job ID and recover without another approval:

```js
const recovered = await pairkey.recoverAndSend(jobId, {
  chain: 'solana', connection, rebroadcast: true,
});
```

## Authentication sources

```js
await pairkey.connect({source: 'program', wallet, program, mode: 'Onchain',
  namespace: 'org/acme/treasury', policyScope: 'namespace'});

await pairkey.connect({source: 'passkey', identity, credentialId,
  namespace: 'user/alice'});

await pairkey.connect({source: 'oidc', identity, namespace: 'user/alice',
  getIdToken: ({nonce}) => obtainIdToken({nonce})});
```

Passkey and OIDC create a short-lived nonexportable Ed25519 binding for each
approval. The ephemeral key authenticates the exact PairKey request; it does not
change the deterministic derived key.

## Program policy management

```js
import {ProgramClient} from '@pairkey/sdk/program';

const programClient = new ProgramClient({web3, wallet, programId,
  mode: 'Onchain', policyScope: 'namespace', storage: localStorage});
await programClient.connect({namespace: 'org/acme/treasury'});
await programClient.setPolicy({
  chain: 'solana', pathPrefix: [0], remainingApprovals: 5,
});
```

`policyScope: 'namespace'` stores rules at
`["pairkey-policy", owner, namespace_digest]`. Use `'shared'` to retain the older
`["pairkey-policy", owner]` layout across all of that owner's namespaces.

Policy edits and onchain program approvals are explicit owner-signed Solana
transactions. Destination broadcast is performed by the application through its
RPC connection. Verify the returned key, signature, approval, and both signer
receipts before relying on a result.

## Publish from this repository

```sh
cd website
npm pack --dry-run
npm login
npm publish --access public
```

Publishing the `@pairkey/sdk` scope requires npm organization permission. Bump the
version before every subsequent release.
