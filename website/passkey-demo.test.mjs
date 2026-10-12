import test from 'node:test';
import assert from 'node:assert/strict';
import {compressedP256, createDemoPasskey, validPasskeyRecord} from './passkey-demo.mjs';
import {base64url} from './hosted-v2.mjs';

test('passkey registration binds the browser origin and returns only public metadata', async () => {
  const key = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);
  const spki = await crypto.subtle.exportKey('spki', key.publicKey), origin = 'https://pairkey.com';
  const credentials = {create: async ({publicKey}) => ({
    type: 'public-key', rawId: Uint8Array.from([1, 2, 3]),
    response: {clientDataJSON: new TextEncoder().encode(JSON.stringify({type: 'webauthn.create', origin, challenge: base64url(publicKey.challenge)})), getPublicKey: () => spki, getPublicKeyAlgorithm: () => -7},
  })};
  const record = await createDemoPasskey({origin, credentials});
  assert.equal(record.public_key.length, 33);
  assert.deepEqual(record.public_key, await compressedP256(spki));
  assert.equal(validPasskeyRecord(record, origin), true);
  assert.equal(validPasskeyRecord(record, 'https://other.example'), false);
  assert.equal(JSON.stringify(record).includes('private'), false);
});

test('a passkey registration with changed origin is rejected', async () => {
  const credentials = {create: async ({publicKey}) => ({
    type: 'public-key', rawId: Uint8Array.from([1]),
    response: {clientDataJSON: new TextEncoder().encode(JSON.stringify({type: 'webauthn.create', origin: 'https://other.example', challenge: base64url(publicKey.challenge)})), getPublicKey: () => new ArrayBuffer(1)},
  })};
  await assert.rejects(() => createDemoPasskey({origin: 'https://pairkey.com', credentials}), /origin or challenge changed/);
});
