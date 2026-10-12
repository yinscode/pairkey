import test from 'node:test';
import assert from 'node:assert/strict';
import {readGoogleClaims, showGoogleButton} from './google-oidc.mjs';

function token(claims) {
  const encoded = btoa(JSON.stringify(claims)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  return `header.${encoded}.signature`;
}
const now = Math.floor(Date.now() / 1000);
const claims = {iss: 'https://accounts.google.com', aud: 'client', sub: 'stable-subject', iat: now, exp: now + 300, nonce: 'bound'};
test('identity discovery is provisional and a bound token must match subject and nonce', () => {
  assert.deepEqual(readGoogleClaims(token(claims), 'client'), {issuer: claims.iss, audience: claims.aud, subject: claims.sub});
  assert.deepEqual(readGoogleClaims(token(claims), 'client', {subject: claims.sub, nonce: 'bound'}).subject, claims.sub);
  for (const options of [{subject: 'other'}, {nonce: 'other'}, {issuedAfter: now + 1}]) {
    assert.throws(() => readGoogleClaims(token(claims), 'client', options), /different account/);
  }
  for (const changes of [{aud: 'other'}, {iss: 'https://other.example'}, {exp: now - 1}]) {
    assert.throws(() => readGoogleClaims(token({...claims, ...changes}), 'client'), /different account/);
  }
  assert.throws(() => readGoogleClaims('broken', 'client'), /unreadable/);
});
test('Google button uses a fresh binding nonce only for the approval phase', async () => {
  const calls = [], container = {replaceChildren: () => calls.push('clear')};
  globalThis.google = {accounts: {id: {
    initialize: value => calls.push(value), renderButton: (_, options) => calls.push(options),
  }}};
  try {
    await showGoogleButton(container, {audience: 'client', onCredential: () => {}});
    await showGoogleButton(container, {audience: 'client', nonce: 'bound', onCredential: () => {}});
    assert.equal(calls[0].nonce, undefined);
    assert.equal(calls[3].nonce, 'bound');
  } finally { delete globalThis.google; }
});
