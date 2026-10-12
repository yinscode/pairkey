import {base64url} from './hosted-v2.mjs';

const fromBase64url = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(value.length / 4) * 4, '=')), c => c.charCodeAt(0));

export function validPasskeyRecord(record, origin) {
  return record?.version === 1 && record.origin === origin && record.rp_id === new URL(origin).hostname &&
    Array.isArray(record.public_key) && record.public_key.length === 33 &&
    [2, 3].includes(record.public_key[0]) && record.public_key.every(x => Number.isInteger(x) && x >= 0 && x <= 255) &&
    Array.isArray(record.credential_id) && record.credential_id.length > 0 && record.credential_id.length <= 1024 &&
    record.credential_id.every(x => Number.isInteger(x) && x >= 0 && x <= 255);
}

export async function compressedP256(spki, subtle = crypto.subtle) {
  const key = await subtle.importKey('spki', spki, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
  const jwk = await subtle.exportKey('jwk', key);
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) throw new Error('The passkey did not provide a P-256 public key.');
  const x = fromBase64url(jwk.x), y = fromBase64url(jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new Error('The passkey returned an invalid P-256 public key.');
  return [y[31] & 1 ? 3 : 2, ...x];
}

export async function createDemoPasskey({origin = location.origin, credentials = navigator.credentials, subtle = crypto.subtle} = {}) {
  if (!origin.startsWith('https://') && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) throw new Error('Passkeys require HTTPS or localhost.');
  if (!credentials?.create) throw new Error('This browser does not support passkey creation.');
  const rpId = new URL(origin).hostname, challenge = crypto.getRandomValues(new Uint8Array(32));
  const credential = await credentials.create({publicKey: {
    challenge, rp: {name: 'PairKey demo', id: rpId},
    user: {id: crypto.getRandomValues(new Uint8Array(32)), name: 'PairKey demo', displayName: 'PairKey demo'},
    pubKeyCredParams: [{type: 'public-key', alg: -7}], timeout: 60000,
    authenticatorSelection: {residentKey: 'preferred', userVerification: 'required'}, attestation: 'none',
  }});
  if (credential?.type !== 'public-key' || !credential.rawId?.byteLength || !credential.response?.getPublicKey) throw new Error('Passkey creation did not return a usable credential.');
  const client = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
  if (client.type !== 'webauthn.create' || client.origin !== origin || client.challenge !== base64url(challenge) || client.crossOrigin || client.topOrigin) throw new Error('Passkey registration origin or challenge changed.');
  if (credential.response.getPublicKeyAlgorithm && credential.response.getPublicKeyAlgorithm() !== -7) throw new Error('The passkey must use P-256 ES256.');
  const spki = credential.response.getPublicKey();
  if (!spki) throw new Error('This browser cannot export the passkey public key.');
  const record = {version: 1, origin, rp_id: rpId, credential_id: [...new Uint8Array(credential.rawId)], public_key: await compressedP256(spki, subtle)};
  if (!validPasskeyRecord(record, origin)) throw new Error('Passkey registration returned invalid metadata.');
  return record;
}

export function passkeyIdentity(record) {
  if (!validPasskeyRecord(record, location.origin)) throw new Error('Saved passkey belongs to a different site or is invalid.');
  return {Passkey: {public_key: [...record.public_key], rp_id: record.rp_id, origin: record.origin}};
}
