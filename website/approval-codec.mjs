/** Canonical v1 approval encoding, shared by the browser SDK and its Rust vectors.
 * No private key operations or chain-specific signature arithmetic live here.
 */
export const utf8 = text => new TextEncoder().encode(text);
export const hex = bytes => [...bytes].map(x => x.toString(16).padStart(2, '0')).join('');
export const same = (a, b) => Array.isArray(a) || ArrayBuffer.isView(a)
  ? (Array.isArray(b) || ArrayBuffer.isView(b)) && a.length === b.length && Array.from(a).every((v, i) => same(v, b[i]))
  : a && typeof a === 'object' ? b && typeof b === 'object' && Object.keys(a).length === Object.keys(b).length && Object.keys(a).every(k => Object.hasOwn(b, k) && same(a[k], b[k])) : a === b;
export function check(condition, message) { if (!condition) throw new Error(message); }
const fields = (v, names) => { check(v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k)), 'Invalid canonical fields'); return v; };
const fixed = (v, n) => { check((Array.isArray(v) || v instanceof Uint8Array) && v.length === n && Array.from(v).every(x => Number.isInteger(x) && x >= 0 && x < 256), 'Invalid byte array'); return Uint8Array.from(v); };
export const concat = (...values) => { const out = new Uint8Array(values.reduce((n, v) => n + v.length, 0)); let at = 0; for (const v of values) { out.set(v, at); at += v.length; } return out; };
const num = (n, size) => { check(Number.isSafeInteger(n) && n >= 0 && BigInt(n) < 1n << BigInt(size * 8), 'Integer outside browser-safe range'); const out = new Uint8Array(size); let v = BigInt(n); for (let i = 0; i < size; i++) { out[i] = Number(v & 255n); v >>= 8n; } return out; };
const byte = n => num(n, 1), u16 = n => num(n, 2), u32 = n => num(n, 4), u64 = n => num(n, 8);
const bool = v => { check(typeof v === 'boolean', 'Invalid boolean'); return byte(v ? 1 : 0); };
const list = (v, encode, max) => { check(Array.isArray(v) && v.length <= max, 'Array exceeds protocol bound'); return concat(u32(v.length), ...v.map(encode)); };
const bytes = (v, max = 1232) => { const b = fixed(v, v?.length); check(b.length <= max, 'Bytes exceed protocol bound'); return concat(u32(b.length), b); };
const string = (v, max) => { check(typeof v === 'string', 'String required'); return bytes(utf8(v), max); };
const opt = (v, encode) => v === null ? byte(0) : concat(byte(1), encode(v));
const enumeration = (v, values) => { const i = values.indexOf(v); check(i >= 0, 'Unknown protocol variant'); return byte(i); };
const path = v => list(v, u32, 8);
export const encodeAccount = v => { fields(v, ['destination', 'path']); return concat(fixed(v.destination, 32), path(v.path)); };
export function encodeNamespace(v) {
  fields(v, ['version', 'scheme', 'network', 'registry', 'derivation_authority', 'namespace_id', 'enclave_set']);
  check(v.version === 1 && v.scheme === 'FrostEd25519', 'Unsupported namespace');
  return concat(u16(v.version), byte(0), ...['network', 'registry', 'derivation_authority', 'namespace_id', 'enclave_set'].map(k => fixed(v[k], 32)));
}
export function encodeRegistration(v) {
  fields(v, ['namespace', 'public_shares', 'public_key']);
  check(Array.isArray(v.public_shares) && v.public_shares.length === 2 && !same(v.public_shares[0], v.public_shares[1]), 'Two independent public shares required');
  return concat(encodeNamespace(v.namespace), ...v.public_shares.map(k => fixed(k, 32)), fixed(v.public_key, 32));
}
export function encodeSource(v) {
  fields(v, ['program', 'authority', 'seeds', 'code_hash', 'accounts', 'mode']);
  check(v.program.some(x => x) && v.authority.some(x => x) && (v.mode === 'Offchain' ? v.code_hash.some(x => x) : v.code_hash.every(x => !x)), 'Program code pin required for off-chain evaluation');
  check(new Set(v.accounts.map(a => hex(fixed(a, 32)))).size === v.accounts.length, 'Duplicate program account');
  return concat(fixed(v.program, 32), fixed(v.authority, 32), list(v.seeds, s => bytes(s, 32), 15), fixed(v.code_hash, 32), list(v.accounts, a => fixed(a, 32), 6), enumeration(v.mode, ['Offchain', 'Onchain']));
}
export function identityKind(v) { check(v && Object.keys(v).length === 1, 'One identity variant required'); const kind = Object.keys(v)[0]; check(['Account', 'Passkey', 'Oidc', 'Program'].includes(kind), 'Unknown identity'); return kind; }
export function encodeIdentity(v) {
  const kind = identityKind(v), data = v[kind];
  if (kind === 'Account') { fields(data, ['public_key']); return concat(byte(0), fixed(data.public_key, 32)); }
  if (kind === 'Passkey') { fields(data, ['public_key', 'rp_id', 'origin']); check(data.public_key.length === 33 && [2, 3].includes(data.public_key[0]), 'Compressed P-256 key required'); return concat(byte(1), bytes(data.public_key, 33), string(data.rp_id, 128), string(data.origin, 256)); }
  if (kind === 'Oidc') { fields(data, ['issuer', 'audience', 'subject']); return concat(byte(2), ...['issuer', 'audience', 'subject'].map(k => string(data[k], 256))); }
  return concat(byte(3), encodeSource(data));
}
export function encodeCommit(v) { fields(v, ['registration_digest', 'request_id', 'account', 'message_hash', 'message_len']); return concat(fixed(v.registration_digest, 32), fixed(v.request_id, 32), encodeAccount(v.account), fixed(v.message_hash, 32), u32(v.message_len)); }
export function encodeRules(v) {
  fields(v, ['revision', 'destinations', 'path_prefixes', 'max_payload_bytes', 'payload_prefix', 'disabled']);
  check(v.max_payload_bytes > 0 && v.max_payload_bytes <= 1232 && v.payload_prefix.length <= v.max_payload_bytes, 'Invalid policy limits');
  return concat(u64(v.revision), opt(v.destinations, a => list(a, x => fixed(x, 32), 16)), opt(v.path_prefixes, a => list(a, path, 16)), u32(v.max_payload_bytes), bytes(v.payload_prefix, 128), bool(v.disabled));
}
export function encodeRequest(v) {
  fields(v, ['version', 'identity', 'commit', 'policy_revision', 'policy_digest', 'issued_at', 'expires_at']);
  check(v.version === 1, 'Unsupported approval version');
  return concat(u16(v.version), encodeIdentity(v.identity), encodeCommit(v.commit), u64(v.policy_revision), fixed(v.policy_digest, 32), u64(v.issued_at), u64(v.expires_at));
}
export function encodeBinding(v) { fields(v, ['namespace_digest', 'identity_digest', 'public_key', 'issued_at', 'expires_at']); return concat(fixed(v.namespace_digest, 32), fixed(v.identity_digest, 32), fixed(v.public_key, 32), u64(v.issued_at), u64(v.expires_at)); }
export function encodePolicyUpdate(v) { fields(v, ['namespace', 'identity', 'rules', 'issued_at', 'expires_at']); return concat(encodeNamespace(v.namespace), encodeIdentity(v.identity), encodeRules(v.rules), u64(v.issued_at), u64(v.expires_at)); }
export const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
export const digest = async (label, encoded) => { const name = utf8(label); return sha256(concat(u32(name.length), name, u32(encoded.length), encoded)); };
export const registrationDigest = reg => digest('pairkey/registration/v1', encodeRegistration(reg));
export const namespaceDigest = ns => digest('pairkey/namespace/v1', encodeNamespace(ns));
export const identityDigest = identity => digest('pairkey/approval-identity/v1', encodeIdentity(identity));
export const requestDigest = request => digest('pairkey/offchain-approval/v1', encodeRequest(request));
export const bindingChallenge = binding => digest('pairkey/identity-binding/v1', encodeBinding(binding));
export const policyChallenge = update => digest('pairkey/policy-update/v1', encodePolicyUpdate(update));
export const signingMessage = async request => utf8(`PairKey off-chain approval v1\nRequest: ${hex(await requestDigest(request))}`);
export const jobDigest = async request => digest('pairkey/offchain-job/v1', await requestDigest(request));
export const messageHash = message => sha256(concat(utf8('pairkey/exact-message/v1'), u32(message.length), message));
export async function authority(identity) {
  encodeIdentity(identity);
  if (identity.Account) return fixed(identity.Account.public_key, 32);
  if (identity.Program) return fixed(identity.Program.authority, 32);
  return digest('pairkey/identity-authority/v1', encodeIdentity(identity));
}
const chains = ['solana', 'evm', 'zcash', 'near', 'bitcoin'];
export async function account(chain, derivationPath) {
  path(derivationPath);
  let destination;
  if (chain === 'evm') destination = await digest('pairkey/evm-destination/v1', u64(84532));
  else if (chain === 'bitcoin') destination = await digest('pairkey/bitcoin-bip340-destination/v1', byte(1));
  else destination = await digest('pairkey/hosted-message-destination/v1', enumeration(chain, chains));
  return { destination: [...destination], path: [...derivationPath] };
}
export function encodeKey(v) {
  fields(v, ['version', 'suite', 'namespace', 'account', 'public_key', 'registration']);
  check(v.version === 1, 'Unsupported signing key');
  return concat(u16(v.version), enumeration(v.suite, ['Dkls23Secp256k1', 'FrostRedPallas', 'FrostSecp256k1Tr']), fixed(v.namespace, 32), encodeAccount(v.account), bytes(v.public_key, 65), fixed(v.registration, 32));
}
export async function payload(q, key) {
  const { chain, path, registration } = q.key;
  check(typeof q.message === 'string' && q.message.trim() && utf8(q.message).length <= 256, 'Message must contain 1–256 UTF-8 bytes');
  check(same(key.account, await account(chain, path)), 'Derived key path changed');
  const publicKey = fixed(key.public_key, chain === 'evm' ? 33 : 32);
  check(key.public_key_hex === `0x${hex(publicKey)}`, 'Public key encoding changed');
  const message = utf8(q.message);
  if (chain === 'solana' || chain === 'near') { check(key.multi === null, 'Unexpected signing suite'); return message; }
  const expected = { evm: 'Dkls23Secp256k1', zcash: 'FrostRedPallas', bitcoin: 'FrostSecp256k1Tr' }[chain];
  check(key.multi?.key?.suite === expected && expected, 'Signing suite changed');
  check(same(key.multi.key.public_key, publicKey) && same(key.multi.key.account, key.account) && same(key.multi.key.namespace, await registrationDigest(registration)), 'Signing key namespace changed');
  const typed = chain === 'evm' ? concat(byte(2), u64(84532), bytes(message)) : chain === 'bitcoin' ? concat(byte(3), byte(1), bytes(message)) : concat(byte(1), bytes(message));
  return concat(utf8('pairkey/signing-intent/v1\0'), u16(1), encodeKey(key.multi.key), typed);
}
export function interval(issued, expires, now, maximum) {
  u64(issued); u64(expires); u64(now);
  check(issued <= now && expires > now && expires > issued && expires - issued <= maximum, 'Approval expired or has an invalid validity window');
}
export async function verifyPrepared(value, expected, key, now = Math.floor(Date.now() / 1000)) {
  fields(value, ['signing_request', 'request', 'rules', 'payload', 'signing_message']);
  check(same(value.signing_request, expected.signing_request) && same(value.request.identity, expected.identity), 'Prepared request changed');
  const q = expected.signing_request, bytes = await payload(q, key), r = value.request;
  const commit = { registration_digest: [...await registrationDigest(q.key.registration)], request_id: q.request_id, account: key.account, message_hash: [...await messageHash(bytes)], message_len: bytes.length };
  encodeRequest(r); encodeRules(value.rules);
  interval(r.issued_at, r.expires_at, now, 300);
  check(fixed(q.request_id, 32).some(x => x) && same(r.commit, commit) && same(value.payload, bytes), 'Exact message commitment changed');
  check(same(await authority(expected.identity), q.key.registration.namespace.derivation_authority), 'Approval identity changed');
  check(r.policy_revision === value.rules.revision && same(r.policy_digest, await digest('pairkey/approval-rules/v1', encodeRules(value.rules))), 'Policy commitment changed');
  const rules = value.rules;
  check(!rules.disabled && bytes.length <= rules.max_payload_bytes && same(bytes.slice(0, rules.payload_prefix.length), rules.payload_prefix)
    && (rules.destinations === null || rules.destinations.some(d => same(d, key.account.destination)))
    && (rules.path_prefixes === null || rules.path_prefixes.some(p => same(p, key.account.path.slice(0, p.length)))), 'Request is outside the current policy');
  if (rules.revision === 0) check(rules.destinations === null && rules.path_prefixes === null && rules.max_payload_bytes === 1232 && rules.payload_prefix.length === 0 && !rules.disabled, 'Invalid default policy');
  check(same(value.signing_message, await signingMessage(r)), 'Wallet signing bytes changed');
  return Uint8Array.from(value.signing_message);
}
export const wireBytes = { byte, u16, u32, u64, bool, fixed, bytes, path, list };
