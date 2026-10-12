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
const MASK64=(1n<<64n)-1n;
const BLAKE2B_IV=[0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n];
const BLAKE2B_SIGMA=[[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],[11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],[9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],[12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],[6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3]];
const rotr64=(value,bits)=>((value>>BigInt(bits))|(value<<BigInt(64-bits)))&MASK64;
const read64=(block,offset)=>{let value=0n;for(let i=7;i>=0;i--)value=(value<<8n)|BigInt(block[offset+i]);return value;};
const write64=(out,offset,value)=>{for(let i=0;i<8;i++){out[offset+i]=Number(value&255n);value>>=8n;}};
/** Blake2b-256 used by Sui addresses and transaction intent signing. */
export function blake2b256(input){
  input=Uint8Array.from(input);const h=[...BLAKE2B_IV];h[0]^=0x01010020n;
  const compress=(block,count,last)=>{const m=Array.from({length:16},(_,i)=>read64(block,i*8)),v=[...h,...BLAKE2B_IV];v[12]^=BigInt(count)&MASK64;v[13]^=BigInt(count)>>64n;if(last)v[14]^=MASK64;
    const g=(a,b,c,d,x,y)=>{v[a]=(v[a]+v[b]+x)&MASK64;v[d]=rotr64(v[d]^v[a],32);v[c]=(v[c]+v[d])&MASK64;v[b]=rotr64(v[b]^v[c],24);v[a]=(v[a]+v[b]+y)&MASK64;v[d]=rotr64(v[d]^v[a],16);v[c]=(v[c]+v[d])&MASK64;v[b]=rotr64(v[b]^v[c],63);};
    for(const s of BLAKE2B_SIGMA){g(0,4,8,12,m[s[0]],m[s[1]]);g(1,5,9,13,m[s[2]],m[s[3]]);g(2,6,10,14,m[s[4]],m[s[5]]);g(3,7,11,15,m[s[6]],m[s[7]]);g(0,5,10,15,m[s[8]],m[s[9]]);g(1,6,11,12,m[s[10]],m[s[11]]);g(2,7,8,13,m[s[12]],m[s[13]]);g(3,4,9,14,m[s[14]],m[s[15]]);}
    for(let i=0;i<8;i++)h[i]=(h[i]^v[i]^v[i+8])&MASK64;
  };
  let offset=0;while(offset+128<input.length){compress(input.slice(offset,offset+128),offset+128,false);offset+=128;}const last=new Uint8Array(128);last.set(input.slice(offset));compress(last,input.length,true);
  const out=new Uint8Array(32);for(let i=0;i<4;i++)write64(out,i*8,h[i]);return out;
}
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
/** Map a human-readable namespace label to the protocol's existing 32-byte ID.
 * Labels are case-sensitive NFC strings. The domain and length framing are part
 * of the stable v1 mapping; changing either would select different keys. */
export async function namedNamespaceId(label) {
  check(typeof label === 'string', 'Namespace label must be a string');
  const canonical = label.normalize('NFC'), encoded = utf8(canonical);
  check(canonical === label, 'Namespace label must use Unicode NFC normalization');
  check(encoded.length > 0 && encoded.length <= 128, 'Namespace label must contain 1–128 UTF-8 bytes');
  check(!/[\u0000-\u001f\u007f]/u.test(canonical), 'Namespace label must not contain control characters');
  return [...await digest('pairkey/named-namespace/v1', bytes(encoded, 128))];
}
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
const chains = ['solana', 'evm', 'zcash', 'near', 'bitcoin', 'sui'];
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
function transactionPayload(q, key) {
  const transaction=q.transaction;
  check(transaction && Object.keys(transaction).length===1 && q.message==='', 'Choose one typed transaction');
  if(transaction.solana){
    check(q.key.chain==='solana' && key.multi===null,'Solana transaction/key mismatch');
    fields(transaction.solana,['message']);
    return concat(utf8('pairkey/transaction-intent/v1\0'),byte(0),bytes(transaction.solana.message,1232));
  }
  if(transaction.near){
    check(q.key.chain==='near' && key.multi===null,'NEAR transaction/key mismatch');
    fields(transaction.near,['transaction']);
    return concat(utf8('pairkey/transaction-intent/v1\0'),byte(1),bytes(transaction.near.transaction,1024));
  }
  if(transaction.sui){
    check(q.key.chain==='sui' && key.multi===null,'Sui transaction/key mismatch');
    fields(transaction.sui,['transaction']);
    return concat(utf8('pairkey/transaction-intent/v1\0'),byte(2),bytes(transaction.sui.transaction,1197));
  }
  if(transaction.evm_legacy){
    check(q.key.chain==='evm' && key.multi?.key?.suite==='Dkls23Secp256k1','EVM transaction/key mismatch');
    fields(transaction.evm_legacy,['transfer']);
    const t=transaction.evm_legacy.transfer;
    fields(t,['chain_id','nonce','gas_price','gas_limit','to','value']);
    check(t.chain_id===84532 && t.gas_price>0 && t.gas_limit>=21000 && t.gas_limit<=1000000,'Unsupported EVM transaction bounds');
    return concat(utf8('pairkey/signing-intent/v1\0'),u16(1),encodeKey(key.multi.key),byte(0),u64(t.chain_id),u64(t.nonce),u64(t.gas_price),u64(t.gas_limit),fixed(t.to,20),u64(t.value));
  }
  throw new Error('Unsupported transaction adapter');
}
export async function payload(q, key) {
  const { chain, path, registration } = q.key;
  check(same(key.account, await account(chain, path)), 'Derived key path changed');
  const publicKey = fixed(key.public_key, chain === 'evm' ? 33 : 32);
  check(key.public_key_hex === `0x${hex(publicKey)}`, 'Public key encoding changed');
  if(q.transaction!==undefined)return transactionPayload(q,key);
  check(typeof q.message === 'string' && q.message.trim() && utf8(q.message).length <= 256, 'Message must contain 1–256 UTF-8 bytes');
  const message = utf8(q.message);
  if (chain === 'solana' || chain === 'near' || chain === 'sui') { check(key.multi === null, 'Unexpected signing suite'); return message; }
  const expected = { evm: 'Dkls23Secp256k1', zcash: 'FrostRedPallas', bitcoin: 'FrostSecp256k1Tr' }[chain];
  check(key.multi?.key?.suite === expected && expected, 'Signing suite changed');
  check(same(key.multi.key.public_key, publicKey) && same(key.multi.key.account, key.account) && same(key.multi.key.namespace, await registrationDigest(registration)), 'Signing key namespace changed');
  const typed = chain === 'evm' ? concat(byte(2), u64(84532), bytes(message)) : chain === 'bitcoin' ? concat(byte(3), byte(1), bytes(message)) : concat(byte(1), bytes(message));
  return concat(utf8('pairkey/signing-intent/v1\0'), u16(1), encodeKey(key.multi.key), typed);
}
export async function signingPayload(q,key){
  if(q.transaction?.solana)return fixed(q.transaction.solana.message,q.transaction.solana.message.length);
  if(q.transaction?.near)return sha256(fixed(q.transaction.near.transaction,q.transaction.near.transaction.length));
  if(q.transaction?.sui)return blake2b256(concat(Uint8Array.of(0,0,0),fixed(q.transaction.sui.transaction,q.transaction.sui.transaction.length)));
  if(q.transaction?.evm_legacy)return null;
  if(q.key.chain==='solana'||q.key.chain==='near'||q.key.chain==='sui')return utf8(q.message);
  return null;
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
