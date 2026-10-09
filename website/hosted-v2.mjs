/** PairKey hosted v2. Wallet approvals are off-chain; policy edits and program
 * commit are explicit transactions. The Rust SDK remains the full independent
 * verifier of curve-specific key certificates, signatures and signer receipts.
 */
import {PairKey as TransactionClient} from './hosted-client.mjs';
import * as c from './approval-codec.mjs';
const now = () => Math.floor(Date.now() / 1000);
const copy = value => structuredClone(value);
const b = c.wireBytes;
const keyId = q => `${c.hex(c.encodeRegistration(q.registration))}:${q.chain}:${q.path.join('/')}`;
export const base64url = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
export async function verifyEd25519(publicKey, message, signature) {
  const key = await crypto.subtle.importKey('raw', b.fixed(publicKey, 32), 'Ed25519', false, ['verify']);
  c.check(await crypto.subtle.verify('Ed25519', key, b.fixed(signature, 64), message), 'Ed25519 signature verification failed');
}
function instructionData(ix) { return {program_id: ix.programId.toBase58(), accounts: ix.keys.map(k => ({pubkey: k.pubkey.toBase58(), is_signer: k.isSigner, is_writable: k.isWritable})), data: [...ix.data]}; }

export class PairKey extends TransactionClient {
  constructor({web3, endpoint = 'https://pairkey.com/api/v2', deployment, onProgress} = {}) {
    const url = new URL(endpoint);
    c.check(url.protocol === 'https:' || url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname), 'HTTPS is required for hosted authorization');
    super({web3, endpoint, onProgress});
    this.deployment = deployment ? copy(deployment) : undefined;
    this.keys = new Map();
  }
  async config() {
    const value = await this.request('/config');
    c.check(value.version === 2 && value.registration_required === false && value.sessions === false, 'Hosted v2 is not available on this deployment');
    c.check(value.signer_identities?.length === 2 && !c.same(value.signer_identities[0], value.signer_identities[1]), 'Two distinct signer identities required');
    for (const key of value.signer_identities) b.fixed(key, 32);
    if (this.deployment) for (const field of ['registry', 'genesis_hash', 'enclave_set', 'signer_identities']) c.check(c.same(value[field], this.deployment[field]), `Pinned deployment changed: ${field}`);
    // A client instance pins its first HTTPS configuration for subsequent calls.
    this.deployment ??= copy(value);
    return value;
  }
  pubkey(value) { return new this.web3.PublicKey(value); }
  pda(seeds, program) { return this.web3.PublicKey.findProgramAddressSync(seeds.map(v => Uint8Array.from(v)), this.pubkey(program))[0]; }
  async onboard(wallet, {identity, namespaceId = Array(32).fill(0)} = {}) {
    const caller = wallet?.publicKey ? [...wallet.publicKey.toBytes()] : undefined;
    identity ??= {Account: {public_key: caller}};
    const wanted = copy({identity, namespace_id: namespaceId});
    const config = await this.config(), owner = await c.authority(wanted.identity);
    if (identity.Program) c.check(c.same(this.pda(identity.Program.seeds, identity.Program.program).toBytes(), owner), 'Program authority PDA changed');
    const response = await this.request('/namespaces', wanted), reg = response.proposal?.registration;
    c.encodeRegistration(reg);
    const expected = {version: 1, scheme: 'FrostEd25519', network: [...this.pubkey(config.genesis_hash).toBytes()], registry: [...this.pubkey(config.registry).toBytes()], derivation_authority: [...owner], namespace_id: wanted.namespace_id, enclave_set: config.enclave_set};
    c.check(c.same(reg.namespace, expected) && c.same(response.identity, wanted.identity), 'Namespace authority or deployment changed');
    const digest = await c.registrationDigest(reg), nsDigest = await c.namespaceDigest(expected);
    c.check(response.namespace_address === this.pda([c.utf8('namespace'), nsDigest], config.registry).toBase58(), 'Namespace address changed');
    const message = c.concat(c.utf8('pairkey/enrolled-registration/v1'), digest, owner);
    c.check(response.proposal.identity_signatures?.length === 2, 'Namespace attestations missing');
    await Promise.all(config.signer_identities.map((key, i) => verifyEd25519(key, message, response.proposal.identity_signatures[i])));
    return {registration: copy(reg), identity: wanted.identity, namespaceAddress: response.namespace_address, caller, config: copy(config)};
  }
  async programSource(programId, owner, mode = 'Offchain') {
    const requested = {program: this.pubkey(programId).toBase58(), owner: this.pubkey(owner).toBase58(), mode};
    const response = await this.request('/programs/example', requested), source = response.identity?.Program;
    c.encodeSource(source);
    const seeds = [c.utf8('controller'), this.pubkey(owner).toBytes()], authority = this.pda(seeds, programId);
    const policy = this.pda([c.utf8('pairkey-policy'), this.pubkey(owner).toBytes()], programId);
    c.check(c.same(source.program, this.pubkey(programId).toBytes()) && c.same(source.authority, authority.toBytes()) && c.same(source.seeds, seeds) && c.same(source.accounts, [[...policy.toBytes()]]) && source.mode === mode && response.policy_address === policy.toBase58(), 'Example program source changed');
    return response;
  }
  async key(namespace, chain = 'solana', path = [0]) {
    const request = copy({registration: namespace.registration, chain, path}), key = await this.request('/keys', request);
    // Bind the exact public key/intent to what the user will approve. Full
    // certificate arithmetic is performed by both workers and the Rust SDK.
    await c.payload({key: request, message: 'key context check'}, key);
    this.keys.set(keyId(request), copy(key));
    return key;
  }
  async prepare(namespace, wallet, {chain = 'solana', path = [0], message, requestId = [...crypto.getRandomValues(new Uint8Array(32))]} = {}) {
    if (namespace.caller) this.checkWallet(namespace, wallet);
    const expected = copy({signing_request: {key: {registration: namespace.registration, chain, path}, request_id: requestId, message}, identity: namespace.identity});
    const key = this.keys.get(keyId(expected.signing_request.key));
    c.check(key, 'Load this chain and path’s public key first');
    const prepared = await this.request('/approvals', expected);
    await c.verifyPrepared(prepared, expected, key);
    return prepared;
  }
  checkWallet(namespace, wallet) {
    c.check(wallet?.publicKey && c.same(wallet.publicKey.toBytes(), namespace.caller), 'Wallet changed. Reconnect before approving a request.');
  }
  async checked(namespace, prepared) {
    const key = this.keys.get(keyId(prepared.signing_request.key));
    c.check(key && c.same(prepared.signing_request.key.registration, namespace.registration), 'Approval namespace or key changed');
    return c.verifyPrepared(prepared, {signing_request: prepared.signing_request, identity: namespace.identity}, key);
  }
  /** Account and program callers sign the exact digest. Program Onchain requires
   * a separate explicit commitProgram call before submitting this proof. */
  async approve(namespace, wallet, prepared) {
    const immutable = copy(prepared), message = await this.checked(namespace, immutable);
    this.checkWallet(namespace, wallet);
    c.check(wallet.signMessage, 'This flow needs wallet.signMessage');
    const kind = c.identityKind(namespace.identity);
    c.check(kind === 'Account' || kind === 'Program', 'Use a bound ephemeral key for this identity');
    const caller = Uint8Array.from(namespace.caller);
    if (kind === 'Account') c.check(c.same(caller, namespace.identity.Account.public_key), 'Account owner changed');
    this.onProgress({stage: 'wallet_message', message: 'Approve this exact request in your wallet. No transaction is sent.'});
    const signed = await wallet.signMessage(message.slice(), 'utf8');
    this.checkWallet(namespace, wallet);
    const signature = [...(signed.signature || signed)];
    await verifyEd25519(caller, message, signature);
    const proof = kind === 'Account' ? {Account: {signature}} : {Program: {caller: [...caller], signature}};
    return {signing_request: immutable.signing_request, approval: {request: immutable.request, proof}};
  }
  async jobId(request) { return this.pubkey(await c.jobDigest(request)).toBase58(); }
  /** Safe to save before submission: public request metadata only. */
  async recovery(prepared) { return {version: 2, endpoint: this.endpoint, job_id: await this.jobId(prepared.request), prepared: copy(prepared), key: copy(this.keys.get(keyId(prepared.signing_request.key))), deployment: copy(this.deployment)}; }
  async submit(submission) {
    const snapshot = copy(submission), expected = await this.jobId(snapshot.approval.request);
    const result = await this.request('/jobs', snapshot);
    c.check(result.job_id === expected, 'Hosted job ID changed');
    return result;
  }
  async recover(jobId) { this.pubkey(jobId); return this.request(`/jobs/${encodeURIComponent(jobId)}/recover`, {}); }
  async wait(jobId, {prepared, key} = {}) {
    const result = await super.wait(jobId);
    if (prepared && key) await this.checkResult(prepared, key, result);
    return result;
  }
  async checkResult(prepared, key, result) {
    const q = prepared.signing_request;
    c.check(result.chain === q.key.chain && result.signed_message === q.message && result.public_key_hex === key.public_key_hex, 'Hosted result context changed');
    c.check(typeof result.signature_hex === 'string' && /^0x[0-9a-f]+$/.test(result.signature_hex), 'Signature encoding missing');
    c.check(result.receipts?.length === 2, 'Both signer receipts required');
    const attempts = key.multi ? result.receipts.map(r => r.request?.attempt) : [result.attempt, result.attempt];
    for (const attempt of attempts) c.check(c.same(attempt?.authorization?.access_proof?.Offchain?.request, prepared.request) && c.same(attempt.commit, prepared.request.commit), 'Receipt approval changed');
    c.check(c.same(attempts[0], attempts[1]), 'Receipts belong to different attempts');
    const roles = result.receipts.map(r => (r.receipt || r).role);
    c.check(c.same(roles, ['A', 'B']), 'Receipt signer order changed');
    if (!key.multi) await verifyEd25519(key.public_key, c.utf8(q.message), result.signature_hex.slice(2).match(/../g).map(h => parseInt(h, 16)));
    // Multisuite cryptography and full receipt verification run in the hosted
    // Rust SDK; use its offline verifier when transport-independent proof is needed.
    return result;
  }
  async programPolicy(programId, owner) { return this.request('/programs/example/policy/read', {program: this.pubkey(programId).toBase58(), owner: this.pubkey(owner).toBase58()}); }
  async rules(namespace) {
    const response = await this.request('/policies', {registration: namespace.registration});
    c.encodeRules(response.rules);
    c.check(response.policy_address === this.pda([c.utf8('rules'), await c.namespaceDigest(namespace.registration.namespace)], namespace.registration.namespace.registry).toBase58(), 'Policy address changed');
    return response;
  }
  async preparePolicy(namespace, rules) {
    const expected = copy({registration: namespace.registration, identity: namespace.identity, rules});
    const prepared = await this.request('/policies/prepare', expected);
    await checkPolicy(prepared, expected);
    return prepared;
  }
  async setPolicy(namespace, wallet, prepared, authentication) {
    const p = copy(prepared), update = p.update;
    await checkPolicy(p, {registration: namespace.registration, identity: namespace.identity, rules: update.rules});
    const kind = c.identityKind(namespace.identity), payer = wallet.publicKey;
    if (kind === 'Account' || kind === 'Program') this.checkWallet(namespace, wallet);
    authentication ??= kind === 'Account' ? 'Wallet' : kind === 'Program' ? 'ProgramCpi' : undefined;
    const auth = copy(authentication), ns = update.namespace, registry = this.pubkey(ns.registry);
    const response = await this.request('/policies/instructions', {payer: payer.toBase58(), update, authentication: auth});
    let proof, native = [];
    if (kind === 'Account' && auth === 'Wallet') proof = b.byte(0);
    else if (kind === 'Program' && auth === 'ProgramCpi') proof = b.byte(3);
    else if (kind === 'Passkey' && auth?.Passkey) {
      const a = auth.Passkey, data = Uint8Array.from(response.instructions?.[0]?.data || []);
      const client = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Uint8Array.from(a.client_data_json)));
      c.check(client.type === 'webauthn.get' && client.origin === namespace.identity.Passkey.origin && client.challenge === base64url(p.challenge) && !client.crossOrigin && !client.topOrigin, 'Passkey policy challenge changed');
      const message = c.concat(b.fixed(a.authenticator_data, 37), await c.sha256(Uint8Array.from(a.client_data_json)));
      const header = c.concat(Uint8Array.of(1, 0), ...[49, 65535, 16, 65535, 113, message.length, 65535].map(b.u16));
      c.check(data.length === 113 + message.length && c.same(data.slice(0, 16), header) && c.same(data.slice(16, 49), namespace.identity.Passkey.public_key) && c.same(data.slice(113), message), 'Native passkey verification changed');
      native = [this.makeInstruction('Secp256r1SigVerify1111111111111111111111111', [], data)];
      proof = c.concat(b.byte(1), b.bytes(a.authenticator_data), b.bytes(a.client_data_json, 2048));
    } else if (kind === 'Oidc' && auth?.Oidc) {
      const message = c.concat(c.utf8('pairkey/oidc-policy-update/v1'), Uint8Array.from(p.challenge));
      for (let i = 0; i < 2; i++) {
        const data = Uint8Array.from(response.instructions?.[i]?.data || []);
        const header = c.concat(Uint8Array.of(1, 0), ...[16, 65535, 80, 65535, 112, message.length, 65535].map(b.u16));
        c.check(data.length === 112 + message.length && c.same(data.slice(0, 16), header) && c.same(data.slice(80, 112), namespace.config.signer_identities[i]) && c.same(data.slice(112), message), 'OIDC policy attestation changed');
        await verifyEd25519(namespace.config.signer_identities[i], message, data.slice(16, 80));
        native.push(this.makeInstruction('Ed25519SigVerify111111111111111111111111111', [], data));
      }
      proof = b.byte(2);
    } else throw new Error('Policy authentication does not match this identity');
    const owner = kind === 'Account' || kind === 'Program' ? this.meta(await c.authority(namespace.identity), true) : this.meta(payer);
    const ix = this.makeInstruction(registry, [this.meta(payer, true, true), owner, this.meta(this.pda([c.utf8('set'), ns.enclave_set], registry)), this.meta(this.pda([c.utf8('rules'), await c.namespaceDigest(ns)], registry), false, true), this.meta(this.web3.SystemProgram.programId), this.meta(this.web3.SYSVAR_INSTRUCTIONS_PUBKEY)], c.concat(b.byte(11), c.encodePolicyUpdate(update), proof));
    this.checkInstructions(response, [...native, ix]);
    const gateway = kind === 'Program' ? this.controller(this.pubkey(namespace.identity.Program.program), payer).wrapInstruction(ix) : ix;
    return this.send(wallet, [...native, gateway]);
  }
  async setProgramPolicy(wallet, q) {
    const expected = copy(q), config = await this.config(), owner = [...wallet.publicKey.toBytes()];
    c.check(expected.owner === wallet.publicKey.toBase58(), 'Program policy owner changed');
    const account = await c.account(expected.chain, expected.path_prefix);
    const data = c.concat(c.utf8('pairkey_policy/v1\0'), b.fixed(owner, 32), b.fixed(config.enclave_set, 32), b.u64(expected.revision), b.bool(expected.enabled), b.fixed(account.destination, 32), b.path(expected.path_prefix), b.u16(expected.max_payload_bytes), b.bool(expected.require_commit), b.u64(expected.remaining_approvals));
    const ix = this.makeInstruction(expected.program, [this.meta(wallet.publicKey, true, true), this.meta(this.pda([c.utf8('pairkey-policy'), owner], expected.program), false, true), this.meta(this.web3.SystemProgram.programId)], data);
    const response = await this.request('/programs/example/policy', expected);
    this.checkInstructions(response, [ix]);
    return this.send(wallet, [ix]);
  }
  async commitProgram(namespace, wallet, prepared) {
    const immutable = copy(prepared); await this.checked(namespace, immutable); this.checkWallet(namespace, wallet);
    const source = namespace.identity.Program;
    c.check(source?.mode === 'Onchain', 'This request uses off-chain program evaluation');
    const ns = namespace.registration.namespace, owner = [...wallet.publicKey.toBytes()], registry = this.pubkey(ns.registry), program = this.pubkey(source.program);
    const authority = this.pda([c.utf8('controller'), owner], program), policy = this.pda([c.utf8('pairkey-policy'), owner], program), nsDigest = await c.namespaceDigest(ns);
    c.check(c.same(source.authority, authority.toBytes()) && c.same(source.accounts, [[...policy.toBytes()]]), 'Example program scope changed');
    const data = c.concat(c.utf8('pairkey_approve_commit/v1\0'), c.encodeNamespace(ns), c.encodeRequest(immutable.request), b.bytes(immutable.payload));
    const ix = this.makeInstruction(program, [this.meta(wallet.publicKey, true, true), this.meta(authority), this.meta(policy, false, true), this.meta(registry), this.meta(this.pda([c.utf8('set'), ns.enclave_set], registry)), this.meta(this.pda([c.utf8('namespace'), nsDigest], registry)), this.meta(this.pda([c.utf8('program-approval'), nsDigest, immutable.request.commit.request_id], registry), false, true), this.meta(this.web3.SystemProgram.programId)], data);
    const response = await this.request('/programs/example/commit', {owner: wallet.publicKey.toBase58(), prepared: immutable});
    this.checkInstructions(response, [ix]);
    return this.send(wallet, [ix]);
  }
  meta(pubkey, isSigner = false, isWritable = false) { return {pubkey: this.pubkey(pubkey), isSigner, isWritable}; }
  makeInstruction(programId, keys, data) { return new this.web3.TransactionInstruction({programId: this.pubkey(programId), keys, data}); }
  checkInstructions(response, expected) { c.check(c.same(response.instructions, expected.map(instructionData)), 'Unsigned instructions changed. Nothing was sent.'); }
}

/** Create before preparing a request or policy update so its lifetime covers the
 * approval. The private key is nonextractable and stays in this closure. */
export async function ephemeralIdentity(namespace, {lifetimeSeconds = 600} = {}) {
  namespace = copy(namespace);
  c.check(['Passkey', 'Oidc'].includes(c.identityKind(namespace.identity)), 'Bound identity required');
  c.check(Number.isInteger(lifetimeSeconds) && lifetimeSeconds > 0 && lifetimeSeconds <= 600, 'Binding lifetime must be at most ten minutes');
  const keys = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']), issued = now();
  const binding = {namespace_digest: [...await c.namespaceDigest(namespace.registration.namespace)], identity_digest: [...await c.identityDigest(namespace.identity)], public_key: [...new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))], issued_at: issued, expires_at: issued + lifetimeSeconds};
  const challenge = await c.bindingChallenge(binding);
  return {
    binding: copy(binding), challenge: challenge.slice(), oidcNonce: base64url(challenge),
    async approve(prepared, key, authentication) {
      const snapshot = copy(prepared);
      const message = await c.verifyPrepared(snapshot, {signing_request: snapshot.signing_request, identity: namespace.identity}, key);
      c.interval(binding.issued_at, binding.expires_at, now(), 600);
      c.check(snapshot.request.issued_at >= binding.issued_at && snapshot.request.expires_at <= binding.expires_at, 'Binding does not cover this request');
      const signature = [...new Uint8Array(await crypto.subtle.sign('Ed25519', keys.privateKey, message))];
      const proof = namespace.identity.Passkey ? {Passkey: {binding: copy(binding), assertion: copy(authentication.assertion), signature}} : {Oidc: {binding: copy(binding), id_token: authentication.idToken, signature}};
      return {signing_request: snapshot.signing_request, approval: {request: snapshot.request, proof}};
    },
    async approvePolicy(prepared, idToken) {
      c.check(namespace.identity.Oidc, 'Passkey policy updates use a native assertion over the policy challenge');
      await checkPolicy(prepared, {registration: namespace.registration, identity: namespace.identity, rules: prepared.update.rules});
      c.interval(binding.issued_at, binding.expires_at, now(), 600);
      c.check(prepared.update.issued_at >= binding.issued_at && prepared.update.expires_at <= binding.expires_at, 'Binding does not cover this policy update');
      const signature = [...new Uint8Array(await crypto.subtle.sign('Ed25519', keys.privateKey, Uint8Array.from(prepared.signing_message)))];
      return {Oidc: {binding: copy(binding), id_token: idToken, signature}};
    },
  };
}
async function checkPolicy(prepared, expected) {
  const u = prepared.update;
  c.encodePolicyUpdate(u); c.interval(u.issued_at, u.expires_at, now(), 300);
  c.check(u.rules.revision > 0 && c.same(u.namespace, expected.registration.namespace) && c.same(u.identity, expected.identity) && c.same(u.rules, expected.rules), 'Policy update changed');
  c.check(c.same(await c.authority(u.identity), u.namespace.derivation_authority), 'Policy authority changed');
  const challenge = await c.policyChallenge(u);
  c.check(c.same(challenge, prepared.challenge) && c.same(c.utf8(`PairKey policy update v1\nUpdate: ${c.hex(challenge)}`), prepared.signing_message), 'Policy signing bytes changed');
}
export async function passkeyAssertion(identity, challenge, credentialId) {
  c.check(identity.Passkey && globalThis.navigator?.credentials, 'WebAuthn is unavailable');
  c.check(location.origin === identity.Passkey.origin, 'Passkey origin changed');
  const credential = await navigator.credentials.get({publicKey: {challenge: Uint8Array.from(challenge), rpId: identity.Passkey.rp_id, allowCredentials: [{type: 'public-key', id: Uint8Array.from(credentialId)}], userVerification: 'required', timeout: 60000}});
  c.check(credential?.response, 'Passkey approval was cancelled');
  return {authenticator_data: [...new Uint8Array(credential.response.authenticatorData)], client_data_json: [...new Uint8Array(credential.response.clientDataJSON)], signature_der: [...new Uint8Array(credential.response.signature)]};
}
