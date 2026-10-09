import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as codec from './approval-codec.mjs';
const vectors=JSON.parse(readFileSync(new URL('./fixtures/offchain-vectors.json',import.meta.url)));
test('all five chains match Rust request, payload, policy, binding and job encodings',async()=>{
  assert.equal(vectors.cases.length,5);
  for(const v of vectors.cases){
    const p=v.prepared,reg=p.signing_request.key.registration;
    assert.deepEqual([...await codec.registrationDigest(reg)],v.registration_digest);
    assert.deepEqual([...await codec.namespaceDigest(reg.namespace)],v.namespace_digest);
    assert.deepEqual([...await codec.requestDigest(p.request)],v.request_digest);
    assert.deepEqual([...await codec.jobDigest(p.request)],v.job_digest);
    assert.deepEqual([...await codec.bindingChallenge(v.binding)],v.binding_challenge);
    assert.deepEqual([...await codec.policyChallenge(v.policy_update)],v.policy_challenge);
    assert.deepEqual([...await codec.verifyPrepared(p,{signing_request:p.signing_request,identity:p.request.identity},v.key,100)],p.signing_message);
  }
});
test('passkey, OIDC and program identities match Rust encodings and stable authorities',async()=>{
  for(const v of vectors.identities){
    assert.deepEqual([...codec.encodeIdentity(v.identity)],v.encoded);
    assert.deepEqual([...await codec.identityDigest(v.identity)],v.digest);
    assert.deepEqual([...await codec.authority(v.identity)],v.authority);
  }
});
test('message, chain, path, source, policy, expiry and wallet-byte substitutions fail locally',async()=>{
  for(const v of vectors.cases){
    const expected={signing_request:v.prepared.signing_request,identity:v.prepared.request.identity};
    for(const change of [
      p=>p.signing_request.message+='!',p=>p.signing_request.key.path[0]++,
      p=>p.request.identity.Account.public_key[0]^=1,p=>p.request.commit.message_hash[0]^=1,
      p=>p.request.commit.request_id[0]^=1,p=>p.request.policy_digest[0]^=1,
      p=>p.rules.disabled=true,p=>p.payload[0]^=1,p=>p.signing_message[0]^=1,
      p=>p.request.expires_at=100,p=>p.request.issued_at=101,
      p=>p.signing_request.key.chain=p.signing_request.key.chain==='evm'?'solana':'evm',
      p=>p.request.policy_revision=Number.MAX_SAFE_INTEGER+1,
      p=>p.request.unrecognized=true,
    ]){
      const changed=structuredClone(v.prepared);change(changed);
      await assert.rejects(()=>codec.verifyPrepared(changed,expected,v.key,100));
    }
  }
});
test('default revision cannot smuggle a nondefault restriction and malformed bytes fail',async()=>{
  const v=structuredClone(vectors.cases[0]);
  v.prepared.rules.max_payload_bytes=1000;
  v.prepared.request.policy_digest=[...await codec.digest('pairkey/approval-rules/v1',codec.encodeRules(v.prepared.rules))];
  v.prepared.signing_message=[...await codec.signingMessage(v.prepared.request)];
  await assert.rejects(()=>codec.verifyPrepared(v.prepared,{signing_request:v.prepared.signing_request,identity:v.prepared.request.identity},v.key,100),/default policy/);
  for(const value of [[256],[-1],[NaN],['1']])assert.throws(()=>codec.wireBytes.bytes(value));
});
