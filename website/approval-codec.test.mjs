import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as codec from './approval-codec.mjs';
const vectors=JSON.parse(readFileSync(new URL('./fixtures/offchain-vectors.json',import.meta.url)));
test('Blake2b-256 matches the standard empty-input vector',()=>{
  assert.equal(codec.hex(codec.blake2b256(new Uint8Array())), '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8');
});
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
test('named namespace labels have stable domain-separated IDs',async()=>{
  const id=await codec.namedNamespaceId('org/acme/treasury');
  assert.equal(id.length,32);
  assert.deepEqual(id,await codec.namedNamespaceId('org/acme/treasury'));
  assert.notDeepEqual(id,await codec.namedNamespaceId('Org/acme/treasury'));
  await assert.rejects(()=>codec.namedNamespaceId(''));
  await assert.rejects(()=>codec.namedNamespaceId('a\n'));
});
test('typed Solana, EVM and NEAR transaction envelopes bind exact transaction fields',async()=>{
  const byChain=Object.fromEntries(vectors.cases.map(v=>[v.prepared.signing_request.key.chain,v]));
  const sol=structuredClone(byChain.solana.prepared.signing_request);sol.message='';sol.transaction={solana:{message:[1,2,3]}};
  const near=structuredClone(byChain.near.prepared.signing_request);near.message='';near.transaction={near:{transaction:[4,5,6]}};
  const evm=structuredClone(byChain.evm.prepared.signing_request);evm.message='';evm.transaction={evm_legacy:{transfer:{chain_id:84532,nonce:1,gas_price:2,gas_limit:21000,to:Array(20).fill(3),value:4}}};
  const solBytes=await codec.payload(sol,byChain.solana.key),nearBytes=await codec.payload(near,byChain.near.key),evmBytes=await codec.payload(evm,byChain.evm.key);
  assert.deepEqual([...await codec.signingPayload(sol,byChain.solana.key)],[1,2,3]);
  assert.deepEqual([...await codec.signingPayload(near,byChain.near.key)],[...await codec.sha256(Uint8Array.from([4,5,6]))]);
  assert.equal(await codec.signingPayload(evm,byChain.evm.key),null);
  evm.transaction.evm_legacy.transfer.value=5;
  assert.notDeepEqual(evmBytes,await codec.payload(evm,byChain.evm.key));
  sol.transaction.solana.message[0]^=1;assert.notDeepEqual(solBytes,await codec.payload(sol,byChain.solana.key));
  near.transaction.near.transaction[0]^=1;assert.notDeepEqual(nearBytes,await codec.payload(near,byChain.near.key));
});
test('typed Sui transaction uses the native intent digest',async()=>{
  const source=vectors.cases.find(v=>v.prepared.signing_request.key.chain==='solana');
  const registration=structuredClone(source.prepared.signing_request.key.registration),path=[0];
  const account=await codec.account('sui',path),publicKey=Array(32).fill(7);
  const key={account,public_key:publicKey,public_key_hex:`0x${codec.hex(publicKey)}`,address:null,multi:null};
  const q={key:{registration,chain:'sui',path},request_id:Array(32).fill(8),message:'',transaction:{sui:{transaction:[1,2,3,4]}}};
  const approved=await codec.payload(q,key),signing=await codec.signingPayload(q,key);
  assert.deepEqual([...signing],[...codec.blake2b256(Uint8Array.of(0,0,0,1,2,3,4))]);
  q.transaction.sui.transaction[0]^=1;
  assert.notDeepEqual(approved,await codec.payload(q,key));
  q.transaction.sui.transaction=Array(1198).fill(0);
  await assert.rejects(()=>codec.payload(q,key),/protocol bound/);
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
