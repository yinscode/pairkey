import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {PairKey, ephemeralIdentity, verifyEd25519} from './hosted-v2.mjs';
import * as c from './approval-codec.mjs';
const web3=new Function(`${readFileSync(new URL('./assets/vendor/solana-web3-1.98.4.min.js',import.meta.url),'utf8')}; return solanaWeb3;`)();
const vector=JSON.parse(readFileSync(new URL('./fixtures/offchain-vectors.json',import.meta.url))).cases[0];
async function signer(seed){
  const bytes=new Uint8Array(32).fill(seed),keypair=web3.Keypair.fromSeed(bytes);
  const prefix=Uint8Array.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
  const privateKey=await crypto.subtle.importKey('pkcs8',c.concat(prefix,bytes),'Ed25519',false,['sign']);
  return {publicKey:keypair.publicKey,sign:async data=>new Uint8Array(await crypto.subtle.sign('Ed25519',privateKey,data))};
}
async function fixture(){
  const owner=await signer(1),a=await signer(2),b=await signer(3),registration=structuredClone(vector.prepared.signing_request.key.registration);
  registration.namespace.derivation_authority=[...owner.publicKey.toBytes()];
  const config={version:2,registration_required:false,sessions:false,registry:new web3.PublicKey(registration.namespace.registry).toBase58(),genesis_hash:new web3.PublicKey(registration.namespace.network).toBase58(),enclave_set:registration.namespace.enclave_set,signer_identities:[a,b].map(k=>[...k.publicKey.toBytes()])};
  const client=new PairKey({web3,deployment:config});
  const calls=[];
  client.request=async(path,body)=>{
    calls.push([path,body]);
    if(path==='/config')return structuredClone(config);
    if(path==='/namespaces'){
      const message=c.concat(c.utf8('pairkey/enrolled-registration/v1'),await c.registrationDigest(registration),owner.publicKey.toBytes());
      return {identity:body.identity,proposal:{registration,identity_signatures:[...await Promise.all([a,b].map(async s=>[...await s.sign(message)]))]},namespace_address:client.pda([c.utf8('namespace'),await c.namespaceDigest(registration.namespace)],config.registry).toBase58()};
    }
    if(path==='/keys')return structuredClone(vector.key);
    if(path==='/approvals')return prepare(body,vector.key);
    if(path==='/jobs')return {job_id:await client.jobId(body.approval.request)};
    if(path.endsWith('/recover'))return {status:'failed',code:'uncertain'};
    throw new Error(`Unexpected route ${path}`);
  };
  const wallet={publicKey:owner.publicKey,signMessage:async message=>({signature:await owner.sign(message)})};
  return {owner,a,b,client,calls,wallet,registration,config};
}
async function prepare(q,key){
  const payload=[...await c.payload(q.signing_request,key)],issued=Math.floor(Date.now()/1000);
  const request={version:1,identity:q.identity,commit:{registration_digest:[...await c.registrationDigest(q.signing_request.key.registration)],request_id:q.signing_request.request_id,account:key.account,message_hash:[...await c.messageHash(Uint8Array.from(payload))],message_len:payload.length},policy_revision:0,policy_digest:[...await c.digest('pairkey/approval-rules/v1',c.encodeRules(vector.prepared.rules))],issued_at:issued,expires_at:issued+300};
  return {signing_request:structuredClone(q.signing_request),request,rules:structuredClone(vector.prepared.rules),payload,signing_message:[...await c.signingMessage(request)]};
}
test('onboarding never calls wallet transaction signing; exact wallet approval is verified locally',async()=>{
  const f=await fixture(),ns=await f.client.onboard(f.wallet),key=await f.client.key(ns);
  const prepared=await f.client.prepare(ns,f.wallet,{message:'My exact request'});
  const submission=await f.client.approve(ns,f.wallet,prepared);
  await verifyEd25519(ns.identity.Account.public_key,Uint8Array.from(prepared.signing_message),submission.approval.proof.Account.signature);
  const recovery=await f.client.recovery(prepared),submitted=await f.client.submit(submission);
  assert.equal(recovery.job_id,submitted.job_id);
  assert.deepEqual(recovery.key,key);
  assert.equal(JSON.stringify(recovery).includes('"proof"'),false);
  await f.client.recover(submitted.job_id);
  assert.deepEqual(f.calls.map(c=>c[0]),['/config','/namespaces','/keys','/approvals','/jobs',`/jobs/${submitted.job_id}/recover`]);
});
test('missing/mutated namespace attestations and changed pinned deployment are refused',async()=>{
  for(const mutate of [r=>r.proposal.identity_signatures[1][0]^=1,r=>r.proposal.registration.namespace.namespace_id[0]^=1,r=>r.namespace_address='wrong']){
    const f=await fixture(),request=f.client.request;
    f.client.request=async(path,body)=>{const r=await request(path,body);if(path==='/namespaces')mutate(r);return r;};
    await assert.rejects(()=>f.client.onboard(f.wallet));
  }
  const f=await fixture();f.config.signer_identities[0][0]^=1;
  await assert.rejects(()=>f.client.onboard(f.wallet),/Pinned deployment changed/);
});
test('wallet mutation, wrong message signature and account switching stop before submission',async()=>{
  for(const tamper of ['message','signature','account']){
    const f=await fixture(),ns=await f.client.onboard(f.wallet);await f.client.key(ns);
    const prepared=await f.client.prepare(ns,f.wallet,{message:'Original message'});
    f.wallet.signMessage=async bytes=>{
      if(tamper==='message')bytes[0]^=1;
      if(tamper==='account')f.wallet.publicKey=f.a.publicKey;
      return {signature:await (tamper==='signature'?f.a:f.owner).sign(bytes)};
    };
    await assert.rejects(()=>f.client.approve(ns,f.wallet,prepared));
    assert.equal(f.calls.some(c=>c[0]==='/jobs'),false);
  }
});
test('bad server preparation is rejected before signMessage is called',async()=>{
  const f=await fixture(),ns=await f.client.onboard(f.wallet);await f.client.key(ns);
  const request=f.client.request;let prompts=0;
  f.wallet.signMessage=async()=>{prompts++;throw new Error('unexpected prompt');};
  f.client.request=async(path,body)=>{const value=await request(path,body);if(path==='/approvals')value.signing_request.message='Other message';return value;};
  await assert.rejects(()=>f.client.prepare(ns,f.wallet,{message:'My message'}),/Prepared request changed/);
  assert.equal(prompts,0);
});
test('passkey and OIDC bind a nonexported ephemeral key to the namespace and exact request',async()=>{
  for(const identity of [
    {Passkey:{public_key:[2,...Array(32).fill(8)],rp_id:'pairkey.example',origin:'https://pairkey.example'}},
    {Oidc:{issuer:'https://issuer.example',audience:'client',subject:'user'}},
  ]){
    const registration=structuredClone(vector.prepared.signing_request.key.registration);
    registration.namespace.derivation_authority=[...await c.authority(identity)];
    const namespace={registration,identity},ephemeral=await ephemeralIdentity(namespace);
    const key=structuredClone(vector.key),q={identity,signing_request:{key:{registration,chain:'solana',path:[0]},request_id:Array(32).fill(4),message:'Bound request'}};
    const prepared=await prepare(q,key);
    const submission=await ephemeral.approve(prepared,key,{idToken:'private-test-token',assertion:{authenticator_data:[],client_data_json:[],signature_der:[]}});
    const proof=submission.approval.proof[c.identityKind(identity)];
    await verifyEd25519(ephemeral.binding.public_key,Uint8Array.from(prepared.signing_message),proof.signature);
    assert.deepEqual(proof.binding,ephemeral.binding);
    const other=await ephemeralIdentity(namespace);
    await assert.rejects(()=>verifyEd25519(other.binding.public_key,Uint8Array.from(prepared.signing_message),proof.signature));
    assert.equal(Object.hasOwn(ephemeral,'privateKey'),false);
    assert.equal(ephemeral.oidcNonce,btoa(String.fromCharCode(...await c.bindingChallenge(ephemeral.binding))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,''));
  }
});
test('instruction substitution is rejected before sending a program policy transaction',async()=>{
  const f=await fixture();let sent=false;
  f.client.send=async()=>{sent=true;};
  const request=f.client.request;
  f.client.request=async(path,body)=>path==='/programs/example/policy'?{instructions:[]} :request(path,body);
  await assert.rejects(()=>f.client.setProgramPolicy(f.wallet,{program:f.config.registry,owner:f.wallet.publicKey.toBase58(),revision:1,enabled:true,chain:'solana',path_prefix:[0],max_payload_bytes:256,require_commit:false,remaining_approvals:2}),/instructions changed/);
  assert.equal(sent,false);
});
test('wallet policy, program policy and commit instructions match Rust account flags and bytes',async t=>{
  t.mock.method(Date,'now',()=>200000);
  const vectors=JSON.parse(readFileSync(new URL('./fixtures/offchain-vectors.json',import.meta.url)));
  const v=vectors.cases[0],m=vectors.management;
  const reg={...v.prepared.signing_request.key.registration,namespace:m.wallet_update.namespace};
  const wallet={publicKey:new web3.PublicKey(reg.namespace.derivation_authority)};
  const config={version:2,registration_required:false,sessions:false,registry:new web3.PublicKey(reg.namespace.registry).toBase58(),genesis_hash:new web3.PublicKey(reg.namespace.network).toBase58(),enclave_set:reg.namespace.enclave_set,signer_identities:[Array(32).fill(2),Array(32).fill(3)]};
  const client=new PairKey({web3,deployment:config});
  const responses={'/config':config,'/policies/instructions':{instructions:[m.wallet_policy]},'/programs/example/policy':{instructions:[m.program_policy]},'/programs/example/commit':{instructions:[m.program_commit]},'/keys':v.key,'/programs/example':m.program_source};
  client.request=async path=>structuredClone(responses[path]);
  const sent=[];client.send=async(_,instructions)=>{sent.push(instructions);return 'test-only';};
  const namespace={registration:reg,identity:m.wallet_update.identity,caller:[...wallet.publicKey.toBytes()],config};
  const update=m.wallet_update,challenge=[...await c.policyChallenge(update)],prepared={update,challenge,signing_message:[...c.utf8(`PairKey policy update v1\nUpdate: ${c.hex(challenge)}`)]};
  await client.setPolicy(namespace,wallet,prepared);
  await client.setProgramPolicy(wallet,m.program_policy_request);
  const source=await client.programSource(m.program_policy_request.program,wallet.publicKey,'Onchain');
  const programNamespace={...namespace,registration:m.program_prepared.signing_request.key.registration,identity:source.identity};
  await client.key(programNamespace);
  await client.commitProgram(programNamespace,wallet,m.program_prepared);
  const wire=ix=>({program_id:ix.programId.toBase58(),accounts:ix.keys.map(k=>({pubkey:k.pubkey.toBase58(),is_signer:k.isSigner,is_writable:k.isWritable})),data:[...ix.data]});
  assert.deepEqual(sent.map(ixs=>ixs.map(wire)),[[m.wallet_policy],[m.program_policy],[m.program_commit]]);
  responses['/policies/instructions'].instructions[0].accounts[0].is_signer=false;
  await assert.rejects(()=>client.setPolicy(namespace,wallet,prepared),/instructions changed/);
  assert.equal(sent.length,3);
});
