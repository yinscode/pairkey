import test from 'node:test';
import assert from 'node:assert/strict';
import {HostedSession} from './hosted-session.mjs';
function fixture(mode) {
  const calls=[],map=new Map(),storage={setItem:(k,v)=>map.set(k,v),getItem:k=>map.get(k)};
  const deployment={registry:'registry',genesis_hash:'network',enclave_set:[1],signer_identities:[[2],[3]]};
  const identity=mode?{Program:{mode}}:{Account:{public_key:[1]}};
  const namespace={identity},key={public_key_hex:'0x01'},prepared={request:{id:'same-request'},signing_request:{message:'hello'}};
  const result={signature_hex:'0x02',signed_message:'hello'};
  const client={endpoint:'http://localhost/api/v2',deployment,checkWallet:()=>{},
    config:async()=>deployment,programSource:async()=>({identity}),onboard:async()=>namespace,
    key:async()=>key,prepare:async()=>prepared,jobId:async()=> 'same-job',
    recovery:async()=>({version:2,endpoint:client.endpoint,job_id:'same-job',prepared,key,deployment}),
    approve:async()=>{calls.push('approve');return {proof:'private-authentication'};},
    commitProgram:async()=>{calls.push('commit');},submit:async()=>{calls.push('submit');assert.ok(map.get('pairkey-v2-recovery'));return {job_id:'same-job'};},
    wait:async()=>{calls.push('wait');return result;},recover:async()=>{calls.push('recover');},
  };
  const wallet={connect:async()=>{},signMessage:()=>{},publicKey:'test-only'};
  const flow=new HostedSession(client,{storage});
  return {flow,client,calls,map,wallet,key,prepared,result};
}
const selection={chain:'solana',path:[0],message:'hello'};
async function connected(f,mode){await f.flow.connect(f.wallet,mode?{program:'program',mode}:{});await f.flow.loadKey('solana',[0]);}
test('lost submission response recovers the original job without another approval or submission',async()=>{
  const f=fixture();await connected(f);
  f.client.submit=async()=>{f.calls.push('submit');assert.ok(f.map.get('pairkey-v2-recovery'));throw new Error('response lost');};
  await assert.rejects(()=>f.flow.sign(selection),/response lost/);
  assert.equal(f.map.get('pairkey-v2-recovery').includes('private-authentication'),false);
  const resumed=new HostedSession(f.client,{storage:f.flow.storage});
  assert.deepEqual(await resumed.recover(),f.result);
  assert.deepEqual(f.calls,['approve','submit','recover','wait']);
});
test('on-chain mode consumes an allowance once; off-chain mode and recovery never commit',async()=>{
  for(const mode of ['Offchain','Onchain']){
    const f=fixture(mode);await connected(f,mode);await f.flow.sign(selection);await f.flow.recover();
    assert.equal(f.calls.filter(c=>c==='commit').length,mode==='Onchain'?1:0);
    assert.equal(f.calls.filter(c=>c==='approve').length,1);
    assert.equal(f.calls.filter(c=>c==='submit').length,1);
  }
});
test('a failed reconnect or key load cannot retain a previous authority or key',async()=>{
  const f=fixture();await connected(f);
  f.client.key=async()=>{throw new Error('load failed');};
  await assert.rejects(()=>f.flow.loadKey('evm',[1]),/load failed/);
  await assert.rejects(()=>f.flow.sign(selection),/Load its key/);
  f.client.onboard=async()=>{throw new Error('connect failed');};
  await assert.rejects(()=>f.flow.connect(f.wallet),/connect failed/);
  assert.equal(f.flow.namespace,undefined);
});
test('changing selected chain/path or failing recovery storage stops before the wallet prompt',async()=>{
  const f=fixture();await connected(f);
  await assert.rejects(()=>f.flow.sign({...selection,chain:'evm'}),/Load its key/);
  await assert.rejects(()=>f.flow.sign({...selection,path:[1]}),/Load its key/);
  f.flow.storage.setItem=()=>{throw new Error('storage disabled');};
  await assert.rejects(()=>f.flow.sign(selection),/storage disabled/);
  assert.deepEqual(f.calls,[]);
});
test('saved recovery cannot silently change job, endpoint or deployment',async()=>{
  for(const mutate of [s=>s.job_id='other-job',s=>s.endpoint='https://other.example/api/v2',s=>s.deployment.registry='other-registry']){
    const f=fixture();await connected(f);await f.flow.sign(selection);f.calls.length=0;
    const saved=JSON.parse(f.map.get('pairkey-v2-recovery'));mutate(saved);
    f.map.set('pairkey-v2-recovery',JSON.stringify(saved));
    await assert.rejects(()=>f.flow.recover());assert.deepEqual(f.calls,[]);
  }
});
test('OIDC uses a bound token for one prepared message and keeps it out of recovery',async()=>{
  const f=fixture(),identity={Oidc:{issuer:'https://accounts.google.com',audience:'client',subject:'person'}};
  f.client.onboard=async(_wallet,options)=>({identity:options.identity});
  f.flow.ephemeral=async namespace=>({
    oidcNonce:'exact-nonce',
    approve:async(prepared,key,{idToken})=>{assert.equal(namespace.identity,identity);assert.equal(idToken,'private-id-token');assert.equal(prepared,f.prepared);assert.equal(key,f.flow.key);f.calls.push('oidc-approve');return {proof:'private-id-token'};},
  });
  await f.flow.connectOidc(identity);
  await f.flow.loadKey('solana',[0]);
  const pending=await f.flow.prepareOidc(selection);
  assert.equal(pending.ephemeral.oidcNonce,'exact-nonce');
  assert.equal(f.map.get('pairkey-v2-recovery').includes('private-id-token'),false);
  assert.deepEqual(await f.flow.completeOidc(pending,'private-id-token'),f.result);
  assert.deepEqual(f.calls,['oidc-approve','submit','wait']);
  assert.equal(f.map.get('pairkey-v2-recovery').includes('private-id-token'),false);
  await f.flow.recover();
  assert.deepEqual(f.calls,['oidc-approve','submit','wait','recover','wait']);
});
test('passkey approval uses one bound assertion and recovery never prompts again',async()=>{
  const f=fixture(),identity={Passkey:{public_key:[2,...Array(32).fill(1)],rp_id:'pairkey.com',origin:'https://pairkey.com'}};
  f.client.onboard=async(_wallet,options)=>({identity:options.identity});
  f.flow.ephemeral=async namespace=>({challenge:[7,8,9],approve:async(prepared,key,{assertion})=>{
    assert.equal(namespace.identity,identity);assert.equal(prepared,f.prepared);assert.equal(key,f.flow.key);
    assert.deepEqual(assertion,{privateAssertion:'proof'});f.calls.push('passkey-approve');return {proof:assertion};
  }});
  f.flow.assertPasskey=async(given,challenge,credentialId)=>{
    assert.equal(given,identity);assert.deepEqual(challenge,[7,8,9]);assert.deepEqual(credentialId,[4,5]);
    assert.ok(f.map.get('pairkey-v2-recovery'),'public recovery record must exist before prompting');
    f.calls.push('passkey-prompt');return {privateAssertion:'proof'};
  };
  await f.flow.connectPasskey(identity);await f.flow.loadKey('solana',[0]);
  assert.deepEqual(await f.flow.signPasskey(selection,[4,5]),f.result);
  assert.equal(f.map.get('pairkey-v2-recovery').includes('privateAssertion'),false);
  await f.flow.recover();
  assert.deepEqual(f.calls,['passkey-prompt','passkey-approve','submit','wait','recover','wait']);
});
