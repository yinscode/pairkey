// Invoked by the Rust hosted integration test. Only generated test keys enter stdin.
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import {PairKey} from '../hosted-v2.mjs';
import {HostedSession} from '../hosted-session.mjs';
import * as c from '../approval-codec.mjs';
const q=JSON.parse(readFileSync(0,'utf8'));
const web3=new Function(`${readFileSync(new URL('../assets/vendor/solana-web3-1.98.4.min.js',import.meta.url),'utf8')}; return solanaWeb3;`)();
const prefix=Uint8Array.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
const key=await crypto.subtle.importKey('pkcs8',c.concat(prefix,Uint8Array.from(q.seed)),'Ed25519',false,['sign']);
const pair=web3.Keypair.fromSeed(Uint8Array.from(q.seed));let prompts=0;
const wallet={connect:async()=>{},publicKey:pair.publicKey,signMessage:async bytes=>{prompts++;return {signature:new Uint8Array(await crypto.subtle.sign('Ed25519',key,bytes))};}};
for(const [asset,type] of [['examples/hosted-client-v2.zip','application/zip'],['examples/hosted-controller.zip','application/zip'],['examples/verify_hosted.rs','text/plain']]){
  const response=await fetch(q.endpoint.replace(/\/api\/v2$/,'/')+asset);
  assert.equal(response.status,200);assert.ok(response.headers.get('content-type').startsWith(type));
  assert.ok((await response.arrayBuffer()).byteLength>0);
}
const client=new PairKey({web3,endpoint:q.endpoint});
const saved=new Map(),storage={setItem:(k,v)=>saved.set(k,v),getItem:k=>saved.get(k)};
const flow=new HostedSession(client,{storage});
await flow.connect(wallet);
const submit=client.submit.bind(client);
client.submit=async approval=>{
  const first=await submit(approval),second=await submit(approval);
  assert.deepEqual(first,second);
  assert.equal(first.job_id,JSON.parse(saved.get('pairkey-v2-recovery')).job_id);
  return first;
};
for(const chain of q.chains){
  const publicKey=await flow.loadKey(chain,[0]);
  const result=await flow.sign({chain,path:[0],message:`Browser SDK ${chain} integration`});
  assert.equal((await client.verify(result)).valid,true);
  const recovery=JSON.parse(saved.get('pairkey-v2-recovery'));
  assert.equal(JSON.stringify(recovery).includes('"proof"'),false);
  const resumed=new HostedSession(new PairKey({web3,endpoint:q.endpoint}),{storage});
  assert.deepEqual(await resumed.recover(),result);
  const changed=structuredClone(result);changed.signed_message+='!';
  await assert.rejects(()=>client.checkResult(recovery.prepared,publicKey,changed));
}
assert.equal(prompts,q.chains.length);
console.log(`Quickstart lifecycle verified ${q.chains.length} hosted signing flows and reload recovery without a registration transaction.`);
