// Invoked by the Rust hosted integration test. Only generated test keys enter stdin.
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import {PairKey} from '../hosted-v2.mjs';
import * as c from '../approval-codec.mjs';
const q=JSON.parse(readFileSync(0,'utf8'));
const web3=new Function(`${readFileSync(new URL('../assets/vendor/solana-web3-1.98.4.min.js',import.meta.url),'utf8')}; return solanaWeb3;`)();
const prefix=Uint8Array.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
const key=await crypto.subtle.importKey('pkcs8',c.concat(prefix,Uint8Array.from(q.seed)),'Ed25519',false,['sign']);
const pair=web3.Keypair.fromSeed(Uint8Array.from(q.seed));let prompts=0;
const wallet={publicKey:pair.publicKey,signMessage:async bytes=>{prompts++;return {signature:new Uint8Array(await crypto.subtle.sign('Ed25519',key,bytes))};}};
const client=new PairKey({web3,endpoint:q.endpoint}),namespace=await client.onboard(wallet);
for(const chain of q.chains){
  const publicKey=await client.key(namespace,chain,[0]);
  const prepared=await client.prepare(namespace,wallet,{chain,path:[0],message:`Browser SDK ${chain} integration`});
  const recovery=await client.recovery(prepared),approved=await client.approve(namespace,wallet,prepared);
  const first=await client.submit(approved),second=await client.submit(approved);
  assert.deepEqual(first,second);assert.equal(first.job_id,recovery.job_id);
  const result=await client.wait(first.job_id,{prepared,key:publicKey});
  assert.equal((await client.verify(result)).valid,true);
  const recovered=await client.recover(first.job_id);assert.deepEqual(recovered.result,result);
  const changed=structuredClone(result);changed.signed_message+='!';
  await assert.rejects(()=>client.checkResult(prepared,publicKey,changed));
}
assert.equal(prompts,q.chains.length);
console.log(`Browser SDK verified ${q.chains.length} hosted signing flows without a registration transaction.`);
