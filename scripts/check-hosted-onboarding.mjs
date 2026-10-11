import { createRequire } from 'node:module';
import { resolve } from 'node:path';
// node scripts/check-hosted-onboarding.mjs DEPENDENCY_DIR STATE_DIR account|program
// DEPENDENCY_DIR has @solana/web3.js@1.98.4 installed; STATE_DIR has a funded
// devnet wallet.json and controller.json. The controller must already be deployed.
const web3 = createRequire(resolve(process.argv[2], 'package.json'))('@solana/web3.js');
import {readFile,writeFile} from 'node:fs/promises';
import {webcrypto} from 'node:crypto';
import assert from 'node:assert/strict';
import { PairKey } from '../website/hosted-client.mjs';
const dir=resolve(process.argv[3]);
const keypair=web3.Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(`${dir}/wallet.json`,'utf8'))));
const wallet={publicKey:keypair.publicKey,signTransaction:async tx=>{tx.sign(keypair);return tx;}};
const client=new PairKey({web3});
const mode=process.argv[4]||'account';
assert(['account','program'].includes(mode));
const program=web3.Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(`${dir}/controller.json`,'utf8')))).publicKey;
const savedPath=`${dir}/${mode}.json`;
let saved={mode,wallet:wallet.publicKey.toBase58(),program:program.toBase58(),cases:{}};
try{saved=JSON.parse(await readFile(savedPath,'utf8'));}catch{}
const save=()=>writeFile(savedPath,JSON.stringify(saved,null,2),{mode:0o600});
const namespace=await client.onboard(wallet,mode==='program'?client.controller(program,wallet.publicKey):{});
saved.namespace=namespace;await save();console.log(`${mode} namespace ${namespace.namespaceAddress}`);
for(const chain of ['solana','evm','zcash','near','bitcoin']){
 if(saved.cases[chain]?.result){console.log(`${chain}: already verified`);continue;}
 if(saved.cases[chain]?.job) throw new Error(`Reconcile existing ${chain} job before another test: ${saved.cases[chain].job.job_id}`);
 const key=await client.key(namespace,chain,[0]);
 assert.deepEqual((await client.key(namespace,chain,[0])).public_key,key.public_key);
 const q=await client.prepare(namespace,wallet,{chain,path:[0],message:`Hosted onboarding ${mode} ${chain}: developer-owned authority.`});
 // Absence of finalized approval must fail without allocating a signing job.
 await assert.rejects(()=>client.submit(q),/approval must be finalized/);
 const tx=await client.approve(namespace,wallet,q);
 const changed=structuredClone(q);changed.signing_request.message+=' changed';
 await assert.rejects(()=>client.submit(changed),/does not match this exact message/);
 const job=await client.submit(q);
 saved.cases[chain]={key,approval:q,transaction:tx,job};await save();
 const result=await client.wait(job.job_id);
 assert.equal((await client.submit(q)).job_id,job.job_id);
 assert.equal((await client.verify(result)).valid,true);
 assert.equal((await client.verify({...result,signed_message:result.signed_message+' changed'})).valid,false);
 if(chain==='solana'||chain==='near'){
   const pub=await webcrypto.subtle.importKey('raw',Uint8Array.from(key.public_key),{name:'Ed25519'},false,['verify']);
   assert.equal(await webcrypto.subtle.verify('Ed25519',pub,Buffer.from(result.signature_hex.slice(2),'hex'),new TextEncoder().encode(result.signed_message)),true);
 }
 saved.cases[chain].result=result;await save();console.log(JSON.stringify({mode,chain,job:job.job_id,approval:tx,verified:true,unapproved_rejected:true,changed_message_rejected:true,idempotent:true}));
}
const second=await client.key(namespace,'solana',[1]);assert.notDeepEqual(second.public_key,saved.cases.solana.key.public_key);
console.log(`${mode}: all five chains verified; distinct paths verified`);
