import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {ProgramClient} from './program-client.mjs';
const web3 = new Function(`${readFileSync(new URL('./assets/vendor/solana-web3-1.98.4.min.js', import.meta.url),'utf8')}; return solanaWeb3;`)();

function fixture({mode = 'Onchain', verifyTranscript} = {}) {
  const data = new Map(), events = [], storage = {
    getItem: key => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, value),
  };
  const wallet = {
    publicKey: {toBase58: () => 'owner'},
    connect: async () => {}, signMessage: async () => {}, signTransaction: async () => {},
  };
  let sequence = 0;
  const deployment = {registry:'r',genesis_hash:'g',enclave_set:[1],signer_identities:[[2],[3]]};
  const client = {endpoint:'https://pairkey.com/api/v2',deployment,
    programSource: async (_program, _owner, selected) => ({identity:{Program:{mode:selected}}}),
    onboard: async (_wallet, {identity,namespace,namespaceId}) => ({identity,namespaceLabel:namespace,namespaceId,caller:[1]}),
    checkWallet: () => {},
    programPolicy: async () => { events.push('read-policy'); return null; },
    setProgramPolicy: async (_wallet, policy) => { events.push(['set-policy',policy]); return 'policy-tx'; },
    key: async (_namespace, chain, path) => { events.push(['key',chain,path]); return {public_key_hex:'0x01'}; },
    prepare: async (_namespace, _wallet, request) => {
      events.push('prepare');
      const id = ++sequence;
      return {request:{id},signing_request:request};
    },
    jobId: async request => `job-${request.id}`,
    recovery: async prepared => ({version:2,endpoint:client.endpoint,job_id:`job-${prepared.request.id}`,prepared,key:{public_key_hex:'0x01'},deployment}),
    approve: async () => { events.push('approve'); return {approval:{request:{id:sequence}}}; },
    commitProgram: async () => { events.push('commit'); },
    submit: async () => { events.push('submit'); return {job_id:`job-${sequence}`}; },
    wait: async jobId => { events.push(['wait',jobId]); return {chain:'solana',signed_message:'hello',public_key_hex:'0x01',signature_hex:'0x02'}; },
    recover: async jobId => { events.push(['recover',jobId]); return {}; },
    config: async () => deployment,
    verify: async () => { events.push('service-verify'); return {valid:true}; },
  };
  const program = new ProgramClient({wallet,programId:'example-program',mode,storage,client,verifyTranscript});
  return {program,client,events,data};
}

test('policy setup is explicit and sign saves each job before the wallet prompt', async () => {
  const f = fixture();
  const connected=await f.program.connect({namespace:'org/acme/treasury'});
  assert.equal(connected.namespaceLabel,'org/acme/treasury');
  const policy = await f.program.setPolicy({chain:'solana',pathPrefix:[0],remainingApprovals:2});
  assert.deepEqual(policy,{transactionSignature:'policy-tx',revision:1});
  const first = await f.program.signMessage({chain:'solana',path:[0],message:'hello'});
  const second = await f.program.signMessage({chain:'solana',path:[0],message:'hello'});
  assert.equal(first.jobId,'job-1');
  assert.equal(second.jobId,'job-2');
  assert.equal(first.verification.independentReceipts,false);
  assert.equal(first.transcript.approval.id,1);
  assert.equal(first.transcript.identities.length,2);
  assert.ok(f.data.has('pairkey-v2-program:example-program:job-1'));
  assert.ok(f.data.has('pairkey-v2-program:example-program:job-2'));
  assert.equal(f.events.filter(e=>e==='commit').length,2);
  assert.equal(f.events.filter(e=>e==='read-policy').length,1);
  assert.equal(f.events.filter(e=>e==='service-verify').length,2);
  assert.equal(f.events.findIndex(e=>e==='approve') > f.events.findIndex(e=>Array.isArray(e)&&e[0]==='key'),true);
});

test('program policy and key selection use the requested EVM chain ID', async () => {
  const f=fixture();
  await f.program.connect({namespace:'org/acme/treasury'});
  await f.program.setPolicy({chain:'evm',chainId:1,pathPrefix:[0]});
  assert.deepEqual(f.events.find(e=>Array.isArray(e)&&e[0]==='set-policy')[1].chain,{evm_chain:{chain_id:1}});
  await f.program.deriveKey({chain:'evm',chainId:1,path:[0]});
  assert.deepEqual(f.events.find(e=>Array.isArray(e)&&e[0]==='key')[1],{evm_chain:{chain_id:1}});
});

test('recovering an older job never approves, commits, or submits again', async () => {
  const f = fixture();
  await f.program.connect();
  await f.program.signMessage({chain:'solana',message:'hello'});
  await f.program.signMessage({chain:'solana',message:'hello'});
  f.events.length = 0;
  const recovered = await f.program.recover('job-1');
  assert.equal(recovered.jobId,'job-1');
  assert.deepEqual(f.events,[['recover','job-1'],['wait','job-1'],'service-verify']);
});

test('a fresh browser client recovers a saved job without reconnecting', async () => {
  const f = fixture();
  await f.program.connect();
  const signed = await f.program.signMessage({chain:'solana',message:'hello'});
  f.events.length = 0;
  const fresh = new ProgramClient({
    wallet:f.program.wallet, programId:'example-program',
    storage:f.program.storage, client:f.client,
  });
  const recovered = await fresh.recover(signed.jobId);
  assert.equal(recovered.jobId,signed.jobId);
  assert.deepEqual(recovered.transcript,signed.transcript);
  assert.deepEqual(f.events,[['recover','job-1'],['wait','job-1'],'service-verify']);
});

test('full verification status requires an independent callback', async () => {
  const f = fixture({mode:'Offchain',verifyTranscript: async transcript => transcript.identities.length===2});
  await f.program.connect();
  const signed = await f.program.signMessage({chain:'solana',message:'hello'});
  assert.equal(signed.verification.independentReceipts,true);
  assert.equal(f.events.includes('commit'),false);
  f.client.verify = async () => ({valid:false});
  await assert.rejects(() => f.program.recover(signed.jobId),/Hosted signature verification failed/);
});

test('Solana proof broadcasts a native Ed25519 verifier instruction only for checked results', async () => {
  const f = fixture(), sent = [];
  let connections = 0;
  f.program.wallet.connect = async () => { connections++; };
  f.client.web3 = web3;
  f.client.send = async (_wallet, instructions) => { sent.push(...instructions); return 'proof-tx'; };
  const signed = {
    publicKeyHex:`0x${'11'.repeat(32)}`,
    signatureHex:`0x${'22'.repeat(64)}`,
    result:{chain:'solana',signed_message:'hello'},
    verification:{serviceSignature:true},
  };
  assert.deepEqual(await f.program.verifyOnSolana(signed),{transactionSignature:'proof-tx'});
  assert.equal(connections,1);
  assert.equal(sent.length,1);
  assert.equal(sent[0].programId.toBase58(),web3.Ed25519Program.programId.toBase58());
  assert.equal(sent[0].data.subarray(16,48).every(byte=>byte===0x11),true);
  assert.equal(sent[0].data.subarray(48,112).every(byte=>byte===0x22),true);
  await assert.rejects(() => f.program.verifyOnSolana({...signed,result:{chain:'evm'}}),/checked Solana/);
  assert.equal(sent.length,1);
});
test('custom program source and policy adapter do not depend on the example-controller endpoints',async()=>{
  const f=fixture({mode:'Onchain'}),calls=[];
  const source={program:Array(32).fill(7),authority:Array(32).fill(8),seeds:[[1]],code_hash:Array(32).fill(0),accounts:[[...Array(32).fill(9)]],mode:'Onchain'};
  const policyAdapter={
    read:async context=>{calls.push(['read',context.namespace.namespaceLabel]);return {revision:4};},
    set:async context=>{calls.push(['set',context.policy]);return {transactionSignature:'custom-policy',revision:5};},
    commit:async context=>{calls.push(['commit',context.prepared.request.id]);},
  };
  const program=new ProgramClient({wallet:f.program.wallet,source,policyAdapter,mode:'Onchain',storage:f.program.storage,client:f.client});
  f.client.onboard=async(_wallet,{identity,namespace})=>({identity,namespaceLabel:namespace,caller:[1]});
  await program.connect({namespace:'org/acme/treasury'});
  assert.deepEqual(await program.policy(),{revision:4});
  assert.deepEqual(await program.setPolicy({chain:'solana',pathPrefix:[0]}),{transactionSignature:'custom-policy',revision:5});
  await program.signMessage({chain:'solana',message:'hello'});
  assert.equal(calls.filter(([kind])=>kind==='commit').length,1);
  assert.equal(f.events.includes('commit'),false);
});
