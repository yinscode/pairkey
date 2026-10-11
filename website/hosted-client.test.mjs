import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PairKey, validateWalletMessage } from './hosted-client.mjs';
// Exercise the same pinned web3.js build shipped to browsers, without npm setup.
const web3 = new Function(`${readFileSync(new URL('./assets/vendor/solana-web3-1.98.4.min.js', import.meta.url), 'utf8')}; return solanaWeb3;`)();

const payer = web3.Keypair.fromSeed(new Uint8Array(32).fill(1));
const recipient = web3.Keypair.fromSeed(new Uint8Array(32).fill(2)).publicKey;
const blockhash = web3.Keypair.fromSeed(new Uint8Array(32).fill(3)).publicKey.toBase58();
const fixture = () => new web3.Transaction({feePayer: payer.publicKey, recentBlockhash: blockhash}).add(
  web3.ComputeBudgetProgram.setComputeUnitLimit({units:1400000}),
  web3.ComputeBudgetProgram.setComputeUnitPrice({microLamports:1000}),
  web3.SystemProgram.transfer({fromPubkey:payer.publicKey,toPubkey:recipient,lamports:1})
);

test('an in-place wallet instruction mutation is rejected before broadcast', async () => {
  const client = new PairKey({ web3 });
  const calls = [];
  client.rpc = async method => { calls.push(method); return { value: { blockhash } }; };
  const wallet = { publicKey: payer.publicKey, signTransaction: async tx => {
    tx.instructions[2].data[4] = 9;
    tx.sign(payer); return tx;
  } };
  await assert.rejects(() => client.send(wallet, [fixture().instructions[2]]), /Wallet changed.*instructions/);
  assert.deepEqual(calls, ['getLatestBlockhash']);
});

test('failed jobs never trigger another signing request', async () => {
  const client = new PairKey({ web3: {} });
  const calls = [];
  client.request = async (path, body) => { calls.push([path, body]); return { status: 'failed', error: 'interrupted', may_have_signed: true }; };
  await assert.rejects(() => client.wait('existing'), /Do not create a fresh signing request/);
  assert.deepEqual(calls, [['/jobs/existing', undefined]]);
});

test('Solana transaction failure is not mistaken for approval finality', async () => {
  const client = new PairKey({ web3: {} });
  client.rpc = async () => ({ value: [{ confirmationStatus: 'finalized', err: { InstructionError: [0, 'InvalidArgument'] } }] });
  await assert.rejects(() => client.finalized('failed-tx'), /Solana transaction failed/);
});

function submissionClient(onProgress = () => {}) {
  class Transaction {
    add() {}
    serializeMessage() { return Uint8Array.of(1, 2); }
    serialize() { return Uint8Array.of(3, 4); }
    signature = new Uint8Array(64);
  }
  const client = new PairKey({ web3: { Transaction, ComputeBudgetProgram: { setComputeUnitLimit: () => ({}), setComputeUnitPrice: () => ({}) } }, onProgress });
  const wallet = { publicKey: {}, signTransaction: async tx => tx };
  return { client, wallet };
}

test('lost submission response reconciles by locally known signature without signing again', async () => {
  const progress = [];
  const {client,wallet} = submissionClient(value => progress.push(value));
  const calls = [];
  client.rpc = async (method, params) => {
    calls.push(method);
    if (method === 'getLatestBlockhash') return {value: {blockhash: 'test', lastValidBlockHeight: 100}};
    if (method === 'sendTransaction') throw new Error('response lost');
    assert.equal(params[0][0], '1'.repeat(64));
    return {value: [{confirmationStatus: 'finalized', err: null}]};
  };
  assert.equal(await client.send(wallet, []), '1'.repeat(64));
  assert.deepEqual(calls, ['getLatestBlockhash', 'sendTransaction', 'getSignatureStatuses']);
  assert.deepEqual(progress.map(p => p.stage), ['wallet', 'submitting', 'finalized']);
  assert.equal(progress[1].signature, '1'.repeat(64));
});

test('expired unobserved transaction stops after a fresh history check', async () => {
  const {client,wallet} = submissionClient();
  const calls=[];
  client.rpc = async method => {
    calls.push(method);
    if (method === 'getLatestBlockhash') return {value:{blockhash:'test',lastValidBlockHeight:100}};
    if (method === 'sendTransaction') return '1'.repeat(64);
    if (method === 'getBlockHeight') return 101;
    return {value:[null]};
  };
  await assert.rejects(() => client.send(wallet,[]), /Transaction expired without confirmation/);
  assert.deepEqual(calls, ['getLatestBlockhash','sendTransaction','getSignatureStatuses','getBlockHeight','getSignatureStatuses']);
});

test('an observed transaction is allowed to finalize even beyond blockhash expiry', async () => {
  const {client}=submissionClient();
  let lookups=0;
  client.rpc=async method=> {
    if(method==='getBlockHeight') return 101;
    lookups++;
    return {value:[lookups===1 ? null : {confirmationStatus:'finalized',err:null}]};
  };
  await client.finalized('existing',{lastValidBlockHeight:100});
  assert.equal(lookups,3);
});

test('rebroadcast uses the identical signed transaction', async t => {
  t.mock.timers.enable({apis:['Date','setTimeout'],now:0});
  const {client}=submissionClient();
  const broadcasts=[];
  let landed=false;
  client.rpc=async (method,params)=> {
    if(method==='sendTransaction'){broadcasts.push(params[0]);landed=true;return 'existing';}
    if(method==='getBlockHeight') return 90;
    return {value:[landed ? {confirmationStatus:'finalized',err:null} : null]};
  };
  const result=client.finalized('existing',{serialized:'unchanged-bytes',lastValidBlockHeight:100});
  for(let i=0;i<12;i++) {await new Promise(resolve=>setImmediate(resolve));t.mock.timers.tick(2500);}
  await result;
  assert.deepEqual(broadcasts,['unchanged-bytes']);
});


test('wallet account-table reorder preserves payer, privileges and instructions', () => {
  const tx=fixture();
  // Add another unsigned read-only key so swapping the account-table entries is safe.
  tx.add(new web3.TransactionInstruction({programId:recipient,keys:[],data:Uint8Array.of(8)}));
  const before=tx.serializeMessage();
  const message=web3.Message.from(before);
  const a=message.accountKeys.length-2,b=a+1;
  assert.equal(message.isAccountWritable(a),false);
  assert.equal(message.isAccountWritable(b),false);
  [message.accountKeys[a],message.accountKeys[b]]=[message.accountKeys[b],message.accountKeys[a]];
  const remap=i=>i===a?b:i===b?a:i;
  for(const ix of message.instructions){ix.programIdIndex=remap(ix.programIdIndex);ix.accounts=ix.accounts.map(remap);}
  assert.notDeepEqual(before,message.serialize());
  validateWalletMessage(web3,before,message.serialize());
});

test('bounded wallet priority fee accepted; excessive fees and extra operations rejected', () => {
  const before=fixture().serializeMessage();
  const adjusted=fixture();
  adjusted.instructions[1]=web3.ComputeBudgetProgram.setComputeUnitPrice({microLamports:7000});
  validateWalletMessage(web3,before,adjusted.serializeMessage());
  adjusted.instructions[1]=web3.ComputeBudgetProgram.setComputeUnitPrice({microLamports:10000});
  assert.throws(()=>validateWalletMessage(web3,before,adjusted.serializeMessage()),/priority fee/);
  for(const change of [
    tx=>{tx.feePayer=recipient;},
    tx=>{tx.recentBlockhash=recipient.toBase58();},
    tx=>{tx.instructions[2].keys[1].isSigner=true;},
    tx=>{tx.instructions[2].keys[1].isWritable=false;},
    tx=>{tx.instructions[2].keys.reverse();},
    tx=>{tx.instructions[2].data[4]=9;},
    tx=>{tx.add(tx.instructions[2]);},
    tx=>{tx.add(web3.ComputeBudgetProgram.setComputeUnitPrice({microLamports:0}));},
    tx=>{tx.instructions[0]=web3.ComputeBudgetProgram.setComputeUnitLimit({units:1000000});},
  ]) {
    const changed=fixture(); change(changed);
    assert.throws(()=>validateWalletMessage(web3,before,changed.serializeMessage()),/Wallet changed/);
  }
});

test('wallet fee adjustment on a deserialized transaction is validated and signed bytes submitted', async () => {
  const client=new PairKey({web3});
  let submitted;
  client.rpc=async (method,params)=> {
    if(method==='getLatestBlockhash')return {value:{blockhash,lastValidBlockHeight:100}};
    if(method==='sendTransaction'){
      submitted=web3.Transaction.from(Buffer.from(params[0],'base64'));
      return 'test-signature';
    }
    return {value:[{confirmationStatus:'finalized',err:null}]};
  };
  const wallet={publicKey:payer.publicKey,signTransaction:async tx=>{
    const signed=web3.Transaction.from(tx.serialize({requireAllSignatures:false,verifySignatures:false}));
    signed.instructions[1]=web3.ComputeBudgetProgram.setComputeUnitPrice({microLamports:2000});
    signed.sign(payer); return signed;
  }};
  await client.send(wallet,[fixture().instructions[2]]);
  assert.equal(submitted.verifySignatures(),true);
  assert.equal(web3.ComputeBudgetInstruction.decodeSetComputeUnitPrice(submitted.instructions[1]).microLamports,2000n);
});
