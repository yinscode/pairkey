import test from 'node:test';
import assert from 'node:assert/strict';
import {flowFor} from './demo-flow.mjs';
const hash='0x'+'ab'.repeat(32);
const signed={action:'transfer',status:'working',signing_started:true,needs_reconciliation:true,transaction_hash:hash,result:{signature_verified:true,receipts_verified:2,receipts:[{role:'A',signature:[1,2],finalized_slot:10},{role:'B',signature:[1,2],finalized_slot:11}]}};
test('working uncertainty means MPC pending, not success or a reconciliation failure',()=>{
 const f=flowFor({action:'transfer',status:'working',needs_reconciliation:true,signing_started:true});
 assert.deepEqual(f.signers.map(s=>s.state),['active','active']);assert.equal(f.uncertain,false);assert.equal(f.assembled,false);
});
test('preflight refusal never implies either signer ran',()=>{
 const f=flowFor({action:'transfer',status:'rejected',signing_started:false});assert.deepEqual(f.signers.map(s=>s.state),['waiting','waiting']);assert.equal(f.failed,true);
});
test('assembly needs verified receipts from both distinct roles',()=>{
 assert.equal(flowFor(signed).assembled,true);assert.equal(flowFor(signed).signature,'0x0102');
 const duplicate=structuredClone(signed);duplicate.result.receipts[1].role='A';assert.equal(flowFor(duplicate).assembled,false);
 const unverified=structuredClone(signed);unverified.result.receipts_verified=1;assert.equal(flowFor(unverified).assembled,false);
});
test('saved signed transaction is not yet proof of broadcast or execution',()=>{
 const f=flowFor(signed);assert.equal(f.assembled,true);assert.equal(f.broadcast,false);assert.equal(f.confirmed,false);
 const accepted=structuredClone(signed);accepted.result.broadcast_accepted=true;assert.equal(flowFor(accepted).broadcast,true);assert.equal(flowFor(accepted).confirmed,false);
});
test('zero-block preconfirmation and another transaction receipt cannot turn green',()=>{
 const op=structuredClone(signed);op.result.receipt={status:'0x1',blockHash:'0x'+'0'.repeat(64),blockNumber:'0x1',transactionHash:hash};assert.equal(flowFor(op).confirmed,false);
 op.result.receipt.blockHash='0x'+'cd'.repeat(32);op.result.receipt.transactionHash='0x'+'ef'.repeat(32);assert.equal(flowFor(op).confirmed,false);
 op.result.receipt.transactionHash=hash;assert.equal(flowFor(op).confirmed,true);
 op.result.receipt.status='0x0';assert.equal(flowFor(op).confirmed,false);assert.equal(flowFor(op).reverted,true);
});
test('signing timeout preserves unknown outcomes instead of claiming no signature',()=>{
 const f=flowFor({action:'transfer',status:'needs_reconciliation',needs_reconciliation:true,signing_started:true});assert.equal(f.uncertain,true);assert.deepEqual(f.signers.map(s=>s.state),['uncertain','uncertain']);assert.equal(f.destination,'uncertain');
});
test('revocation does not invent signer or broadcast work',()=>{
 const f=flowFor({action:'revoke',status:'complete',result:{revoked:true}});assert.equal(f.transfer,false);assert.equal(f.assembled,false);assert.equal(f.broadcast,false);
});
