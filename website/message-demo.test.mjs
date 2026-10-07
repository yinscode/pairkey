import test from 'node:test';
import assert from 'node:assert/strict';
import {messageEnvelope,messageFlow} from './message-demo.mjs';
test('message envelope binds all approval context, preserving UTF-8 text',()=>{
 const value=messageEnvelope('evm','account','controller','request','hello 🌍');
 assert.equal(value,'PairKey message signing v1\nDestination: EVM / Base Sepolia 84532\nAuthority: Solana account\nController: controller\nRequest: request\n\nhello 🌍');
 for(const args of [['near','account','controller','request','hello 🌍'],['evm','program','controller','request','hello 🌍'],['evm','account','other','request','hello 🌍'],['evm','account','controller','other','hello 🌍']])assert.notEqual(value,messageEnvelope(...args));
});
test('both receipt formats require independently identified verified roles',()=>{
 for(const nested of [false,true]) {
  const receipts=['A','B'].map(role=>nested?{receipt:{role,finalized_slot:10}}:{role,finalized_slot:10});
  const op={status:'complete',result:{signature_verified:true,receipts_verified:2,signature_hex:'0x1234',receipts}};
  assert.equal(messageFlow(op).assembled,true);op.result.receipts[1]=op.result.receipts[0];assert.equal(messageFlow(op).assembled,false);
 }
});
test('approval and in-flight uncertainty never imply a signature',()=>{
 let f=messageFlow({status:'working',needs_reconciliation:true,result:{approval_finalized:true}});assert.equal(f.approved,true);assert.equal(f.assembled,false);assert.equal(f.uncertain,false);assert.equal(f.signers[0].state,'waiting');
 f=messageFlow({status:'working',signing_started:true,needs_reconciliation:true});assert.equal(f.signers[0].state,'active');assert.equal(f.assembled,false);
 f=messageFlow({status:'needs_reconciliation',signing_started:true,needs_reconciliation:true});assert.equal(f.signers[0].state,'uncertain');
});
