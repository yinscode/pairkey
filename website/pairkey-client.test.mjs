import test from 'node:test';
import assert from 'node:assert/strict';
import {PairKeyClient} from './pairkey-client.mjs';

function fixture(identity) {
  const events=[],namespace={identity},key={public_key_hex:'0x01'},stored=new Map(),config={transaction_signing:{solana:{sign:true},evm:{sign:true},near:{sign:true},sui:{sign:true},bitcoin:{sign:true}},typed_data_signing:{evm:true}};
  const result=request=>request.transaction?{kind:'wallet',public_key_hex:'0x01',signature_hex:`0x${'02'.repeat(64)}`,transaction:request.transaction,signed_transaction_hex:'0x0102',signed_psbt_hex:'0x70736274ff',serialized_signature_hex:`0x00${'02'.repeat(64)}${'01'.repeat(32)}`}:{kind:'wallet'};
  const session={namespace:undefined,key:undefined,selection:undefined,
    storageKey:'pairkey-test',storage:{getItem:key=>stored.get(key)??null,setItem:(key,value)=>stored.set(key,value)},jobId:'job-1',
    connect:async(_wallet,options)=>session.namespace={identity:options.identity ?? identity,options,config},
    connectPasskey:async(given,options)=>session.namespace={identity:given,options,config},
    connectOidc:async(given,options)=>session.namespace={identity:given,options,config},
    loadKey:async(chain,path)=>{events.push(['key',chain,path]);session.key=key;session.selection={chain,path};return key;},
    sign:async request=>{events.push(['sign',request]);return result(request);},
    signPasskey:async(request,id)=>{events.push(['passkey',request,id]);return request.transaction?{kind:'passkey',public_key_hex:'0x01',signature_hex:'0x02',transaction:request.transaction,signed_transaction_hex:'0x0102'}:{kind:'passkey'};},
    prepareOidc:async request=>{events.push(['prepare-oidc',request]);return {ephemeral:{oidcNonce:'nonce'},prepared:{},key,request};},
    completeOidc:async(pending,token)=>{events.push(['oidc',token]);return pending.request.transaction?{kind:'oidc',public_key_hex:'0x01',signature_hex:'0x02',transaction:pending.request.transaction,signed_transaction_hex:'0x0102'}:{kind:'oidc'};},
    recover:async id=>{events.push(['recover',id]);return {id};},
  };
  const client=new PairKeyClient({client:{}});client.session=session;
  return {client,session,events,stored};
}

test('one interface connects and signs with account and program sources',async()=>{
  for(const source of ['account','program']){
    const identity=source==='account'?{Account:{public_key:[1]}}:{Program:{mode:'Offchain'}},f=fixture(identity);
    await f.client.connect({source,wallet:{},identity,namespace:'org/acme/treasury'});
    assert.equal(f.session.namespace.options.namespace,'org/acme/treasury');
    assert.equal((await f.client.signMessage({chain:'solana',message:'hello'})).result.kind,'wallet');
    assert.equal(f.events[0][0],'key');
  }
});
test('Sui signing returns BCS bytes plus the native serialized signature and sends through a Sui client',async()=>{
  const identity={Account:{public_key:[1]}},f=fixture(identity);await f.client.connect({wallet:{},identity});
  const calls=[];
  const signed=await f.client.signAndSend({chain:'sui',transaction:Uint8Array.of(4,5,6),connection:{executeTransaction:async request=>{calls.push(request);return {$kind:'Transaction',Transaction:{digest:'sui-digest',effects:{status:{success:true}}}};}}});
  assert.deepEqual([...signed.signedTransaction],[4,5,6]);
  assert.equal(signed.serializedSignature.length,97);
  assert.equal(signed.serializedSignature[0],0);
  assert.deepEqual([...calls[0].transaction],[4,5,6]);
  assert.equal(calls[0].signatures.length,1);
  assert.equal(signed.transactionId,'sui-digest');
  assert.equal(signed.status,'confirmed');
});

test('broadcast uncertainty preserves exact bytes for recovery and rebroadcast',async()=>{
  const identity={Account:{public_key:[1]}},f=fixture(identity);await f.client.connect({wallet:{},identity});
  const transaction={chain_id:84532,nonce:1,gas_price:2,gas_limit:21000,to:Array(20).fill(3),value:4};
  const uncertain=await f.client.signAndSend({chain:'evm',transaction,broadcast:async()=>{throw new Error('timeout')}});
  assert.equal(uncertain.status,'unknown');assert.match(uncertain.broadcastError,/timeout/);
  const saved=JSON.parse(f.stored.get('pairkey-test:broadcast:job-1'));
  assert.equal(saved.signed_transaction_hex,'0x0102');assert.equal(saved.status,'unknown');
  f.session.recover=async()=>({transaction:{evm_legacy:{transfer:transaction}},public_key_hex:'0x01',signature_hex:'0x02',signed_transaction_hex:'0x0102'});
  const recovered=await f.client.recoverAndSend('job-1',{chain:'evm',broadcast:async bytes=>{assert.deepEqual([...bytes],[1,2]);return '0xrecovered'}});
  assert.equal(recovered.transactionId,'0xrecovered');assert.equal(recovered.status,'submitted');assert.equal(recovered.recovered,true);
});
test('transaction signing assembles hosted EVM bytes for account and program sources',async()=>{
  for(const source of ['account','program']){
    const identity=source==='account'?{Account:{public_key:[1]}}:{Program:{mode:'Offchain'}},f=fixture(identity);await f.client.connect({source,wallet:{},identity});
    let broadcasts=0;
    const result=await f.client.signAndSend({chain:'evm',transaction:{chain_id:84532,nonce:1,gas_price:2,gas_limit:21000,to:Array(20).fill(3),value:4},
      broadcast:async bytes=>{broadcasts++;assert.deepEqual([...bytes],[1,2]);return '0xtx';}});
    assert.equal(result.transactionId,'0xtx');assert.equal(result.status,'submitted');assert.equal(broadcasts,1);
    assert.equal(f.events.filter(([kind])=>kind==='sign').length,1);
    assert.equal(f.events.find(([kind])=>kind==='sign')[1].transaction.evm_legacy.transfer.value,4);
  }
});

test('EVM chainId selects a distinct exact destination and binds the transfer',async()=>{
  const f=fixture({Account:{public_key:[1]}});await f.client.connect({wallet:{}});
  const transaction={chain_id:1,nonce:1,gas_price:2,gas_limit:21000,to:Array(20).fill(3),value:4};
  await f.client.signTransaction({chain:'evm',chainId:1,transaction});
  assert.deepEqual(f.events.find(([kind])=>kind==='key')[1],{evm_chain:{chain_id:1}});
  assert.deepEqual(f.events.find(([kind])=>kind==='sign')[1].chain,{evm_chain:{chain_id:1}});
  await assert.rejects(()=>f.client.signTransaction({chain:'evm',chainId:0,transaction}),/Invalid EVM chain ID/);
});

test('EIP-712 signs full typed data on its domain chain',async()=>{
  const f=fixture({Account:{public_key:[1]}});await f.client.connect({wallet:{}});
  f.session.sign=async request=>{f.events.push(['sign',request]);return {public_key_hex:'0x01',signature_hex:`0x${'02'.repeat(64)}01`};};
  const typedData={types:{EIP712Domain:[{name:'chainId',type:'uint256'}],Vote:[{name:'support',type:'bool'}]},
    primaryType:'Vote',domain:{chainId:1},message:{support:true}};
  const signed=await f.client.signTypedData({chainId:1,typedData});
  assert.equal(signed.evmSignatureHex,`0x${'02'.repeat(64)}1c`);
  assert.deepEqual(f.events.find(([kind])=>kind==='key')[1],{evm_chain:{chain_id:1}});
  const wire=f.events.find(([kind])=>kind==='sign')[1].transaction.evm_typed_data.typed_data;
  assert.equal(wire.chain_id,1);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(Uint8Array.from(wire.json))),typedData);
  await assert.rejects(()=>f.client.signTypedData({chainId:84532,typedData}),/domain chainId/);
});

test('Bitcoin PSBT returns finalized bytes and preserves them for recovery',async()=>{
  const f=fixture({Account:{public_key:[1]}});await f.client.connect({wallet:{}});
  const spend={network:'testnet',psbt:[112,115,98,116,255],outputs:[{value_sats:99000,script_pubkey:[81]}],max_fee_sats:1000,max_fee_rate_sat_vb:10};
  const signed=await f.client.signAndSend({chain:'bitcoin',transaction:spend,broadcast:async bytes=>{assert.deepEqual([...bytes],[1,2]);return 'btc-txid';}});
  assert.deepEqual([...signed.signedPsbt],[112,115,98,116,255]);
  assert.equal(signed.transactionId,'btc-txid');
  assert.deepEqual(f.events.find(([kind])=>kind==='sign')[1].transaction,{bitcoin_psbt:{spend}});
  f.session.recover=async()=>({transaction:{bitcoin_psbt:{spend}},public_key_hex:'0x01',signature_hex:'0x02',signed_transaction_hex:'0x0102',signed_psbt_hex:'0x70736274ff'});
  const recovered=await f.client.recoverAndSend('job-1',{chain:'bitcoin',broadcast:async bytes=>{assert.deepEqual([...bytes],[1,2]);return 'btc-txid';}});
  assert.deepEqual([...recovered.signedPsbt],[112,115,98,116,255]);
});

test('one interface keeps passkey and OIDC ephemeral authentication source-specific',async()=>{
  const passkey={Passkey:{public_key:[2],rp_id:'example',origin:'https://example'}},p=fixture(passkey);
  await p.client.connect({source:'passkey',identity:passkey,credentialId:[7]});
  assert.equal((await p.client.signMessage({chain:'solana',message:'hello'})).result.kind,'passkey');
  assert.deepEqual(p.events.at(-1)[2],[7]);
  assert.deepEqual([...(await p.client.signTransaction({chain:'near',transaction:Uint8Array.of(4)})).signedTransaction],[1,2]);

  const oidc={Oidc:{issuer:'https://issuer',audience:'client',subject:'user'}},o=fixture(oidc);
  await o.client.connect({source:'oidc',identity:oidc,getIdToken:async({nonce})=>`token:${nonce}`});
  assert.equal((await o.client.signMessage({chain:'near',message:'hello'})).result.kind,'oidc');
  assert.deepEqual(o.events.at(-1),['oidc','token:nonce']);
  assert.deepEqual([...(await o.client.signTransaction({chain:'near',transaction:Uint8Array.of(4)})).signedTransaction],[1,2]);
  assert.deepEqual((await o.client.recover('job')).result,{id:'job'});
});
