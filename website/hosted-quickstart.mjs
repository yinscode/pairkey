import {PairKey} from './hosted-v2.mjs';
import {HostedSession} from './hosted-session.mjs';
const form = document.querySelector('[data-hosted-quickstart]');
if (form) {
  const $ = id => form.querySelector(`#${id}`);
  const program = form.dataset.hostedQuickstart === 'program';
  const tell = text => { $('hosted-output').textContent = text; };
  const linked = new Set();
  const link = signature => {
    if (linked.has(signature)) return;
    linked.add(signature);
    const a = document.createElement('a'); a.textContent = 'View transaction on Solana devnet';
    a.href = `https://explorer.solana.com/tx/${encodeURIComponent(signature)}?cluster=devnet`;
    a.target = '_blank'; a.rel = 'noopener noreferrer'; $('hosted-links').append(a, document.createElement('br'));
  };
  const client = new PairKey({web3: window.solanaWeb3, endpoint: `${location.origin}/api/v2`, onProgress: ({message, signature}) => {
    tell(message); if (signature) link(signature);
  }});
  const stages = {
    preparing: 'Checking the exact message, key and current policy…',
    authorizing: 'Approve this exact request with a wallet message signature. This step sends no transaction.',
    committing: 'Your program must consume an allowance. Approve its Solana transaction, then wait for finality.',
    submitting: 'Submitting the approved request to the hosted signers…',
    signing: 'Signing is in progress. Both signers must authorize and participate; individual completion is not yet reported.',
    recovering: 'Recovering the saved job. No new wallet approval or signing attempt will be made.',
  };
  const flow = new HostedSession(client, {onStage: stage => {if (stages[stage]) tell(stages[stage]);}});
  let loaded;
  const enable = (id, enabled) => {const control=$(id);if(control)control.dataset.wasDisabled=String(!enabled);};
  async function action(work) {
    const controls = [...form.querySelectorAll('button, input, select, textarea')];
    controls.forEach(b => {b.dataset.wasDisabled=String(b.disabled);b.disabled=true;});
    try {await work();} catch(e) {tell(`Action stopped: ${e.message || String(e)}`);}
    finally {controls.forEach(b=>{b.disabled=b.dataset.wasDisabled==='true';});}
  }
  function selection() {
    const index=Number($('hosted-path').value);
    if(!Number.isInteger(index)||index<0||index>4294967295)throw new Error('Path index must be an integer from 0 to 4294967295.');
    return {chain:$('hosted-chain').value,path:[index]};
  }
  function clearResult() {flow.result=undefined;enable('hosted-verify',false);$('hosted-signature').textContent='Your signature will appear here.';}
  function showResult(result) {
    $('hosted-signature').textContent=result.signature_hex;
    $('hosted-public-key').textContent=result.public_key_hex;
    $('hosted-message').value=result.signed_message;
    enable('hosted-verify',true);
    tell('Signature ready. Both signer receipts were returned. No destination transaction was broadcast.');
  }
  function programUnchanged() {
    if(program&&(!loaded||loaded.program!==$('hosted-program').value.trim()||loaded.mode!==$('hosted-mode').value))throw new Error('Program or approval mode changed. Connect again.');
  }
  $('hosted-connect').addEventListener('click',()=>action(async()=>{
    loaded=undefined;flow.reset();clearResult();enable('hosted-key',false);enable('hosted-sign',false);enable('hosted-policy',false);
    const wallet=window.phantom?.solana||window.solflare||window.solana;
    const options=program?{program:$('hosted-program').value.trim(),mode:$('hosted-mode').value}:{};
    if(program&&!options.program)throw new Error('Enter a program ID deployed with the v2 example ABI.');
    tell('Connecting your wallet and preparing public namespace metadata…');
    const ns=await flow.connect(wallet,options);loaded=options;
    $('hosted-public-key').textContent='Your key will appear here.';
    enable('hosted-key',true);enable('hosted-policy',true);
    tell(`Namespace ready without a registration transaction.\nAuthority: ${client.pubkey(ns.registration.namespace.derivation_authority)}\n${program?'Set or review the program’s policy, then load a derived key.':'Choose a chain and load its key. No SOL is needed for ordinary message approvals.'}`);
  }));
  $('hosted-key').addEventListener('click',()=>action(async()=>{
    programUnchanged();clearResult();enable('hosted-sign',false);
    tell('Loading the derived public key from the hosted signers…');
    const q=selection(),key=await flow.loadKey(q.chain,q.path);
    $('hosted-public-key').textContent=key.public_key_hex;
    tell(`Key ready.${key.address?` Public identifier: ${key.address}`:''}\nWrite a message, then approve the exact request.`);
    enable('hosted-sign',true);
  }));
  $('hosted-sign').addEventListener('click',()=>action(async()=>{
    programUnchanged();clearResult();
    showResult(await flow.sign({...selection(),message:$('hosted-message').value}));
  }));
  $('hosted-verify').addEventListener('click',()=>action(async()=>{
    const checked=await client.verify({...flow.result,signed_message:$('hosted-message').value});
    tell(checked.valid?'Service verification passed for the displayed message and derived public key. Use the Rust verifier for independent receipt and signature verification.':'Signature verification failed for the displayed message.');
  }));
  $('hosted-recover').addEventListener('click',()=>action(async()=>{clearResult();showResult(await flow.recover());}));
  $('hosted-example')?.addEventListener('click',()=>action(async()=>{
    const config=await client.config();
    if(!config.example_program)throw new Error('This deployment has no configured example program.');
    $('hosted-program').value=config.example_program;
    $('hosted-mode').value='Onchain';
    tell('Example program selected. On-chain approval supports its upgradeable code. Connect your wallet, then set your own policy.');
  }));
  $('hosted-policy')?.addEventListener('click',()=>action(async()=>{
    programUnchanged();client.checkWallet(flow.namespace,flow.wallet);
    if(!flow.wallet.signTransaction)throw new Error('Policy changes need wallet transaction signing and devnet SOL.');
    const current=await client.programPolicy(loaded.program,flow.wallet.publicKey);
    const q=selection(),remaining=Number($('hosted-allowance').value);
    if(!Number.isSafeInteger(remaining)||remaining<0)throw new Error('Allowance must be a nonnegative safe integer.');
    const signature=await client.setProgramPolicy(flow.wallet,{program:loaded.program,owner:flow.wallet.publicKey.toBase58(),revision:(current?.revision||0)+1,enabled:true,chain:q.chain,path_prefix:q.path,max_payload_bytes:1232,require_commit:loaded.mode==='Onchain',remaining_approvals:remaining});
    link(signature);clearResult();
    tell(`Program policy updated: ${q.chain}, path prefix ${q.path.join('/')}. ${loaded.mode==='Onchain'?`${remaining} on-chain approvals available.`:'Read-only approval; no counter is consumed.'} Load the key before signing.`);
    flow.key=undefined;enable('hosted-sign',false);
  }));
}
