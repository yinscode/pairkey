import {PairKey} from './hosted-v2.mjs';
import {HostedSession} from './hosted-session.mjs';
import {chainLabels,messageFlowV2} from './message-demo.mjs';
import {readGoogleClaims,showGoogleButton} from './google-oidc.mjs';
const $=id=>document.getElementById(id),short=(s,n=10)=>s?`${s.slice(0,n)}…${s.slice(-6)}`:'—';
const recoveryKey='pairkey-v2-demo-recovery',historyKey='pairkey-v2-demo-history';
const schemes={solana:'FROST Ed25519',evm:'DKLS23 · secp256k1',zcash:'FROST RedPallas',near:'FROST Ed25519',bitcoin:'FROST secp256k1 · BIP-340'};
let config,googleIssuer,googleGeneration=0,pendingOidc,connectedScope,busy=false,verifying=false,currentOp,activeOp,verificationFor;
let history=[];
try {history=JSON.parse(sessionStorage.getItem(historyKey)||'[]').slice(-12).filter(o=>o&&typeof o.id==='string'&&Array.isArray(o.events)&&Array.isArray(o.transactions)).map(o=>({...o,validated:false,stage:o.stage==='complete'?'complete':'uncertain'}));} catch {}
const client=new PairKey({web3:window.solanaWeb3,endpoint:`${location.origin}/api/v2`,onProgress:({message,signature})=>{
  $('setup-message').textContent=message;
  if(activeOp){activeOp.events.push(message);if(signature&&!activeOp.transactions.includes(signature))activeOp.transactions.push(signature);renderOperation(activeOp);}
}});
const flow=new HostedSession(client,{storageKey:recoveryKey,onStage:(stage,data={})=>{
  if(!activeOp)return;
  activeOp.stage=stage;
  if(data.prepared){activeOp.prepared=data.prepared;activeOp.chain=data.prepared.signing_request.key.chain;}
  if(data.jobId)activeOp.jobId=data.jobId;
  if(stage==='authorizing'||stage==='complete'){
    const saved=JSON.parse(sessionStorage.getItem(recoveryKey));
    activeOp.recovery=saved;
  }
  if(stage==='complete'){activeOp.result=data.result;activeOp.validated=true;}
  const messages={preparing:'Preparing and checking the exact request.',authorizing:flow.namespace?.identity?.Oidc?'Waiting for a Google ID token bound to this exact request.':'Waiting for the caller’s wallet message signature.',committing:'Waiting for the program’s on-chain approval and finality.',submitting:'Submitting the authenticated request.',signing:'Job admitted. Waiting for both signers and the final result.',recovering:'Reading the original job and saved receipts; no new signing.',complete:'Signature and both receipts returned. The hosted Rust SDK verified the result.'};
  if(messages[stage])activeOp.events.push(messages[stage]);
  saveHistory();renderOperation(activeOp);
}});
function selection(){
  const index=Number($('demo-path').value);
  if(!Number.isInteger(index)||index<0||index>4294967295)throw new Error('Path index must be an integer from 0 to 4294967295.');
  return {chain:$('message-chain').querySelector('input:checked').value,path:[index]};
}
function scope(){return JSON.stringify({source:$('message-authority').value,program:$('demo-program').value.trim(),mode:$('demo-mode').value});}
function connected(){return !!flow.namespace&&connectedScope===scope();}
function saveHistory(){
  if(activeOp&&!history.includes(activeOp))history.push(activeOp);
  history=history.slice(-12);
  try{sessionStorage.setItem(historyKey,JSON.stringify(history.map(({validated,...record})=>record)));}
  catch{$('live-error').textContent='Could not save additional history. Keep the public recovery record and transcript shown below.';}
  renderHistory();
}
function renderHistory(){
  $('operation-history').replaceChildren(...history.map(o=>{const option=document.createElement('option');option.value=o.id;option.textContent=`${chainLabels[o.chain]||'Message'} · ${short(o.jobId||o.id,6)} · ${o.stage}`;return option;}));
  if(currentOp)$('operation-history').value=currentOp.id;
}
function controls(){
  for(const control of $('message-form').querySelectorAll('input,select,textarea,button,fieldset'))control.disabled=busy||!!pendingOidc;
  const source=$('message-authority').value,program=source==='program',google=source==='google';
  $('source-account-label').textContent=google?'Google source':'Connected Solana account';
  $('authority-costs-copy').textContent=google?'A Google ID token authorizes each exact request, without a Solana wallet or per-signature Solana transaction. Optional policy edits need a separate Solana fee payer. Hosted workers hold their own key shares.':'Your wallet controls this request. Account off-chain approvals need no SOL. Policy edits and program commits need devnet fees and any account rent. Hosted workers hold their own key shares.';
  $('program-controls').hidden=!program;$('program-policy-controls').hidden=!program;
  $('google-controls').hidden=!google;
  $('google-button').hidden=!google||connected()&&!pendingOidc;
  $('google-cancel').hidden=!pendingOidc;
  $('google-cancel').disabled=busy;
  $('demo-connect').hidden=google&&!connected();
  $('demo-connect').textContent=google?'Change Google account':'Connect wallet';
  $('demo-connect').disabled=busy||!!pendingOidc||!config||config.ready===false;
  $('demo-example').disabled=busy||!!pendingOidc||!config?.example_program;
  $('demo-key').disabled=busy||!!pendingOidc||!connected();
  $('demo-policy').disabled=busy||!!pendingOidc||!connected();
  let keyMatches=false;try{keyMatches=JSON.stringify(selection())===JSON.stringify(flow.selection);}catch{}
  const bytes=new TextEncoder().encode($('message-text').value).length;
  $('message-size').textContent=`${bytes} / 256 UTF-8 bytes`;
  $('demo-sign').disabled=busy||!!pendingOidc||!connected()||!flow.key||!keyMatches||bytes===0||bytes>256;
  $('demo-sign').firstChild.textContent=google?'Prepare Google approval ':'Approve & sign ';
  $('live-resume').disabled=busy||!!pendingOidc;
  $('operation-history').disabled=busy||verifying||!!pendingOidc;
  $('verify-button').disabled=busy||verifying||!currentOp?.result?.signature_hex;
  for(const id of ['verify-message','verify-key','verify-signature'])$(id).disabled=busy||verifying||!currentOp?.result?.signature_hex;
}
function draft(){
  const source=$('message-authority').value,program=source==='program';
  $('authority-help').textContent=program?'Your program evaluates the authenticated caller and its own rules.':source==='google'?'Choose a Google account. Google will authorize each exact message with a fresh bound ID token.':'Your connected wallet approves each exact request off-chain.';
  let q;try{q=selection();}catch{}
  $('message-preview').textContent=JSON.stringify({source,...q,message:$('message-text').value},null,2);
  controls();if(!currentOp)renderFlow();
}
function clearKey(){flow.key=flow.selection=undefined;$('derived-key').textContent='Load the selected chain and path’s key.';$('derived-scheme').textContent='';$('derived-address').hidden=true;$('key-format').textContent='';}
function clearConnection(){googleGeneration++;pendingOidc=undefined;flow.reset();connectedScope=undefined;clearKey();$('demo-wallet').textContent='Connect your authority.';$('sol-address').textContent=$('controller-address').textContent='—';}
async function googleButton(nonce){
  const generation=++googleGeneration;
  $('google-help').textContent=nonce?'Continue with the same Google account to approve this exact message.':'Choose a Google account to derive its PairKey namespace.';
  await showGoogleButton($('google-button'),{audience:googleIssuer.audience,nonce,onCredential:credential=>{
    if(generation!==googleGeneration||$('message-authority').value!=='google')return;
    void run(async()=>{
      if(!credential)throw new Error('Google did not return an ID token.');
      if(nonce){
        const pending=pendingOidc;
        if(!pending||pending.ephemeral.oidcNonce!==nonce)throw new Error('Google approval expired. Prepare the request again.');
        readGoogleClaims(credential,googleIssuer.audience,{subject:pending.namespace.identity.Oidc.subject,nonce,issuedAfter:pending.ephemeral.binding.issued_at});
        activeOp=currentOp;
        await flow.completeOidc(pending,credential);
        pendingOidc=undefined;$('google-help').textContent='Signature complete. Prepare another message for a new approval.';
      }else{
        const identity=readGoogleClaims(credential,googleIssuer.audience);
        clearConnection();currentOp=undefined;renderFlow();
        const namespace=await flow.connectOidc({Oidc:identity});connectedScope=scope();
        $('demo-wallet').textContent=`Google account selected: ${short(identity.subject)}. Each signing token is verified by both signers.`;
        $('sol-address').textContent='No Solana wallet required';
        $('controller-address').textContent=client.pubkey(namespace.registration.namespace.derivation_authority).toBase58();
        $('setup-message').textContent='Google namespace ready. Load a derived key.';
      }
      draft();
    },failed);
  }});
}
async function run(work,onError){
  if(busy)return;busy=true;$('live-error').textContent='';controls();
  try{await work();}catch(e){$('live-error').textContent=e.message||String(e);onError?.(e);}
  finally{activeOp=undefined;busy=false;controls();}
}
function paint(name,state,status,detail){$(`flow-${name}`).dataset.state=state;$(`${name}-status`).textContent=status;$(`${name}-detail`).textContent=detail;}
function renderFlow(op){
  const view=messageFlowV2(op),identity=op?.prepared?.request.identity,program=identity?!!identity.Program:$('message-authority').value==='program',google=identity?!!identity.Oidc:$('message-authority').value==='google';
  const onchain=identity?.Program?.mode==='Onchain';
  $('authority-title').textContent=program?'Your Solana program':google?'Your Google account':'Your Solana account';
  $('authority-kind').textContent=google?'AUTHORITY / GOOGLE OIDC':'AUTHORITY / SOLANA';
  $('authority-icon').textContent=google?'G':'{ }';
  $('flow-context').textContent=op?`${chainLabels[op.chain]||'Message'} · ${short(op.jobId||op.id,8)} · ${op.stage}`:'Connect your authority, choose a key and follow its signature.';
  const status={preparing:'Preparing',authorizing:google?'Google approval':'Wallet approval',committing:'Finalizing',submitting:'Caller approved',signing:'Admitted',complete:'Approved',recovering:'Recovering',uncertain:'Unknown',stopped:'Stopped'}[view.stage]||'Waiting';
  const detail=view.assembled?(onchain?'Matching on-chain program approval and current policy checked by both signers.':'Exact caller proof and current rules checked by both signers.'):
    view.stage==='committing'?'The program must consume an allowance and record approval in one finalized transaction.':
    view.stage==='authorizing'?(google?'Waiting for Google to issue a token bound to this request. No signing result exists yet.':'Waiting for a wallet message signature over the exact request. No signing result exists yet.'):
    view.stage==='signing'?'The request was admitted. Both signers recheck authorization before releasing their output.':
    view.uncertain?'No verified outcome is available. Recover the original job before making another request.':
    view.saved?'Saved request metadata. Recover the job to recheck its original receipt pair.':
    view.stopped?'The page stopped before submitting a signing job. See the audit trail for the failure.':'The caller authorizes an exact request; the selected policy determines whether it may be signed.';
  paint('authority',view.assembled?'verified':view.uncertain?'uncertain':['preparing','authorizing','committing','submitting','signing','recovering'].includes(view.stage)?'active':'waiting',status,detail);
  $('flow-notice').hidden=!(view.uncertain||view.stopped||view.saved);
  $('flow-notice').textContent=view.uncertain?'Outcome unresolved. Recovery only reads the original attempt; it does not sign again.':view.saved?'Saved result shown without a fresh receipt check. The Verify button checks the signature; recovery checks the original hosted job.':'No signing job was submitted by this page. A program approval transaction may still need reconciliation.';
  for(const signer of view.signers){
    const role=signer.role.toLowerCase(),identities=op?.recovery?.deployment?.signer_identities||config?.signer_identities;
    const identityText=identities?.[role==='a'?0:1]?client.pubkey(identities[role==='a'?0:1]).toBase58():undefined;
    paint(`signer-${role}`,signer.state,signer.receipt?'Receipt verified':signer.state==='active'?'Signing…':signer.state==='uncertain'?'Unknown':'Waiting',signer.receipt?'The hosted Rust SDK verified this identity-signed receipt and the final signature.':signer.state==='active'?'Checks authorization independently and participates in threshold signing. Individual completion is not reported.':'Holds a separate key share and independently enforces authorization.');
    $(`signer-${role}-evidence`).textContent=`Identity ${short(identityText)} · ${signer.receipt?`finalized slot ${signer.receipt.finalized_slot}`:'receipt pending'}`;
  }
  for(const label of document.querySelectorAll('.signer-scheme'))label.textContent=schemes[op?.chain||$('message-chain').querySelector('input:checked').value];
  paint('assembly',view.assembled?'verified':view.uncertain?'uncertain':'waiting',view.assembled?'Verified by service':view.saved?'Saved signature':view.uncertain?'Unknown':'Waiting',view.assembled?'One signature and both matching receipts returned. Verify the displayed message below.':'Signing contributions combine. The full private key is never assembled.');
  $('signature-preview').hidden=!op?.result?.signature_hex;$('signature-preview').textContent=op?.result?.signature_hex||'';
  if(verificationFor!==op?.id||!op?.result){
    verificationFor=op?.id;
    $('verify-message').value=op?.result?.signed_message||'';$('verify-key').value=op?.result?.public_key_hex||'';$('verify-signature').value=op?.result?.signature_hex||'';
    $('verify-result').textContent=op?.result?'Ready for fresh service-side signature verification.':'A completed signature will appear here.';delete $('verify-result').dataset.valid;
  }else if(op?.result&&!$('verify-signature').value){
    $('verify-message').value=op.result.signed_message;$('verify-key').value=op.result.public_key_hex;$('verify-signature').value=op.result.signature_hex;
    $('verify-result').textContent='Ready for fresh service-side signature verification.';
  }
}
function renderOperation(op){
  currentOp=op;const view=messageFlowV2(op);
  $('operation-title').textContent=view.assembled?'One message. One verified signature.':view.uncertain?'Reconcile the original request.':view.saved?'Saved signing result.':'Follow your signing request.';
  $('operation-state').textContent=op.stage;
  $('operation-events').replaceChildren(...op.events.map(message=>{const li=document.createElement('li');li.textContent=message;return li;}));
  const recovery=op.recovery;
  $('operation-json').textContent=JSON.stringify(op.result&&recovery?{request:recovery.prepared.signing_request,approval:recovery.prepared.request,key:recovery.key,result:op.result,identities:recovery.deployment.signer_identities}:{job_id:op.jobId,prepared:op.prepared},null,2);
  $('operation-links').replaceChildren(...op.transactions.map(signature=>{const a=document.createElement('a');a.href=`https://explorer.solana.com/tx/${encodeURIComponent(signature)}?cluster=devnet`;a.textContent='Solana program approval →';a.target='_blank';a.rel='noopener noreferrer';return a;}));
  renderFlow(op);renderHistory();controls();
}
function failed(error){
  if(!activeOp)return;
  activeOp.stage=['submitting','signing','recovering'].includes(activeOp.stage)?'uncertain':'stopped';
  if(pendingOidc){pendingOidc=undefined;googleGeneration++;$('google-button').replaceChildren();$('google-help').textContent='Approval stopped. Prepare a new exact request to try again.';}
  activeOp.events.push(error.message||String(error));saveHistory();renderOperation(activeOp);
}
$('demo-example').addEventListener('click',()=>{clearConnection();$('demo-program').value=config.example_program;$('demo-mode').value='Onchain';draft();});
$('demo-connect').addEventListener('click',()=>run(async()=>{
  clearConnection();currentOp=undefined;renderFlow();
  if($('message-authority').value==='google'){await googleButton();draft();return;}
  const wallet=window.phantom?.solana||window.solflare||window.solana;
  const program=$('message-authority').value==='program';
  const options=program?{program:$('demo-program').value.trim(),mode:$('demo-mode').value}:{};
  if(program&&!options.program)throw new Error('Choose the hosted example or enter a v2 program ID.');
  const namespace=await flow.connect(wallet,options);connectedScope=scope();
  $('demo-wallet').textContent=`Connected: ${short(wallet.publicKey.toBase58())}`;$('sol-address').textContent=wallet.publicKey.toBase58();
  $('controller-address').textContent=client.pubkey(namespace.registration.namespace.derivation_authority).toBase58();
  $('setup-message').textContent='Namespace ready without a registration transaction. Load a derived key.';draft();
}));
$('demo-key').addEventListener('click',()=>run(async()=>{
  if(!connected())throw new Error('Source changed. Connect again.');
  clearKey();const q=selection(),key=await flow.loadKey(q.chain,q.path);
  $('derived-key').textContent=key.public_key_hex;$('derived-scheme').textContent=schemes[q.chain];
  $('derived-address').hidden=!key.address;$('derived-address').textContent=key.address||'';
  $('key-format').textContent=q.chain==='zcash'?'RedPallas verification key; not a complete shielded address.':q.chain==='bitcoin'?'32-byte x-only Taproot output key; custom PairKey message format.':'Derived signing public key for the selected destination.';
  $('setup-message').textContent='Key ready. Approve an exact message to request signing.';draft();
}));
$('demo-policy').addEventListener('click',()=>run(async()=>{
  if(!connected()||!flow.namespace.identity.Program)throw new Error('Connect your program authority first.');
  client.checkWallet(flow.namespace,flow.wallet);
  if(!flow.wallet.signTransaction)throw new Error('Policy updates require wallet transaction signing and devnet SOL.');
  const q=selection(),program=$('demo-program').value.trim(),remaining=Number($('demo-allowance').value);
  if(!Number.isSafeInteger(remaining)||remaining<0)throw new Error('Allowance must be a nonnegative safe integer.');
  const current=await client.programPolicy(program,flow.wallet.publicKey);
  await client.setProgramPolicy(flow.wallet,{program,owner:flow.wallet.publicKey.toBase58(),revision:(current?.revision||0)+1,enabled:true,chain:q.chain,path_prefix:q.path,max_payload_bytes:1232,require_commit:$('demo-mode').value==='Onchain',remaining_approvals:remaining});
  clearKey();$('setup-message').textContent='Program policy finalized. Load the selected key before signing.';
}));
$('message-form').addEventListener('submit',event=>{event.preventDefault();void run(async()=>{
  if(!connected())throw new Error('Connect the selected authority first.');
  activeOp={id:crypto.randomUUID(),chain:selection().chain,stage:'preparing',events:[],transactions:[]};
  verificationFor=undefined;
  if($('message-authority').value==='google'){
    pendingOidc=await flow.prepareOidc({...selection(),message:$('message-text').value});
    await googleButton(pendingOidc.ephemeral.oidcNonce);
    $('setup-message').textContent='Approve this exact message with Google below.';
  }else await flow.sign({...selection(),message:$('message-text').value});
},failed);});
$('google-cancel').addEventListener('click',()=>{pendingOidc=undefined;googleGeneration++;$('google-button').replaceChildren();$('google-help').textContent='Approval cancelled. Prepare a new exact request when ready.';if(currentOp?.stage==='authorizing'){currentOp.stage='stopped';currentOp.events.push('Google approval cancelled before submission.');saveHistory();renderOperation(currentOp);}controls();});
$('live-resume').addEventListener('click',()=>run(async()=>{
  const saved=JSON.parse(sessionStorage.getItem(recoveryKey)||'null');
  if(!saved)throw new Error('No v2 demo job is saved in this tab.');
  activeOp=history.find(o=>o.jobId===saved.job_id)||{id:crypto.randomUUID(),jobId:saved.job_id,chain:saved.prepared.signing_request.key.chain,prepared:saved.prepared,recovery:saved,events:[],transactions:[]};
  activeOp.result=undefined;activeOp.validated=false;verificationFor=undefined;await flow.recover();
},failed));
for(const id of ['message-authority','demo-program','demo-mode'])$(id).addEventListener('input',()=>{clearConnection();draft();const google=$('message-authority').value==='google';$('setup-message').textContent=google?'Choose a Google account to continue. No Solana wallet is needed.':'Connect a Solana wallet to authorize the selected source.';if(google&&googleIssuer)void googleButton().catch(error=>{$('live-error').textContent=error.message;});});
for(const id of ['message-chain','demo-path'])$(id).addEventListener('input',()=>{clearKey();draft();});
$('message-text').addEventListener('input',draft);
$('operation-history').addEventListener('change',()=>{const op=history.find(o=>o.id===$('operation-history').value);if(op){verificationFor=undefined;renderOperation(op);}});
for(const id of ['verify-message','verify-key','verify-signature'])$(id).addEventListener('input',()=>{$('verify-result').textContent='Inputs changed. Verify again.';delete $('verify-result').dataset.valid;});
$('verify-button').addEventListener('click',async()=>{
  if(!currentOp?.result)return;
  verifying=true;controls();const id=currentOp.id,request={chain:currentOp.result.chain,public_key_hex:$('verify-key').value,signed_message:$('verify-message').value,signature_hex:$('verify-signature').value};
  $('verify-result').textContent='Checking the signature…';
  try{const checked=await client.verify(request);if(currentOp?.id===id){$('verify-result').dataset.valid=String(checked.valid);$('verify-result').textContent=checked.valid?'Valid signature for these exact inputs. Fresh service-side verification passed.':'Invalid signature: message, public key or signature does not match.';}}
  catch(error){if(currentOp?.id===id){$('verify-result').textContent=error.message;delete $('verify-result').dataset.valid;}}
  finally{verifying=false;controls();}
});
try{
  config=await client.config();$('setup-title').textContent=config.ready===false?'Backend is initializing':'Hosted v2 connected';
  $('setup-message').textContent='Connect your own wallet. Off-chain account approval sends no transaction.';
  googleIssuer=config.oidc_issuers?.find(x=>x.issuer==='https://accounts.google.com');
  $('google-source').disabled=!googleIssuer;
  $('connection-light').dataset.ready=String(config.ready!==false);$('flow-live').textContent=config.hardware_backed?'HOSTED SIGNERS':'DEVELOPMENT SIGNERS';
}catch(error){$('setup-title').textContent='Hosted v2 unavailable';$('setup-message').textContent='This page needs the coordinated v2 backend. Check the deployment or retry after it is available.';$('flow-live').textContent='DISCONNECTED';}
renderHistory();if(history.length)renderOperation(history.at(-1));draft();
