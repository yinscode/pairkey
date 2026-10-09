export const chainLabels = {solana:'Solana',evm:'EVM / Base Sepolia 84532',zcash:'Zcash / RedPallas',near:'NEAR',bitcoin:'Bitcoin / BIP-340'};
export function messageEnvelope(chain,authority,controller,id,message) {
  return `PairKey message signing v1\nDestination: ${chainLabels[chain]}\nAuthority: ${authority==='program'?'Solana program':'Solana account'}\nController: ${controller}\nRequest: ${id}\n\n${message}`;
}
export function messageFlow(op) {
  const r=op?.result || {}, working=op?.status==='working';
  const receiptList=Array.isArray(r.receipts)?r.receipts:[];
  const trusted=r.signature_verified===true && r.receipts_verified===2;
  const signers=['A','B'].map(role=>{
    const matches=receiptList.map(receipt=>receipt.receipt || receipt).filter(receipt=>receipt.role===role);
    const receipt=trusted && matches.length===1?matches[0]:null;
    return {role,receipt,state:receipt?'verified':working && op.signing_started?'active':!working && op?.needs_reconciliation?'uncertain':'waiting'};
  });
  return {working,signers,assembled:trusted && signers.every(s=>s.receipt) && !!r.signature_hex,uncertain:!working && !!op?.needs_reconciliation,failed:op?.status==='rejected',approved:r.approval_finalized===true};
}

/** V2 states come from the shared hosted lifecycle. A wallet prompt, an admitted
 * job or a saved success flag alone is never evidence of a completed signature. */
export function messageFlowV2(operation) {
  const stage=operation?.stage||'idle',r=operation?.result;
  const receipts=Array.isArray(r?.receipts)?r.receipts.map(x=>x.receipt||x):[];
  const trusted=stage==='complete'&&operation?.validated===true&&r?.signature_verified===true;
  const signers=['A','B'].map(role=>{
    const matches=receipts.filter(x=>x.role===role);
    const receipt=trusted&&matches.length===1?matches[0]:null;
    return {role,receipt,state:receipt?'verified':stage==='signing'?'active':['uncertain','recovering'].includes(stage)?'uncertain':'waiting'};
  });
  return {stage,signers,assembled:trusted&&signers.every(s=>s.receipt)&&!!r?.signature_hex,
    saved:!!r?.signature_hex&&!trusted,uncertain:stage==='uncertain',
    callerApproved:['submitting','signing','complete'].includes(stage),
    stopped:stage==='stopped'};
}
