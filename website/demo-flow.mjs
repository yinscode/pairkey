// Project persisted backend evidence into UI states. Never infer worker success from elapsed time.
export function flowFor(op) {
  const result = op?.result || {};
  const transfer = ['transfer', 'retry'].includes(op?.action);
  const working = op?.status === 'working';
  const uncertain = !working && !!op?.needs_reconciliation;
  const failed = !working && op?.status === 'rejected';
  const receipts = Array.isArray(result.receipts) ? result.receipts : [];
  const verified = result.signature_verified === true && result.receipts_verified === 2;
  const signers = ['A', 'B'].map(role => {
    const matches = receipts.filter(r => r.role === role);
    const receipt = verified && matches.length === 1 ? matches[0] : null;
    return {role, receipt, state: receipt ? 'verified' : op?.signing_started ? (uncertain ? 'uncertain' : failed ? 'failed' : working ? 'active' : 'waiting') : 'waiting'};
  });
  const assembled = verified && signers.every(s => s.receipt);
  const chainReceipt = result.receipt;
  const included = assembled && !!chainReceipt?.blockHash && /^0x[\da-f]{64}$/i.test(chainReceipt.blockHash) && !/^0x0{64}$/i.test(chainReceipt.blockHash) && !!chainReceipt.blockNumber && !!op.transaction_hash && chainReceipt.transactionHash === op.transaction_hash;
  const confirmed = included && chainReceipt.status === '0x1';
  const reverted = included && chainReceipt.status === '0x0';
  const broadcast = result.broadcast_accepted === true || included;
  let signature = assembled ? result.signature_hex : null;
  // Older journal entries keep the final signature in each verified receipt.
  if (assembled && !signature && Array.isArray(signers[0].receipt.signature)) {
    const bytes = signers[0].receipt.signature;
    if (bytes.length && bytes.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) signature = '0x' + bytes.map(n => n.toString(16).padStart(2, '0')).join('');
  }
  return {transfer, working, uncertain, failed, signers, assembled, included, confirmed, reverted, broadcast, signature,
    assembly: assembled ? 'verified' : uncertain ? 'uncertain' : 'waiting',
    destination: confirmed ? 'verified' : reverted ? 'failed' : uncertain ? 'uncertain' : working && assembled ? 'active' : 'waiting'};
}
