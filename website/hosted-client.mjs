/** PairKey hosted devnet client. Pass @solana/web3.js v1 as `web3`.
 * Wallet signing and program CPI are the only ways to authorize a request.
 */
export class PairKey {
  constructor({ web3, endpoint = 'https://pairkey.com/api/v1', onProgress = () => {} }) {
    this.web3 = web3;
    this.onProgress = onProgress;
    this.endpoint = endpoint.replace(/\/$/, '');
  }
  async request(path, body) {
    const response = await fetch(`${this.endpoint}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-PairKey-Client': '1' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(120000),
    });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || `PairKey returned ${response.status}`);
    return value;
  }
  async rpc(method, params) {
    const value = await this.request('/rpc', { jsonrpc: '2.0', id: 1, method, params });
    if (value.error) throw new Error(value.error.message);
    return value.result;
  }
  instruction(value) {
    const { PublicKey, TransactionInstruction } = this.web3;
    return new TransactionInstruction({ programId: new PublicKey(value.program_id),
      keys: value.accounts.map(a => ({ pubkey: new PublicKey(a.pubkey), isSigner: a.is_signer, isWritable: a.is_writable })),
      data: Uint8Array.from(value.data) });
  }
  /** Adapter for the documented owner-gated controller template only.
   * Other programs supply their own wrapInstruction callback.
   */
  controller(programId, owner) {
    const { PublicKey, TransactionInstruction } = this.web3;
    const program = new PublicKey(programId);
    const authority = PublicKey.findProgramAddressSync([new TextEncoder().encode('controller'), owner.toBytes()], program)[0];
    return { authority, wrapInstruction: ix => {
      if (!ix.keys[0].pubkey.equals(owner) || !ix.keys[1].pubkey.equals(authority)) throw new Error('Controller instruction authority mismatch');
      return new TransactionInstruction({ programId: program, data: ix.data,
        keys: [{ pubkey: owner, isSigner: true, isWritable: true }, { pubkey: authority, isSigner: false, isWritable: false },
          { pubkey: ix.programId, isSigner: false, isWritable: false }, ...ix.keys.slice(2)] });
    } };
  }
  async send(wallet, instructions) {
    const latest = await this.rpc('getLatestBlockhash', []);
    const tx = new this.web3.Transaction({ feePayer: wallet.publicKey, recentBlockhash: latest.value.blockhash });
    tx.add(this.web3.ComputeBudgetProgram.setComputeUnitLimit({ units: 1400000 }),
      this.web3.ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1000 }), ...instructions);
    const approvedBytes = tx.serializeMessage();
    this.onProgress({ stage: 'wallet', message: 'Approve the transaction in your wallet.' });
    const signed = await wallet.signTransaction(tx);
    // Snapshot bytes before calling the wallet: providers can mutate tx in place.
    validateWalletMessage(this.web3, approvedBytes, signed.serializeMessage());
    const serialized = toBase64(signed.serialize());
    // Know the transaction ID before submitting: an RPC response can be lost.
    const signature = base58(signed.signature);
    this.onProgress({ stage: 'submitting', signature, message: 'Wallet signed. Submitting to Solana devnet…' });
    let submissionError;
    try {
      const returned = await this.rpc('sendTransaction', [serialized]);
      if (returned !== signature) throw new Error('RPC returned a different transaction ID');
    } catch (e) { submissionError = e.message; }
    await this.finalized(signature, { serialized, lastValidBlockHeight: latest.value.lastValidBlockHeight, submissionError });
    return signature;
  }
  async finalized(signature, { serialized, lastValidBlockHeight, submissionError } = {}) {
    const deadline = Date.now() + 150000;
    let nextBroadcast = Date.now() + 10000;
    while (Date.now() < deadline) {
      let status;
      try {
        const result = await this.rpc('getSignatureStatuses', [[signature]]);
        status = result.value[0];
      } catch (e) {
        this.onProgress({ stage: 'confirming', signature, message: 'Confirmation RPC unavailable. Checking the same transaction again…' });
        await pause(2500);
        continue;
      }
      if (status?.err) throw new Error(`Solana transaction failed: ${signature}: ${JSON.stringify(status.err)}`);
      if (status?.confirmationStatus === 'finalized') {
        this.onProgress({ stage: 'finalized', signature, message: 'Transaction finalized on Solana devnet.' });
        return;
      }
      this.onProgress({ stage: 'confirming', signature, message: status
        ? 'Transaction landed. Waiting for Solana devnet finality…'
        : `Waiting for Solana devnet to accept the transaction.${submissionError ? ` Submission response: ${submissionError}` : ''}` });
      if (!status && Number.isSafeInteger(lastValidBlockHeight)) {
        // Finalized height plus a fresh history lookup prevents premature expiry.
        let height;
        try { height = await this.rpc('getBlockHeight', []); } catch {}
        if (height > lastValidBlockHeight) {
          const checked = await this.rpc('getSignatureStatuses', [[signature]]);
          if (!checked.value[0]) throw new Error(`Transaction expired without confirmation: ${signature}. It is no longer valid for submission. For registration, click Connect wallet & register to check your namespace and try again.`);
          continue;
        }
      }
      if (!status && serialized && Date.now() >= nextBroadcast) {
        // Resend identical signed bytes only; never ask for another signature automatically.
        try { await this.rpc('sendTransaction', [serialized]); } catch (e) { submissionError = e.message; }
        nextBroadcast = Date.now() + 10000;
      }
      await pause(2500);
    }
    throw new Error(`Finality is not confirmed. Check transaction ${signature} before retrying; it may have landed.${submissionError ? ` Submission response: ${submissionError}` : ''}`);
  }
  async onboard(wallet, { authority = wallet.publicKey, wrapInstruction, namespaceId = Array(32).fill(0) } = {}) {
    const config = await this.request('/config');
    const proposal = await this.request('/namespaces', { authority: authority.toBase58(), payer: wallet.publicKey.toBase58(), namespace_id: namespaceId });
    const ns = proposal.proposal.registration.namespace;
    if (!bytesEqual(ns.derivation_authority, authority.toBytes()) || !bytesEqual(ns.namespace_id, namespaceId) ||
        !bytesEqual(ns.registry, new this.web3.PublicKey(config.registry).toBytes()) || !bytesEqual(ns.network, new this.web3.PublicKey(config.genesis_hash).toBytes()) || !bytesEqual(ns.enclave_set, config.enclave_set)) {
      throw new Error('Namespace proposal does not match the requested authority and deployment');
    }
    const instructions = proposal.instructions.map(i => this.instruction(i));
    // Registration carries two identity signatures; the gateway verifies them on-chain.
    if (instructions.length !== 3 || !instructions[2].programId.equals(new this.web3.PublicKey(config.registry)) ||
        !instructions[2].keys[0].pubkey.equals(wallet.publicKey) || !instructions[2].keys[1].pubkey.equals(authority)) throw new Error('Registration instruction mismatch');
    const exists = await this.rpc('getAccountInfo', [proposal.namespace_address]);
    if (!exists.value || exists.value.owner === this.web3.SystemProgram.programId.toBase58()) {
      if (wrapInstruction) instructions[2] = await wrapInstruction(instructions[2]);
      proposal.transaction = await this.send(wallet, instructions);
    }
    return { registration: proposal.proposal.registration, namespaceAddress: proposal.namespace_address, wrapInstruction, transaction: proposal.transaction };
  }
  async key(namespace, chain = 'solana', path = [0]) {
    return this.request('/keys', { registration: namespace.registration, chain, path });
  }
  async prepare(namespace, wallet, { chain = 'solana', path = [0], message, requestId = [...crypto.getRandomValues(new Uint8Array(32))] }) {
    return this.request('/approvals', { key: { registration: namespace.registration, chain, path }, payer: wallet.publicKey.toBase58(), request_id: requestId, message });
  }
  async approve(namespace, wallet, approval) {
    const instructions = approval.instructions.map(i => this.instruction(i));
    if (instructions.length !== 1 || !instructions[0].programId.equals(new this.web3.PublicKey(namespace.registration.namespace.registry)) ||
        !instructions[0].keys[0].pubkey.equals(wallet.publicKey) || !bytesEqual(instructions[0].keys[1].pubkey.toBytes(), namespace.registration.namespace.derivation_authority)) throw new Error('Approval instruction authority mismatch');
    if (namespace.wrapInstruction) instructions[0] = await namespace.wrapInstruction(instructions[0]);
    return this.send(wallet, instructions);
  }
  async submit(approval) { return this.request('/jobs', approval.signing_request); }
  async wait(jobId) {
    const deadline = Date.now() + 240000;
    while (Date.now() < deadline) {
      const job = await this.request(`/jobs/${encodeURIComponent(jobId)}`);
      if (job.status === 'complete') return job.result;
      if (job.status === 'failed') throw new Error(`${job.error} Job: ${jobId}. Do not create a fresh signing request automatically.`);
      await pause(2500);
    }
    throw new Error(`Still waiting for job ${jobId}. Poll this same job to recover the result.`);
  }
  async verify(result) {
    return this.request('/verify', { chain: result.chain, public_key_hex: result.public_key_hex, signed_message: result.signed_message, signature_hex: result.signature_hex });
  }
}
export const bytesEqual = (a, b) => a.length === b.length && Array.from(a).every((v, i) => v === b[i]);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const toBase64 = bytes => btoa(String.fromCharCode(...bytes));

// Transaction signatures are raw 64-byte Ed25519 signatures in web3.js.
const base58 = bytes => {
  if (!bytes || bytes.length !== 64) throw new Error('Wallet did not return a transaction signature');
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n, result = '';
  for (const byte of bytes) n = n * 256n + BigInt(byte);
  while (n) { result = alphabet[Number(n % 58n)] + result; n /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; result = '1' + result; }
  return result;
};

/** Compare the transaction's meaning, not its account-table serialization order.
 * Only a prefix ComputeUnitPrice may change; cap its total fee at 10,000 lamports.
 * Payer, blockhash, privileges, instruction order, operands and data stay exact.
 */
export function validateWalletMessage(web3, beforeBytes, afterBytes) {
  if (bytesEqual(beforeBytes, afterBytes)) return;
  const normalize = bytes => {
    const message = web3.Message.from(bytes);
    const key = index => {
      if (!message.accountKeys[index]) throw new Error('Wallet returned an invalid account index');
      return message.accountKeys[index].toBase58();
    };
    const accounts = message.accountKeys.map((_, index) => [key(index), message.isAccountSigner(index), message.isAccountWritable(index)]);
    if (new Set(accounts.map(a => a[0])).size !== accounts.length) throw new Error('Wallet returned duplicate accounts');
    let price, limit, prefix = true;
    const instructions = [];
    for (const ix of message.compiledInstructions) {
      const program = key(ix.programIdIndex);
      const data = Uint8Array.from(ix.data);
      const budget = program === web3.ComputeBudgetProgram.programId.toBase58();
      if (!budget) prefix = false;
      if (budget && data[0] === 3) {
        if (!prefix || data.length !== 9 || ix.accountKeyIndexes.length || price !== undefined) throw new Error('Wallet changed the transaction: invalid priority-fee instruction');
        price = new DataView(data.buffer).getBigUint64(1, true);
        continue;
      }
      if (budget && data[0] === 2 && data.length === 5) limit = new DataView(data.buffer).getUint32(1, true);
      instructions.push([program, ix.accountKeyIndexes.map(key), Array.from(data)]);
    }
    if (price === undefined || !limit || limit > 1400000 || (price * BigInt(limit) + 999999n) / 1000000n > 10000n) {
      throw new Error('Wallet changed the transaction: priority fee must stay at or below 0.00001 SOL');
    }
    return { payer: key(0), blockhash: message.recentBlockhash,
      accounts: accounts.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0), instructions };
  };
  const before = normalize(beforeBytes), after = normalize(afterBytes);
  for (const field of ['payer', 'blockhash', 'accounts', 'instructions']) {
    if (JSON.stringify(before[field]) !== JSON.stringify(after[field])) throw new Error(`Wallet changed the transaction: ${field} differ. Nothing was submitted.`);
  }
}
