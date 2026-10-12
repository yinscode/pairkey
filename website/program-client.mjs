/** Small hosted-v2 entry point for the supplied Solana controller example.
 * Policy edits remain explicit wallet transactions. Signing preserves a public
 * recovery record before prompting the wallet or committing an allowance.
 */
import {PairKey} from './hosted-v2.mjs';
import {HostedSession} from './hosted-session.mjs';
import {check, same, namespaceDigest} from './approval-codec.mjs';

export class ProgramClient {
  constructor({web3, wallet, programId, source, sourceProvider, policyAdapter, mode = 'Onchain', policyScope = 'namespace', endpoint, deployment,
    storage = globalThis.sessionStorage, storageKey, onProgress = () => {},
    onStage = () => {}, verifyTranscript, client} = {}) {
    check(programId || source || sourceProvider, 'A program ID, Program source, or sourceProvider is required');
    check(mode === 'Onchain' || mode === 'Offchain', 'Approval mode must be Onchain or Offchain');
    check(storage?.getItem && storage?.setItem, 'Provide persistent browser storage for job recovery');
    check(wallet?.connect && wallet?.signMessage, 'A Solana wallet with message signing is required');
    this.wallet = wallet;
    this.programId = programId;
    this.source = source;
    this.sourceProvider = sourceProvider;
    this.policyAdapter = policyAdapter;
    this.mode = mode;
    check(policyScope === 'shared' || policyScope === 'namespace', 'Policy scope must be shared or namespace');
    this.policyScope = policyScope;
    this.client = client ?? new PairKey({web3, endpoint, deployment, onProgress});
    this.verifyTranscript = verifyTranscript;
    this.storage = storage;
    const sourceKey = programId ?? 'custom';
    this.storageKey = storageKey ?? `pairkey-v2-program:${sourceKey}`;
    this.session = new HostedSession(this.client, {storage, storageKey: this.storageKey, onStage,
      commitProgram: policyAdapter?.commit ? (namespace, connectedWallet, prepared) => policyAdapter.commit({namespace, wallet: connectedWallet, prepared, client: this.client}) : undefined});
  }

  async connect({namespace, namespaceId} = {}) {
    let source = this.source;
    if (this.sourceProvider) source = await this.sourceProvider({programId: this.programId, wallet: this.wallet, mode: this.mode, policyScope: this.policyScope, namespace, namespaceId, client: this.client});
    const identity = source ? {Program: source.Program ?? source} : undefined;
    const connected = await this.session.connect(this.wallet, {program: identity ? undefined : this.programId, identity, mode: this.mode, namespace, namespaceId, policyScope: this.policyScope});
    this.namespaceScope = this.policyScope === 'namespace' && connected.registration?.namespace
      ? [...await namespaceDigest(connected.registration.namespace)] : undefined;
    return connected;
  }

  async policy() {
    check(this.session.namespace, 'Connect the program first');
    if (this.policyAdapter?.read) return this.policyAdapter.read({namespace: this.session.namespace, wallet: this.wallet, client: this.client});
    return this.client.programPolicy(this.programId, this.wallet.publicKey, this.namespaceScope);
  }

  /** Explicit owner transaction. Call for setup or a deliberate rules edit. */
  async setPolicy({chain, pathPrefix, maxPayloadBytes = 1232,
    remainingApprovals = 0, enabled = true} = {}) {
    check(this.session.namespace, 'Connect the program first');
    check(chain && Array.isArray(pathPrefix), 'Choose a destination chain and path prefix');
    if (this.policyAdapter?.set) {
      const result = await this.policyAdapter.set({namespace: this.session.namespace, wallet: this.wallet, client: this.client,
        policy: {chain, pathPrefix, maxPayloadBytes, remainingApprovals, enabled, requireCommit: this.mode === 'Onchain'}});
      this.session.key = this.session.selection = this.session.result = undefined;
      return result;
    }
    const current = await this.policy();
    const revision = (current?.revision ?? 0) + 1;
    const signature = await this.client.setProgramPolicy(this.wallet, {
      program: this.programId,
      owner: this.wallet.publicKey.toBase58(),
      revision, enabled, chain, path_prefix: pathPrefix,
      max_payload_bytes: maxPayloadBytes,
      require_commit: this.mode === 'Onchain',
      remaining_approvals: remainingApprovals,
      ...(this.namespaceScope ? {namespace_scope: this.namespaceScope} : {}),
    });
    // A policy edit can invalidate an old selection. Make callers reload the key.
    this.session.key = this.session.selection = this.session.result = undefined;
    return {transactionSignature: signature, revision};
  }

  async deriveKey({chain, path = [0]} = {}) {
    check(chain, 'Choose a destination chain');
    return this.session.loadKey(chain, path);
  }

  async finish(result, saved) {
    // This is the hosted service's signature check, in addition to the
    // browser SDK's request/context checks. It is not independent receipt
    // verification; applications needing that must supply verifyTranscript.
    const checked = await this.client.verify(result);
    check(checked?.valid === true, 'Hosted signature verification failed');
    const transcript = {
      request: saved.prepared.signing_request,
      approval: saved.prepared.request,
      key: saved.key,
      result,
      identities: saved.deployment.signer_identities,
    };
    let independent = false;
    if (this.verifyTranscript) {
      check(await this.verifyTranscript(transcript) === true, 'Independent transcript verification failed');
      independent = true;
    }
    return {
      jobId: saved.job_id,
      publicKeyHex: saved.key.public_key_hex,
      signatureHex: result.signature_hex,
      result,
      transcript,
      verification: {browserContext: true, serviceSignature: true, independentReceipts: independent},
    };
  }

  async signMessage({chain, path = [0], message} = {}) {
    check(this.session.namespace, 'Connect the program first');
    if (!this.session.key || !same(this.session.selection, {chain, path})) {
      await this.deriveKey({chain, path});
    }
    const result = await this.session.sign({chain, path, message});
    const saved = JSON.parse(this.storage.getItem(this.storageKey));
    return this.finish(result, saved);
  }

  async signTransaction({chain, path=[0], transaction}={}) {
    check(['solana','evm','near','sui'].includes(chain), 'Transaction signing supports Solana, EVM, NEAR and Sui');
    check(this.session.namespace?.config?.transaction_signing?.[chain]?.sign === true,
      `This PairKey deployment does not advertise ${chain} transaction signing`);
    if (!this.session.key || !same(this.session.selection, {chain, path})) await this.deriveKey({chain, path});
    const wire=chain==='solana'?{solana:{message:[...(transaction.message?.serialize?.()??transaction.serializeMessage?.()??[])]}}
      :chain==='evm'?(transaction.evm_legacy?transaction:{evm_legacy:{transfer:transaction}})
      :chain==='near'?(transaction.near?transaction:{near:{transaction:[...transaction]}})
      :transaction.sui?transaction:{sui:{transaction:[...transaction]}};
    const result=await this.session.signTransaction({chain,path,transaction:wire});
    const saved=JSON.parse(this.storage.getItem(this.storageKey));
    return this.finish(result,saved);
  }

  /** Public-only recovery. The job ID can identify any saved job for this program. */
  async recover(jobId) {
    const result = await this.session.recover(jobId);
    const raw = this.storage.getItem(jobId ? `${this.storageKey}:${jobId}` : this.storageKey);
    return this.finish(result, JSON.parse(raw));
  }

  /** Broadcast a Solana native Ed25519 verification instruction for a signed
   * Solana message. The owner's wallet pays the transaction fee. This proves
   * the signature on chain; it does not move assets from the derived key. */
  async verifyOnSolana(signed) {
    check(signed?.result?.chain === 'solana' && signed.verification?.serviceSignature === true,
      'A checked Solana message result is required');
    const decode = (value, size) => {
      check(typeof value === 'string' && value.startsWith('0x') && value.length === size * 2 + 2
        && /^0x[0-9a-f]+$/i.test(value), 'Invalid hex signing output');
      return Uint8Array.from(value.slice(2).match(/../g).map(byte => parseInt(byte, 16)));
    };
    const ix = this.client.web3.Ed25519Program.createInstructionWithPublicKey({
      publicKey: decode(signed.publicKeyHex, 32),
      message: new TextEncoder().encode(signed.result.signed_message),
      signature: decode(signed.signatureHex, 64),
    });
    // Recovery is public, but a fee-paying proof still needs a connected wallet.
    await this.wallet.connect();
    const transactionSignature = await this.client.send(this.wallet, [ix]);
    return {transactionSignature};
  }
}
