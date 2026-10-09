/** Shared quickstart/demo lifecycle. Recovery stores public metadata only and
 * never asks for a new signature, calls submit, or consumes another allowance. */
import {same, check} from './approval-codec.mjs';
export class HostedSession {
  constructor(client, {storage = globalThis.sessionStorage, storageKey = 'pairkey-v2-recovery', onStage = () => {}} = {}) {
    this.client = client; this.storage = storage; this.storageKey = storageKey; this.onStage = onStage;
  }
  reset() { this.namespace = this.wallet = this.key = this.selection = this.result = undefined; }
  async connect(wallet, {program, mode = 'Offchain'} = {}) {
    this.reset();
    check(wallet?.connect && wallet?.signMessage, 'Connect a Solana wallet with message signing, such as Phantom or Solflare.');
    await wallet.connect();
    const source = program ? await this.client.programSource(program, wallet.publicKey, mode) : undefined;
    const namespace = await this.client.onboard(wallet, source ? {identity: source.identity} : {});
    this.wallet = wallet; this.namespace = namespace; this.result = undefined;
    this.onStage('ready', {namespace});
    return namespace;
  }
  async loadKey(chain, path) {
    check(this.namespace, 'Connect your authority first.');
    this.client.checkWallet(this.namespace, this.wallet);
    this.key = this.selection = this.result = undefined;
    const key = await this.client.key(this.namespace, chain, path);
    this.key = structuredClone(key); this.selection = {chain, path: [...path]};
    return key;
  }
  async sign({chain, path, message}) {
    check(this.key && same(this.selection, {chain, path}), 'Chain or path changed. Load its key first.');
    this.result = undefined;
    this.onStage('preparing');
    const prepared = await this.client.prepare(this.namespace, this.wallet, {chain, path, message});
    const recovery = await this.client.recovery(prepared);
    // Stop before the wallet prompt if safe recovery metadata cannot be saved.
    this.storage.setItem(this.storageKey, JSON.stringify(recovery));
    this.onStage('authorizing', {prepared});
    const submission = await this.client.approve(this.namespace, this.wallet, prepared);
    if (this.namespace.identity.Program?.mode === 'Onchain') {
      this.onStage('committing', {prepared});
      await this.client.commitProgram(this.namespace, this.wallet, prepared);
    }
    this.onStage('submitting', {jobId: recovery.job_id, prepared});
    const job = await this.client.submit(submission);
    this.onStage('signing', {jobId: job.job_id, prepared});
    this.result = await this.client.wait(job.job_id, {prepared, key: this.key});
    this.onStage('complete', {result: this.result, jobId: job.job_id, prepared});
    return this.result;
  }
  async recover() {
    const raw = this.storage.getItem(this.storageKey);
    check(raw, 'No v2 signing job is saved in this browser tab.');
    const saved = JSON.parse(raw);
    check(saved.version === 2 && saved.endpoint === this.client.endpoint && saved.prepared && saved.key && saved.deployment, 'Recovery belongs to a different API or format.');
    check(await this.client.jobId(saved.prepared.request) === saved.job_id, 'Saved job ID does not match its request.');
    if (!this.client.deployment) this.client.deployment = structuredClone(saved.deployment);
    for (const field of ['registry', 'genesis_hash', 'enclave_set', 'signer_identities']) check(same(this.client.deployment[field], saved.deployment[field]), 'Recovery deployment changed.');
    await this.client.config();
    this.onStage('recovering', {jobId: saved.job_id});
    await this.client.recover(saved.job_id);
    this.result = await this.client.wait(saved.job_id, {prepared: saved.prepared, key: saved.key});
    this.onStage('complete', {result: this.result, jobId: saved.job_id, prepared: saved.prepared});
    return this.result;
  }
}
