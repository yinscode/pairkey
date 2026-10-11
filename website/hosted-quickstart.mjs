import { PairKey } from './hosted-client.mjs?v=wallet-compatibility-2';
const form = document.querySelector('[data-hosted-quickstart]');
if (form) {
  const client = new PairKey({ web3: window.solanaWeb3, endpoint: `${location.origin}/api/v1`, onProgress: ({ message, signature }) => {
    tell(message);
    if (signature) link('View transaction on Solana devnet', signature);
  } });
  const $ = id => form.querySelector(`#${id}`);
  const output = $('hosted-output');
  let wallet, walletAddress, namespace, key, result, approval;
  const tell = text => { output.textContent = text; };
  const linked = new Set();
  const link = (label, signature) => {
    if (linked.has(signature)) return;
    linked.add(signature);
    const a = document.createElement('a'); a.textContent = label;
    a.href = `https://explorer.solana.com/tx/${encodeURIComponent(signature)}?cluster=devnet`;
    a.target = '_blank'; a.rel = 'noopener noreferrer'; $('hosted-links').append(a, document.createElement('br'));
  };
  async function action(button, work) {
    const buttons = [...form.querySelectorAll('button, input, select, textarea')];
    buttons.forEach(b => { b.dataset.wasDisabled = String(b.disabled); b.disabled = true; });
    try { await work(); } catch (e) { tell(`Action stopped: ${e.message || String(e)}`); }
    finally { buttons.forEach(b => { b.disabled = b.dataset.wasDisabled === 'true'; }); }
  }
  $('hosted-connect').addEventListener('click', () => action(null, async () => {
    wallet = window.phantom?.solana || window.solflare || window.solana;
    if (!wallet?.connect || !wallet?.signTransaction) throw new Error('Open this page in a browser with a Solana wallet such as Phantom or Solflare. Select devnet in your wallet.');
    await wallet.connect();
    walletAddress = wallet.publicKey.toBase58();
    key = result = approval = undefined;
    $('hosted-sign').dataset.wasDisabled = 'true';
    $('hosted-verify').dataset.wasDisabled = 'true';
    $('hosted-public-key').textContent = 'Your key will appear here.';
    $('hosted-signature').textContent = 'Your signature will appear here.';
    let options = {};
    if (form.dataset.hostedQuickstart === 'program') {
      if (!$('hosted-program').value.trim()) throw new Error('Enter the program ID you deployed from the owner-gated controller template.');
      options = client.controller($('hosted-program').value.trim(), wallet.publicKey);
    }
    tell('Preparing your namespace with the hosted signers…');
    namespace = await client.onboard(wallet, options);
    if (namespace.transaction) link('Namespace registration on Solana', namespace.transaction);
    tell(`Namespace ready: ${namespace.namespaceAddress}\nAuthority: ${new solanaWeb3.PublicKey(namespace.registration.namespace.derivation_authority)}\nChoose a chain, then load its key.`);
    $('hosted-key').dataset.wasDisabled = 'false';
  }));
  $('hosted-key').addEventListener('click', () => action(null, async () => {
    const index = Number($('hosted-path').value);
    if (!Number.isInteger(index) || index < 0 || index > 4294967295) throw new Error('Path index must be an integer from 0 to 4294967295.');
    tell('Enrolling your derived key with the hosted signers…');
    key = await client.key(namespace, $('hosted-chain').value, [Number($('hosted-path').value)]);
    key.chain = $('hosted-chain').value; key.path = Number($('hosted-path').value);
    result = undefined; $('hosted-verify').dataset.wasDisabled = 'true';
    $('hosted-signature').textContent = 'Your signature will appear here.';
    $('hosted-public-key').textContent = key.public_key_hex;
    tell(`Key ready. ${key.address ? `Public identifier: ${key.address}` : 'Public key shown below.'}\nWrite a message, then approve it on Solana.`);
    $('hosted-sign').dataset.wasDisabled = 'false';
  }));
  $('hosted-sign').addEventListener('click', () => action(null, async () => {
    if (!wallet.publicKey || wallet.publicKey.toBase58() !== walletAddress) throw new Error('Wallet changed. Connect and register again.');
    if (key.chain !== $('hosted-chain').value || key.path !== Number($('hosted-path').value)) throw new Error('Chain or path changed. Load its key first.');
    result = undefined;
    $('hosted-verify').dataset.wasDisabled = 'true';
    $('hosted-signature').textContent = 'Waiting for this request’s signature.';
    approval = await client.prepare(namespace, wallet, { chain: key.chain, path: [key.path], message: $('hosted-message').value });
    sessionStorage.setItem('pairkey-hosted-pending', JSON.stringify(approval));
    sessionStorage.removeItem('pairkey-hosted-job');
    tell('Approve this message in your wallet. Waiting for Solana devnet finality…');
    const tx = await client.approve(namespace, wallet, approval); link('Message approval on Solana', tx);
    tell('Approval finalized. Both signers are checking your authority and signing…');
    const job = await client.submit(approval);
    sessionStorage.setItem('pairkey-hosted-job', job.job_id);
    result = await client.wait(job.job_id);
    $('hosted-signature').textContent = result.signature_hex;
    tell(`Signature ready. Job ${job.job_id}\nNo destination transaction was broadcast.`);
    $('hosted-verify').dataset.wasDisabled = 'false';
  }));
  $('hosted-verify').addEventListener('click', () => action(null, async () => {
    const checked = await client.verify({ ...result, signed_message: $('hosted-message').value });
    tell(checked.valid ? 'Signature verified against the derived public key and exact message.' : 'Signature verification failed.');
  }));
  $('hosted-recover').addEventListener('click', () => action(null, async () => {
    let id = sessionStorage.getItem('pairkey-hosted-job');
    if (!id) {
      const pending = sessionStorage.getItem('pairkey-hosted-pending');
      if (!pending) throw new Error('No submitted job is saved in this browser tab.');
      const submitted = await client.submit(JSON.parse(pending));
      id = submitted.job_id; sessionStorage.setItem('pairkey-hosted-job', id);
    }
    tell(`Recovering existing job ${id}…`); result = await client.wait(id);
    $('hosted-signature').textContent = result.signature_hex; $('hosted-public-key').textContent = result.public_key_hex;
    $('hosted-message').value = result.signed_message;
    tell(`Recovered signature for: ${result.signed_message}`); $('hosted-verify').dataset.wasDisabled = 'false';
  }));
}
