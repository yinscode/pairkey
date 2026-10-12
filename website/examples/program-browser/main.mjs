// The site example imports the same module exported by the local
// @pairkey/sdk/program export. Installed apps can import that package path.
import {ProgramClient} from '../../program-client.mjs';

const $ = id => document.getElementById(id);
const endpoint = 'https://pairkey.com/api/v2';
let program, signed, connected = false, keyReady = false, working = false;
function status(message) { $('status').textContent = message; }
function updateButtons() {
  $('example').disabled = $('connect').disabled = $('recover').disabled = working;
  $('policy').disabled = $('key').disabled = working || !connected;
  $('sign').disabled = working || !keyReady;
  $('proof').disabled = $('transcript').disabled = working || !signed;
}
function busy(work) {
  return async () => {
    if (working) return;
    working = true; updateButtons();
    try { await work(); }
    catch (error) { status(`Stopped: ${error.message || error}`); }
    finally { working = false; updateButtons(); }
  };
}
function makeClient() {
  const wallet = window.phantom?.solana || window.solflare || window.solana;
  if (!wallet) throw new Error('Install a Solana wallet with signMessage and signTransaction.');
  const programId = $('program').value.trim();
  if (!programId) throw new Error('Enter a deployed v2 example controller program ID.');
  return new ProgramClient({
    web3: window.solanaWeb3, wallet, programId, mode: $('mode').value,
    endpoint, storage: sessionStorage,
    onProgress: event => { if (event.message) status(event.message); },
    onStage: stage => status(`PairKey stage: ${stage}`),
  });
}

$('example').addEventListener('click', busy(async () => {
  const response = await fetch(`${endpoint}/config`);
  if (!response.ok) throw new Error(`Configuration request failed: ${response.status}`);
  const config = await response.json();
  if (!config.example_program) throw new Error('This deployment has no example program.');
  $('program').value = config.example_program;
  $('mode').value = 'Onchain';
  status('Hosted example selected. Connect your wallet, then create your own policy.');
}));

$('connect').addEventListener('click', busy(async () => {
  connected = keyReady = false; signed = undefined;
  program = makeClient();
  const namespace = await program.connect();
  connected = true;
  status(`Connected. Program authority: ${new window.solanaWeb3.PublicKey(namespace.registration.namespace.derivation_authority).toBase58()}`);
}));

$('policy').addEventListener('click', busy(async () => {
  if (!program) throw new Error('Connect first.');
  const result = await program.setPolicy({chain:'solana',pathPrefix:[0],maxPayloadBytes:1232,remainingApprovals:3});
  keyReady = false;
  status(`Policy revision ${result.revision} finalized. Solana transaction: ${result.transactionSignature}`);
}));

$('key').addEventListener('click', busy(async () => {
  if (!program) throw new Error('Connect first.');
  const key = await program.deriveKey({chain:'solana',path:[0]});
  keyReady = true;
  status(`Derived public key: ${key.public_key_hex}`);
}));

$('sign').addEventListener('click', busy(async () => {
  if (!program) throw new Error('Connect first.');
  signed = await program.signMessage({chain:'solana',path:[0],message:$('message').value});
  $('job').value = signed.jobId;
  status(`Job ${signed.jobId}\nPublic key: ${signed.publicKeyHex}\nSignature: ${signed.signatureHex}\nIndependent receipt verification: ${signed.verification.independentReceipts}`);
}));

$('recover').addEventListener('click', busy(async () => {
  program ??= makeClient();
  signed = await program.recover($('job').value.trim() || undefined);
  $('job').value = signed.jobId;
  status(`Recovered job ${signed.jobId}\nSignature: ${signed.signatureHex}\nNo new wallet approval or signing attempt was made.`);
}));

$('proof').addEventListener('click', busy(async () => {
  if (!signed) throw new Error('Sign or recover a Solana message first.');
  const {transactionSignature} = await program.verifyOnSolana(signed);
  status(`Native Ed25519 verification finalized on Solana devnet: ${transactionSignature}\nThis transaction did not move assets.`);
}));
$('transcript').addEventListener('click', () => {
  if (!signed) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(signed.transcript, null, 2)], {type:'application/json'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = `pairkey-${signed.jobId}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
updateButtons();
