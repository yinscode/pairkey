import { evaluate, toWei, RECIPIENTS } from './demo-policy.mjs';
const el = id => document.getElementById(id);
const rules = el('demo-rules');
if (rules) {
  let session = null;
  let sequence = 0;
  let busy = false;
  let receiptCount = 0;
  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
  function announce(text) { el('demo-announcement').textContent = text; }
  function paintSigner(role, title, decision) {
    const panel = el(`demo-signer-${role}`);
    panel.dataset.state = decision ? (decision.allowed ? 'approved' : 'refused') : 'waiting';
    panel.querySelector('h4').textContent = title;
    const list = panel.querySelector('ul');
    list.replaceChildren();
    for (const check of decision?.checks ?? []) {
      const item = document.createElement('li');
      item.textContent = `${check.pass ? '✓' : '×'} ${check.label}`;
      list.append(item);
    }
  }
  function ready() {
    for (const role of ['a', 'b']) paintSigner(role, 'Ready to check');
  }
  function renderSession() {
    const remaining = session ? Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000)) : 0;
    const state = !session ? 'Not granted' : session.revoked ? 'Revoked' : remaining === 0 ? 'Expired' : 'Active';
    el('demo-session-state').textContent = state;
    el('demo-session-state').dataset.state = state.toLowerCase();
    el('demo-session-detail').textContent = session
      ? `${session.limitText} ETH / transfer · ${session.recipient === RECIPIENTS.treasury ? 'Treasury' : 'Operations'} · ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')} remaining`
      : 'Publish your first simulated grant to begin.';
    el('demo-revoke').disabled = !session || session.revoked;
    el('demo-expire').disabled = !session || session.revoked || remaining === 0;
    el('demo-submit').disabled = !session || busy;
    el('demo-grant').disabled = busy;
  }
  rules.addEventListener('submit', event => {
    event.preventDefault();
    if (busy) return;
    const limitText = el('demo-limit').value.trim();
    const limit = toWei(limitText);
    if (limit === null) { el('demo-rule-error').textContent = 'Enter a positive ETH amount with up to 18 decimal places.'; return; }
    el('demo-rule-error').textContent = '';
    session = { limit, limitText, recipient: RECIPIENTS[el('demo-recipient-rule').value], expiresAt: Date.now() + Number(el('demo-duration').value) * 60000, revoked: false };
    sequence++;
    ready(); renderSession();
    el('demo-result-title').textContent = 'Permission granted';
    el('demo-result-detail').textContent = 'The simulated Solana program has authorized this session. Request a transfer to see both signers check it.';
    el('demo-result').dataset.state = 'idle';
    announce('Session granted. You can now request a transfer.');
  });
  el('demo-request').addEventListener('submit', async event => {
    event.preventDefault();
    if (!session || busy) return;
    const request = { amount: el('demo-amount').value.trim(), recipient: RECIPIENTS[el('demo-recipient').value] };
    const current = ++sequence;
    busy = true; renderSession();
    el('demo-result-title').textContent = 'Checking program authority…';
    el('demo-result-detail').textContent = 'Two separate signers evaluate the same request and current session.';
    el('demo-result').dataset.state = 'idle';
    for (const role of ['a', 'b']) paintSigner(role, 'Checking permissions…');
    announce('Both simulated signers are checking authorization.');
    for (const role of ['a', 'b']) {
      await wait(450);
      if (current !== sequence) return;
      const decision = evaluate(session, request, Date.now());
      paintSigner(role, decision.allowed ? 'Authorized' : 'Refused', decision);
    }
    await wait(300);
    if (current !== sequence) return;
    // Recheck at issuance so revocation/expiry during the animation refuses output.
    const final = evaluate(session, request, Date.now());
    for (const role of ['a', 'b']) paintSigner(role, final.allowed ? 'Authorized' : 'Refused', final);
    el('demo-result').dataset.state = final.allowed ? 'approved' : 'refused';
    if (final.allowed) {
      receiptCount++;
      el('demo-result-title').textContent = 'Simulated payment accepted';
      el('demo-result-detail').textContent = `${request.amount} ETH → ${request.recipient}. Both signers authorize; the walkthrough illustrates a combined signature and destination submission. No funds move.`;
      el('demo-receipt').hidden = false;
      el('demo-receipt').textContent = `Illustrative receipt #${receiptCount}: ${request.amount} ETH → ${request.recipient}. This is not a transaction hash or cryptographic signature.`;
      announce('Both signers authorized the request. Simulated payment accepted.');
    } else {
      const failed = final.checks.filter(check => !check.pass).map(check => check.label).join('; ');
      el('demo-result-title').textContent = 'Signing refused';
      el('demo-result-detail').textContent = `Failed checks: ${failed}. No simulated signature is issued for this request.`;
      announce(`Signing refused. ${failed}.`);
    }
    busy = false; renderSession();
  });
  el('demo-revoke').addEventListener('click', () => {
    if (!session) return;
    session.revoked = true; renderSession();
    announce('Session revoked. Both signers observe this immediately in the simulation. Future requests will be refused.');
    if (!busy) {
      el('demo-result-title').textContent = 'Permission revoked';
      el('demo-result-detail').textContent = 'Request another transfer to see both signers refuse. Previously issued signatures remain valid; the last illustrative receipt stays below.';
      el('demo-result').dataset.state = 'idle';
    }
  });
  el('demo-expire').addEventListener('click', () => {
    if (!session) return;
    session.expiresAt = Date.now(); renderSession();
    announce('Session expired. The next request will be refused.');
  });
  el('demo-too-much').addEventListener('click', () => {
    if (!session) return;
    const amount = session.limit + 10n ** 18n;
    const whole = amount / 10n ** 18n;
    const fraction = String(amount % 10n ** 18n).padStart(18, '0').replace(/0+$/, '');
    el('demo-amount').value = String(whole) + (fraction ? `.${fraction}` : '');
    announce('Request amount set above the active grant limit. Select Request transfer to test it.');
  });
  el('demo-wrong-recipient').addEventListener('click', () => {
    el('demo-recipient').value = session?.recipient === RECIPIENTS.alternate ? 'treasury' : 'alternate';
    announce('Request recipient changed. Select Request transfer to test it.');
  });
  el('demo-reset').addEventListener('click', () => {
    sequence++; session = null; busy = false; receiptCount = 0;
    rules.reset(); el('demo-request').reset(); ready(); renderSession();
    el('demo-rule-error').textContent = ''; el('demo-receipt').hidden = true;
    el('demo-result').dataset.state = 'idle';
    el('demo-result-title').textContent = 'Your program sets the rules';
    el('demo-result-detail').textContent = 'Grant a session, then request a transfer. Change the amount, change the recipient, or revoke permission to see the difference.';
    announce('Demo reset. Grant a session to begin.');
  });
  ready(); renderSession(); setInterval(renderSession, 1000);
}
