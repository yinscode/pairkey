import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, toWei, RECIPIENTS } from './demo-policy.mjs';
const grant = { limit: toWei('0.01'), recipient: RECIPIENTS.treasury, expiresAt: 1000, revoked: false };
const request = { amount: '0.005', recipient: RECIPIENTS.treasury };
test('an in-scope transfer and its exact cap are authorized', () => {
  assert.equal(evaluate(grant, request, 999).allowed, true);
  assert.equal(evaluate(grant, {...request, amount: '0.01'}, 999).allowed, true);
});
test('one wei above the cap is refused without floating-point rounding', () => {
  assert.equal(toWei('0.000000000000000001'), 1n);
  assert.equal(evaluate(grant, {...request, amount: '0.010000000000000001'}, 999).allowed, false);
});
test('negative, zero, exponential, malformed, and overprecise amounts are invalid', () => {
  for (const amount of ['-1','0','0.000','1e-3','NaN','Infinity','01','.5','1.','0.0000000000000000001','<script>']) {
    assert.equal(toWei(amount), null, amount);
    assert.equal(evaluate(grant, {...request, amount}, 999).allowed, false, amount);
  }
});
test('recipient substitution is refused', () => {
  assert.equal(evaluate(grant, {...request, recipient: RECIPIENTS.alternate}, 999).allowed, false);
});
test('missing, revoked, and expired authority are refused, including exact expiry', () => {
  assert.equal(evaluate(null, request, 999).allowed, false);
  assert.equal(evaluate({...grant, revoked:true}, request, 999).allowed, false);
  assert.equal(evaluate(grant, request, 1000).allowed, false);
  assert.equal(evaluate(grant, request, 1001).allowed, false);
});
test('a final authorization check reflects revocation after an earlier successful check', () => {
  const session={...grant};
  assert.equal(evaluate(session,request,990).allowed,true);
  session.revoked=true;
  assert.equal(evaluate(session,request,991).allowed,false);
});
test('per-operation cap permits multiple separate in-scope requests', () => {
  const session=Object.freeze({...grant});
  for (let i=0;i<4;i++) assert.equal(evaluate(session, request, 999).allowed,true);
});
