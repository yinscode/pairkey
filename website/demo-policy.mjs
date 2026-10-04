// Educational policy model only. No cryptography, network, or production authority.
export const RECIPIENTS = {
  treasury: '0x1111111111111111111111111111111111111111',
  alternate: '0x2222222222222222222222222222222222222222',
};
export function toWei(value) {
  if (!/^(0|[1-9]\d{0,6})(\.\d{1,18})?$/.test(value)) return null;
  const [whole, fraction = ''] = value.split('.');
  const amount = BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, '0'));
  return amount > 0n ? amount : null;
}
export function evaluate(session, request, now) {
  const amount = toWei(request.amount);
  const checks = [
    { label: 'Session is active', pass: Boolean(session && !session.revoked) },
    { label: 'Permission has not expired', pass: Boolean(session && now < session.expiresAt) },
    { label: 'Recipient matches the grant', pass: Boolean(session && request.recipient === session.recipient) },
    { label: 'Amount is within the per-transfer limit', pass: Boolean(session && amount !== null && amount <= session.limit) },
  ];
  return { checks, allowed: checks.every(check => check.pass) };
}
