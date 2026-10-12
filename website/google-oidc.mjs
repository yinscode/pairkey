/** Google Identity Services supplies ID tokens. These browser checks are only
 * for selecting an identity and rejecting obvious mismatches; the two signers
 * independently verify the signed token against their pinned Google JWKS. */
export function readGoogleClaims(token, audience, {subject, nonce, issuedAfter} = {}) {
  if (typeof token !== 'string' || token.length > 16 * 1024) throw new Error('Google returned an invalid ID token.');
  let claims;
  try {
    const payload = token.split('.')[1];
    if (!payload || !/^[A-Za-z0-9_-]+$/.test(payload)) throw new Error();
    const base64 = payload.replaceAll('-', '+').replaceAll('_', '/');
    claims = JSON.parse(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')));
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw new Error();
  } catch { throw new Error('Google returned an unreadable ID token.'); }
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== 'https://accounts.google.com' || claims.aud !== audience ||
      typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 256 ||
      !Number.isInteger(claims.iat) || claims.iat > now || issuedAfter !== undefined && claims.iat < issuedAfter ||
      !Number.isInteger(claims.exp) || claims.exp <= now ||
      subject !== undefined && claims.sub !== subject || nonce !== undefined && claims.nonce !== nonce) {
    throw new Error('Google returned an ID token for a different account, client, or request.');
  }
  return {issuer: claims.iss, audience: claims.aud, subject: claims.sub};
}

let loading;
export async function loadGoogleIdentity() {
  if (globalThis.google?.accounts?.id) return globalThis.google.accounts.id;
  loading ??= new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.onload = () => globalThis.google?.accounts?.id ? resolve(globalThis.google.accounts.id) : reject(new Error('Google Sign-In did not initialize.'));
    script.onerror = () => reject(new Error('Google Sign-In could not load. Check browser blockers and retry.'));
    document.head.append(script);
  }).catch(error => { loading = undefined; throw error; });
  return loading;
}

export async function showGoogleButton(container, {audience, nonce, onCredential}) {
  const identity = await loadGoogleIdentity();
  // GIS resets its configuration on initialize. The first button selects the
  // subject; the second requests a new token with the PairKey binding nonce.
  identity.initialize({client_id: audience, callback: response => onCredential(response?.credential),
    ...(nonce ? {nonce} : {}), auto_select: false, ux_mode: 'popup'});
  container.replaceChildren();
  identity.renderButton(container, {type: 'standard', theme: 'outline', size: 'large',
    text: 'continue_with', shape: 'rectangular', width: 260});
}
