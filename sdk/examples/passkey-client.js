// Browser helper for a controller-enrolled ES256 public key. Call from its pinned HTTPS origin.
// Get the 32-byte challenge from SDK policy::session_challenge or policy::access_challenge.
// The controller enrolls the corresponding SEC1 public key, RP ID and origin on Solana.
export async function passkeyProof({ challenge, rpId, credentialId }) {
  if (!Array.isArray(challenge) || challenge.length !== 32) {
    throw new Error("Expected a 32-byte operation challenge");
  }
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(challenge),
      rpId,
      allowCredentials: [{ type: "public-key", id: new Uint8Array(credentialId) }],
      userVerification: "required",
      timeout: 60000,
    },
  });
  if (!assertion || assertion.type !== "public-key") {
    throw new Error("Missing passkey assertion");
  }
  return {
    Passkey: {
      authenticator_data: Array.from(new Uint8Array(assertion.response.authenticatorData)),
      client_data_json: Array.from(new Uint8Array(assertion.response.clientDataJSON)),
      signature_der: Array.from(new Uint8Array(assertion.response.signature)),
    },
  };
}
// Place the result in authorization.session_proof or authorization.access_proof.
// POST { registration, commit, message, authorization } to /jobs; then poll or use SSE.
// A proof authenticates this exact operation; it does not authorize enrollment or root access.

// Client-side creation only. The owner must approve this public material in the
// controller's set_policy/grant_session transaction. There is no server attestation ceremony.
export async function createPasskey({ rpId, userId, userName, challenge }) {
  if (!Array.isArray(challenge) || challenge.length !== 32) {
    throw new Error("Expected a fresh 32-byte registration challenge");
  }
  const created = await navigator.credentials.create({
    publicKey: {
      challenge: new Uint8Array(challenge),
      rp: { id: rpId, name: "PairKey" },
      user: { id: new Uint8Array(userId), name: userName, displayName: userName },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { userVerification: "required" },
      attestation: "none",
      timeout: 60000,
    },
  });
  if (!created || created.response.getPublicKeyAlgorithm() !== -7) {
    throw new Error("Expected an ES256 credential");
  }
  const spki = created.response.getPublicKey();
  if (!spki) throw new Error("Browser does not expose the credential public key");
  const key = await crypto.subtle.importKey(
    "spki", spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"],
  );
  const publicKey = Array.from(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
  return {
    credentialId: Array.from(new Uint8Array(created.rawId)),
    credential: { Passkey: { public_key: publicKey, rp_id: rpId, origin: location.origin } },
  };
}
