# Hosted approval API v2

This is the implementation-branch API contract. The browser SDK, quickstarts and demo use this contract.
Live rollout still requires a coordinated deployment. The existing `/api/v1` API remains
available for previously registered namespaces and COMMIT requests.

Use `/api/v2` as the base URL. POST JSON with `X-PairKey-Client: 1`. Every mutation
constructs a request or unsigned instruction; the API never spends the hosted
wallet's funds on behalf of a developer.

## Message signing

1. `GET /config` returns the gateway, network, signer identities, enclave-set ID,
   supported chains, the configured example program, and OIDC issuer/audience pairs. Pin deployment
   identity in your application. This deployment uses development workers.
2. `POST /namespaces` with `{identity, namespace_id}` obtains public derivation
   metadata and two signer attestations. No registration transaction is created.
   The Rust SDK's `offchain_namespace` verifies those attestations and the expected
   namespace. Existing account and controller-PDA derivation authorities are
   preserved byte-for-byte.
3. `POST /keys` with `{registration, chain, path}` lazily obtains the derived key.
   `chain` is `solana`, `evm`, `zcash`, `near` or `bitcoin`. Use `offchain_key` to
   verify the public derivation or multi-suite certificate.
4. `POST /approvals` with `{signing_request, identity}` prepares the exact request.
   `signing_request` contains `{key, request_id, message}`; `key` is the input from
   step 3. Save this request. The response includes current rules, exact committed
   payload bytes, expiry, and the ASCII `signing_message`. Verify it against your
   original inputs before obtaining authorization; Rust `prepare_offchain` does
   this locally. Preparing again can produce a different expiry and approval.
5. Authenticate the exact `signing_message`, then `POST /jobs` with
   `{signing_request, approval: {request, proof}}`. Both workers independently check
   the private proof and current chain policy before a job is reserved. This is
   separate from transaction broadcasting on any destination chain.
6. Poll `GET /jobs/{job_id}`. Verify the returned chain signature and both signer
   receipts against the original approval with
   `pairkey_sdk::hosted::offchain::verify_result`.

The default approval lifetime is five minutes. Raw messages are limited to 256
UTF-8 bytes. Standard rules constrain the committed payload: raw message bytes for
Solana and NEAR, or the serialized signing Intent for EVM, Zcash and Bitcoin.
These are message rules, not transaction parsing or cumulative spending limits.

Account proof:

```text
Identity::Account { public_key: wallet_public_key }
Proof::Account { signature: wallet.signMessage(signing_message) }
```

For a passkey or OIDC identity, create an ephemeral Ed25519 key and a `Binding`
containing its public key, identity digest, namespace digest, and validity window.
The binding's lifetime is at most ten minutes and must cover the request lifetime.
The ephemeral key signs the exact request. This is per-request authentication,
not a delegated session or permission to bypass the owner's policy.

- Passkey: use the base64url-encoded `Binding::challenge()` as the WebAuthn
  challenge. Send the assertion, binding and ephemeral request signature privately.
  RP ID, origin, user presence and user verification are checked by each worker.
- OIDC: use that challenge's base64url encoding as the authentication request's
  nonce. Send the ID token, binding and ephemeral request signature privately.
  Workers accept the configured issuer/audience only, validate the RS256 signature
  and identity/time/nonce claims, and fetch keys from the operator-pinned JWKS URL.

The hosted job journal and public receipts contain the proof commitment, not the
JWT, passkey assertion or caller signature.

## Recovery

Save the original prepared request and returned job ID. Retrying its exact
submission returns the same job, including after approval expiry. A different
approval cannot reuse the same namespace/request ID.

After interruption, `POST /jobs/{job_id}/recover` reads the coordinator's durable
record and both workers' saved public receipts. It cannot create a key, approve a
request, start a protocol round, or assign fresh randomness. A complete result
remains verifiable after approval expiry. If there is insufficient evidence of a
completed result, the job remains uncertain; do not automatically create a fresh
request to replace it.

Public recovery contains messages and signatures. Do not use a public hosted
message-signing demo for confidential payloads.

## Optional persistent rules

No policy account is required for direct per-message authorization. After a
policy is created, its revision is authoritative; absence, read failure and a
disabled policy are different states.

- `POST /policies` with `{registration}` reads the current rules and PDA address.
- `POST /policies/prepare` with `{registration, identity, rules}` constructs an
  exact `PolicyUpdate`. Supply the explicit next revision; the server refuses a
  stale revision and never silently replaces your selected rules. Verify the
  response with `PolicyPrepared::verify`.
- `POST /policies/instructions` with `{payer, update, authentication}` returns
  unsigned native verification and gateway instructions. Inspect and send them
  through the owner's wallet; this endpoint does not broadcast.

Authentication variants are `Wallet`, `ProgramCpi`, `Passkey(assertion)`, and
`Oidc { binding, id_token, signature }` in the Rust types' JSON encoding.

Wallet updates require the account owner's native transaction signature. Program
updates require the authority PDA to sign through the application's CPI. Passkey
updates use a WebAuthn assertion over `PolicyUpdate::challenge()` and Solana's
native P-256 verification instruction; no threshold signature is needed. OIDC
updates use a bound ephemeral signature over `PolicyUpdate::signing_message()`;
both workers attest the update, and only their public attestations enter Solana.

One policy account is reused across edits, with monotonic revisions and no delete
fallback. Each update has a transaction fee. Creating or enlarging a policy can
require a rent deposit; a same-size edit reuses its existing deposit. Ordinary
off-chain signing creates no approval account and submits no Solana transaction.

## Example program

The example controller's stable authority is the PDA derived from
`[b"controller", owner_public_key]` under its program ID. Applications with other
PDA seeds or policy accounts can construct their own `Identity::Program(Source)`
and implement the approval ABI in `pairkey_types::program_approval`.

- `POST /programs/example` with `{program, owner, mode}` returns the example source
  and application policy address. `mode` is `Offchain` or `Onchain`. Off-chain
  evaluation resolves and pins immutable deployed program code. On-chain mode
  supports upgradeable programs and uses the recorded PDA-authorized decision.
- `POST /programs/example/policy/read` with `{program, owner}` reads the current
  application policy, or returns null if none exists.
- `POST /programs/example/policy` constructs an owner-signed application policy
  update. Supply program, owner, next revision, enabled flag, chain, path prefix,
  maximum committed payload size, `require_commit`, and `remaining_approvals`.
  Send these instructions once to create rules or explicitly to edit them.
- In off-chain mode, sign the exact request with the caller wallet and submit
  `Proof::Program { caller, signature }`. Each worker runs its own authenticated
  read-only `pairkey_approve` simulation. It does not consume the counter.
- In on-chain mode, `POST /programs/example/commit` with `{owner, prepared}`
  constructs the example's `pairkey_approve_commit` instruction. Send and finalize
  it before submitting the same prepared approval and caller proof to `/jobs`.
  The application consumes one allowance and records the exact request atomically.
  Signing afterward does not consume it again.

Do not broadcast the bare gateway approval instruction from a wallet. Program
authority comes from the application's authenticated `invoke_signed` call.
Unsigned instruction bundles are checked against Solana's transaction-size limit,
including the browser client's compute-budget prefix. Large policies, identity
fields or committed payloads may need to be shortened.

Simulation uses finalized RPC data and depends on the RPC provider's correctness.
It does not certify a consensus approval or reserve mutable state. Use commit for
one-time allowances, cumulative budgets or state changes. Worker identity accounts
need a small funded balance to act as simulation fee payers, but simulations are
not broadcast and do not spend that balance.

## Operator identity configuration

Optionally create `oidc-issuers.json` in the private runtime state directory, mode
0600, before starting the service:

```json
[
  {
    "issuer": "https://issuer.example",
    "audience": "your-client-id",
    "jwks_url": "https://issuer.example/.well-known/jwks.json"
  }
]
```

The service passes this configuration to both workers. Each worker independently
fetches and validates keys. The issuer string must exactly match token `iss`, and
the audience must match your application's OAuth client. Endpoints require HTTPS;
redirects and token-selected key URLs are not accepted. Only issuer and audience
are published in `/config`. Configuration is bounded, duplicate pairs are refused,
and malformed files fail startup. With no file, no OIDC providers are enabled.
Provider configuration alone is not evidence of a successful live OAuth test.

Before rollout or a configuration restart, inspect active hosted and coordinator
jobs, preserve all roots, identities, journals and incident latches, and reconcile
uncertain results. Deploy the gateway, controller ABI, workers and hosted API as a
coordinated change. Never reset runtime state to make a failed test pass.
