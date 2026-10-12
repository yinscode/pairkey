# OWS-style PairKey SDK implementation

This record maps the eleven implementation tasks to the code that now carries
them. “OWS-style” means the application gets a small signer interface such as
`connect`, `signTransaction`, and `signAndSend`; PairKey's remote threshold signer,
exact approval, receipts, and recovery semantics remain visible where they affect
security.

1. **Named namespaces.** A case-sensitive NFC label of 1–128 UTF-8 bytes maps to
   `digest("pairkey/named-namespace/v1", borsh_bytes(label))`. The existing raw
   32-byte namespace ID remains supported.
2. **SDK namespace support.** `connect({namespace})` works for account, program,
   passkey, and OIDC sources. `namespaceId` is the compatibility form.
3. **Reusable program client.** `ProgramClient` accepts the supplied controller,
   a custom `Program` source, a source provider, and read/set/commit policy
   adapters.
4. **Policy scope.** The controller accepts compatible shared policy PDA
   `["pairkey-policy", owner]` and namespace policy PDA
   `["pairkey-policy", owner, namespace_digest]`. The program source binds exactly
   one selected account. The high-level controller client defaults to namespace
   scope.
5. **Four auth sources.** `PairKeyClient` has one key/sign/recovery surface.
   Account and program requests use wallet caller proof. Passkey and OIDC requests
   create a fresh short-lived Ed25519 binding and keep assertions/tokens out of
   public recovery data.
6. **Typed transaction requests.** The approval commits a domain-separated typed
   transaction envelope. Both workers independently validate that envelope and
   compute the destination signing bytes.
7. **Transaction adapters.** Solana legacy/v0 messages, EIP-155 legacy EVM native
   transfers on configured chain 84532, and canonical NEAR transactions are
   implemented. Bitcoin and Zcash requirements are recorded in
   `docs/transaction-adapters.md`.
8. **Sign and send.** The browser SDK assembles signed transactions and can submit
   them through an application-supplied Solana connection, EVM/NEAR RPC URL, or
   broadcast callback. The hosted signer service never chooses a destination RPC.
9. **Uncertain outcome recovery.** Signing recovery is saved before approval.
   Exact signed transaction bytes are saved before broadcast. RPC timeouts return
   `unknown`; `recoverAndSend` recovers the original signer job and can rebroadcast
   identical bytes without another approval or threshold signing round.
10. **Tests.** Rust tests cover canonical Solana/NEAR conversion, hosted typed
    preparation/verification, coordinator-worker payload separation, and shared vs
    namespace policy instructions. Browser tests cover namespace mapping, all four
    auth dispatch paths, transaction assembly/broadcast, mutation refusal, and
    uncertain broadcast recovery. A real hosted HTTP test signs typed Solana,
    EVM, and NEAR transactions through the coordinator and both workers. Existing
    SBF/live sidecar tests remain the full environment gate.
11. **Package and docs.** `website/package.json` defines `@pairkey/sdk` 0.2.0 with
    root and `/program` exports. The generated docs describe the common API,
    source-specific authentication, program policy scope, per-chain capability
    matrix, recovery states, and npm publication steps.

## Compatibility boundary

The SDK shape resembles a local wallet signer, but PairKey is asynchronous and
policy-aware. `signTransaction` can require a wallet/passkey/OIDC prompt, an
onchain program commit, two remote signing participants, and later recovery.
`signAndSend` reports signing and destination delivery separately. Applications
must retain the job ID and must not treat a transport failure as proof that no
signature or transaction exists.
