# Hosted v2 deployment — October 13, 2026

`main` was fast-forwarded to `4cb2a5f`. That release supplies the Linux backend,
workers, coordinator, DKLS sidecar, website, browser SDK and docs now served at
https://pairkey.com. The rollout completed on October 12 UTC / October 13 in
Asia/Bangkok. The following documentation-only commit records its evidence.

## Deployment and continuity

- Upgraded the existing Solana devnet gateway
  `rsYu5jyioN9YjWcj58houJ4AYnWKWwjTtpG8hSMw1QZ` and example controller
  `EQJ78XYJXQL4bLchc45yhHhZhYjArkpkfcFGhydHKZJW`. Both deployed binaries were
  downloaded and compared with the tested release bytes. Upgrade authority was retained.
- Paused public signing, checked terminal jobs, stopped the service and took
  access-controlled server and offline backups before the upgrade. Preserved roots,
  identity keys, incident latches, service ports, journals and the historical
  uncertain job; no signing attempt was reassigned or retried during migration.
- Re-derived both existing account/program namespace registrations and checked
  their ten message-key contexts plus the legacy EVM key. Sixteen existing hosted
  key certificates and the private identity files remained unchanged.
- Resumed public traffic only after signing, policy and restart-recovery checks.
  The demo and both quickstarts return HTTP 200; `/api/v2/config` reports ready.

## Verification

The exact deployment-ID SBF binaries passed 14 gateway, policy and program tests.
The Linux release passed 20 host tests; its eight explicitly ignored integration
tests were covered separately by the earlier acceptance gate, not counted as Linux
passes. All 45 website unit tests and the 16-page site check passed.

Using a disposable funded devnet account and the deployed browser SDK:

- Signed Solana, EVM, Zcash, NEAR and Bitcoin messages through account approvals.
  No wallet transaction was requested and the account SOL balance stayed unchanged.
- Created the example program's owner policy and committed one Solana message
  approval. Its allowance changed from two to one exactly once; result recovery
  left it at one.
- Updated account rules on Solana. A previously prepared approval was rejected
  before job admission (the API surfaced a generic HTTP 400); a disallowed path
  was rejected, while a fresh allowed request signed under the new revision.
- Rejected altered-message verification for every completed signing case. The
  independent Rust verifier checked all seven signatures and both signer receipts.
- Restarted the real backend and recovered all seven original signatures unchanged.
  Recovery created no new signing job and consumed no additional program allowance.

Browser checks confirmed the live v2 connection, all five destinations, the example
program ID and automatic on-chain mode selection, and both quickstart pages. No
browser console errors were observed. No user wallet was connected for these UI checks.

Public identifiers and artifact hashes are in
[the machine-readable deployment evidence](offchain-approval-deployment.json).
Private backups, test-wallet material and operator logs remain outside Git and the
public web root.

## Operational findings and remaining scope

Backdated Git archives can appear older than copied Cargo artifacts. Refresh staged
source timestamps or use a clean build before reusing a cache; this rollout caught
and corrected stale artifacts before service activation. Serve public assets from
their own readable web directory without widening access to the private operator home.

The first gateway upload exhausted RPC retries. The saved buffer was resumed with
paced idempotent writes, checked against the complete binary and then activated.
The controller upload completed normally. No program ID or signer state was replaced.

This remains a development-worker deployment on one host with Solana devnet as its
control plane and Base Sepolia as the configured EVM destination. It does not establish
independent hardware-backed TEEs. Live checks covered account approvals and the
upgradeable example's on-chain program approval. Immutable program evaluation and
passkey/OIDC flows retain their recorded local test coverage; they were not exercised
against public devnet during this rollout. No OIDC provider is configured. Sessions
remain deferred in v2. These checks signed messages, not destination transactions.

## Google OIDC preview after the rollout — October 13, 2026

The operator subsequently configured Google as a pinned OIDC issuer for the hosted
v2 development service. Its public audience is the PairKey Web client ID
`551116982116-nlms8ht155986h1p4k1jpa1ulc3ctrke.apps.googleusercontent.com`;
the signer configuration uses Google's HTTPS JWKS endpoint. The OAuth client
secret is not used for browser ID-token approval and is not stored in the site.
After a coordinated service restart, `/api/v2/config` reported the new audience
and `ready: true`. The user confirmed Google account selection in their browser.
No completed Google-authorized signing job was observed at the time of this
addendum, so the live OIDC signing path is still a preview rather than an
end-to-end acceptance result. The earlier “No OIDC provider is configured” line
records the state at the original deployment snapshot. Changing the OIDC
audience changes namespace identity and derived keys for that source.
