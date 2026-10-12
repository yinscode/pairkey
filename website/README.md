# PairKey website

Static landing page, hosted v2 message demo at `/demo`, and 18 documentation pages.
Visual assets are local. The Google source loads Google Identity Services for sign-in;
no analytics or external fonts are loaded.

For static layout preview (no signing API):

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory website
```

The Rust service serves `/demo`, the docs, downloadable SDK/program archives, and
`/api/v2` together. `/testnet.html` redirects to `/demo`. The new pages require the
coordinated v2 release; they do not silently fall back to the legacy shared owner.

## Approval model

V2 establishes public metadata without a registration transaction. Accounts sign
exact requests with wallet `signMessage`. Programs use authenticated read-only
simulation against immutable code or an explicit state-consuming on-chain commit.
Optional standard rules live in reusable Solana accounts. Sessions are deferred
for v2; the older transfer-session APIs remain compatible and separately documented.

Passkeys and configured OIDC providers authenticate bound ephemeral Ed25519 keys
through the SDK. The public demo creates or reuses a site-scoped passkey and stores
only its public credential metadata in the visitor's browser. Applications still
need a verified WebAuthn registration and recovery ceremony. The demo also exposes
account and program sources, plus Google when its issuer is configured.
Google credentials stay in browser memory and are not included in public recovery
records.
Development hardware status and transaction-format boundaries belong in the docs.
The landing page describes the target two-independent-TEE architecture without
claiming a measured production latency or universal free service.

## Demo and SDK

`hosted-v2.mjs` and `approval-codec.mjs` implement canonical browser approvals and
explicit management transactions. They reuse wallet transaction compatibility from
`hosted-client.mjs` (the v1 client). `pairkey-client.mjs` provides one interface
for account, program, passkey and OIDC sources with message signing, typed
transaction signing, client-side broadcast and recovery. `program-client.mjs`
adds explicit example-controller policy management. They form the publishable
`@pairkey/sdk` package with type declarations. The docs generator includes them in
`examples/hosted-client-v2.zip`.

`hosted-session.mjs` is shared by the quickstarts and demo. It saves public recovery
metadata for each job before submission and never reauthenticates, recommits or
resubmits on recovery. `testnet.js` connects visitor wallets, passkeys or a Google account, exposes program
setup, and shows message signing across five destinations. History is tab-local and contains
public transcripts only. Saved results are not labelled freshly verified.

`message-demo.mjs` projects lifecycle evidence into signer cards. Joint work does
not invent individual completion timings. The backend Rust SDK verifies full
receipts and all signature suites. Browser checks of exact context and Ed25519 do
not replace that complete independent verification. The page's Verify button uses
the service; the downloadable Rust example supports independent verification.

## Generated documentation and program download

Edit `content/*.html`, then run:

```sh
python3 website/build-docs.py
```

The generator produces `docs.html`, 17 pages under `docs/`, public Rust examples,
the browser SDK archive and a self-contained program archive. The program bundles
the exact typed gateway ABI and policy implementation from the source tree, with
pinned dependencies. Edit application rules in the downloaded bundle's
`vendor/programs/example-controller/src/approval.rs`. The entrypoint rejects legacy
Register/Commit forwarding as an alternate route around those rules.

## Verification

```sh
python3 website/check-site.py
node --test website/*.test.mjs
node --check website/testnet.js
cargo run -p pairkey-sdk --example approval_vectors --locked -- --check
cargo test -p pairkey-sdk --example verify_hosted --locked
# Requires SBF tools and built registry; tests the exact extracted program archive.
source .local/ci-tools/env.sh
python3 scripts/check-controller-bundle.py --sbf
```

CI also runs the shared browser lifecycle against a real local hosted API and two
workers for all five signing suites. Its in-memory chain refuses broadcasts in the
account test. Program tests exercise actual SBF simulation and atomic commit.
For manual browser QA, the ignored `hosted_manual_browser_preview` test uses only
isolated generated workers, an in-memory Solana chain, and an explicit stop file.
It must never load operational `.local/testnet-demo` state.

The site checker validates generated output, links/fragments, downloads, labels and
headings. Browser QA separately checks layout and interactions. A full gate is
`bash scripts/ci.sh`; its logs are saved under `.local/ci-report`.
