# PairKey website

Static landing page, a backend-connected demo at `/demo`, and ten developer documentation pages. All assets are local; no analytics or external fonts. For static landing page and docs preview only, serve this directory:

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory website
```

Open http://127.0.0.1:4173. The authorization-path tabs support arrow, Home, and End keys; FAQs use native disclosure controls. The comparison table scrolls horizontally on narrow screens.

## Content approach

The landing page leads with programmable keys, two independent TEE signers, and multichain signing. It describes the protocol architecture, with a compact developer-preview label and direct links to availability. Detailed deployment status, integration coverage, fee semantics, and security assumptions live in `docs.html`. The comparison focuses on authorization and signing models rather than unverified performance claims.

## Content boundaries

The intended architecture has two independent TEE signers, with no full private key assembled in protocol execution. Independent TEE deployment is not yet validated. Solana is the sole control plane. Solidity and NEAR transaction integration are planned; RedPallas signing is not a complete Zcash wallet. Solana and EVM native-transfer flows are demonstrated locally.

The session fee claim is specifically zero *per-signature Solana authorization transaction* fees for eligible session-only requests. Setup, revocation, destination execution, infrastructure and potential service charges are separate. No comparative performance benchmark or production price is asserted.

Competitor descriptions link directly to NEAR's standard Chain Signatures flow and Turnkey's architecture. NEAR has multichain outputs; Turnkey uses several specialized enclave services. Neither is presented as lacking programmability.

This initial version is saved in the PairKey repository for local review; no hosted deployment is configured. The complete implementation guides remain in `../docs/`.

## Demo

`/demo` uses the live Rust backend. `demo.html` contains authority and chain selectors, exact-message approval, and a branching diagram matching the hero: Solana program/account → independent signer A and B → combined signature → fresh verification. No destination broadcast occurs. `/testnet.html` redirects to `/demo`. The homepage contains no interactive simulation.

`testnet.js` submits idempotent requests, polls the persisted operation, and exposes recent operation history. `message-demo.mjs` projects verified backend evidence into visual states. Signer cards become verified only when the SDK has verified the corresponding receipts; no individual round timings are invented. Unknown outcomes stay unknown. The final signature and both signer receipts are inspectable in the audit trail. `demo-policy.mjs` provides exact integer wei parsing.

## Documentation

Edit `content/*.html`, then regenerate the checked-in static pages:

```sh
python3 website/build-docs.py
```

The generator writes `docs.html` (Overview), nine pages in `docs/`, and a copy of the public Rust client in `examples/`. Sidebar navigation, page contents, titles, and previous/next links share one template. There are no client-side routing or runtime build requirements. `docs.js` preserves legacy links such as `docs.html#quickstart`.

Pages: Overview, Quickstart, Interactive demo, Live testnet setup, Architecture, Solana program integration, Scoped sessions, Signing integrations, SDK & API reference, and Security & status.

## Verify

```sh
python3 website/check-site.py
node --test website/demo-policy.test.mjs website/demo-flow.test.mjs website/message-demo.test.mjs
node --check website/testnet.js
```

The site checker verifies generated output, local links, fragment targets, assets, form labels, and one main heading per public page. Policy tests cover valid requests, exact-cap and one-wei-over boundaries, malformed amounts, recipient substitution, missing/revoked/expired authority, issuance rechecks, and per-operation semantics. Flow tests cover pending signing, preflight refusals, verified signer roles, assembly, broadcast acceptance, zero-block preconfirmations, reverted receipts, and unknown outcomes. Browser QA covers history selection, real signing, refusals, and narrow/wide layouts.

## Live testnet backend

`demo.html` and `testnet.js` use the loopback Rust service in `crates/pairkey-demo`. Build, fund, deploy and start it with `scripts/demo-testnet.sh` as described in `docs/testnet.html`; open `http://127.0.0.1:4180/demo`. This runs actual FROST Ed25519, DKLS23 secp256k1, FROST RedPallas, and Bitcoin FROST secp256k1 (BIP-340) signing with finalized Solana devnet approvals and two development signer processes. Only the legacy transfer API broadcasts Base Sepolia transactions. It does not claim hardware-backed TEE execution. `GET /api/status` reports setup and funding state. The service provides no public hosting or arbitrary transaction API.

Check `node --check website/testnet.js` and `cargo test -p pairkey-demo -p pairkey-signing --locked` in addition to the website checks. Public-testnet execution needs funded dedicated addresses and deployed programs; a successful build alone does not establish a live transfer.
