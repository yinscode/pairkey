# PairKey website

Static landing page, interactive browser simulation, and nine developer documentation pages. All assets are local; no analytics, external fonts, dependencies, or backend. Serve only this directory:

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

`demo.js` owns the ephemeral browser walkthrough. `demo-policy.mjs` evaluates grant existence, revocation, expiry, recipient, and per-operation limits with exact integer wei arithmetic. The signer panels, signature outcome, and receipts are explicitly simulated. No wallet connection, backend, transaction, telemetry, storage, or real cryptographic operation is involved.

The demo supports editable grants and requests, amount/recipient refusal presets, expiration, revocation during checking, and reset. A final issuance check observes revocation or expiry during the animation. Reset invalidates pending animation work. Changing the rule form does not modify the active grant until it is submitted. Prior illustrative receipts remain visible after revocation.

## Documentation

Edit `content/*.html`, then regenerate the checked-in static pages:

```sh
python3 website/build-docs.py
```

The generator writes `docs.html` (Overview), eight pages in `docs/`, and a copy of the public Rust client in `examples/`. Sidebar navigation, page contents, titles, and previous/next links share one template. There are no client-side routing or runtime build requirements. `docs.js` preserves legacy links such as `docs.html#quickstart`.

Pages: Overview, Quickstart, Interactive demo, Architecture, Solana program integration, Scoped sessions, Signing integrations, SDK & API reference, and Security & status.

## Verify

```sh
python3 website/check-site.py
node --test website/demo-policy.test.mjs
node --check website/demo.js
```

The site checker verifies generated output, local links, fragment targets, assets, form labels, and one main heading per public page. Policy tests cover valid requests, exact-cap and one-wei-over boundaries, malformed amounts, recipient substitution, missing/revoked/expired authority, issuance rechecks, and per-operation semantics. Browser QA should cover successful and refused flows, in-flight revocation, reset, legacy docs redirects, and narrow/wide layouts.
