# PairKey website

Buildless landing page and initial developer guide. All assets are local; no analytics, external fonts, dependencies, or backend. Serve only this directory:

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory website
```

Open http://127.0.0.1:4173. The authorization-path tabs support arrow, Home, and End keys; FAQs use native disclosure controls. The comparison table scrolls horizontally on narrow screens.

## Content boundaries

The intended architecture has two independent TEE signers, with no full private key assembled in protocol execution. Independent TEE deployment is not yet validated. Solana is the sole control plane. Solidity and NEAR transaction integration are planned; RedPallas signing is not a complete Zcash wallet. Solana and EVM native-transfer flows are demonstrated locally.

The session fee claim is specifically zero *per-signature Solana authorization transaction* fees for eligible session-only requests. Setup, revocation, destination execution, infrastructure and potential service charges are separate. No comparative performance benchmark or production price is asserted.

Competitor descriptions link directly to NEAR's standard Chain Signatures flow and Turnkey's architecture. NEAR has multichain outputs; Turnkey uses several specialized enclave services. Neither is presented as lacking programmability.

This initial version is saved in the PairKey repository for local review; no hosted deployment is configured. The complete implementation guides remain in `../docs/`.
