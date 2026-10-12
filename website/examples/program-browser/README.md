# Runnable program browser example

This is a static example for the hosted v2 **example controller**. From the
repository root:

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory website
```

Open `http://127.0.0.1:4173/examples/program-browser/`. Use a Solana wallet with
devnet SOL, then choose the hosted example program or enter your own deployed
v2 example controller ID. The hosted API is at `https://pairkey.com/api/v2`.

The example walks through an explicit owner policy transaction, public key
derivation, one exact message approval, optional on-chain commit, signing, and
public-only recovery. The final button broadcasts a native Solana Ed25519
verification instruction and waits for finality. It proves that the returned
message signature is valid for the derived public key; it does not move assets.

The browser SDK and service verification used here do not independently verify
all key certificates and both signer receipts. Click **Download verification
transcript**, then run `cargo run -p pairkey-sdk --example verify_hosted --
pairkey-<job-id>.json` from the repository root. You can also supply the
`ProgramClient.verifyTranscript` callback to enforce this in your application.

To use the local installable package in your own frontend project instead of
the example's repository import, run
`npm install /path/to/pairkey/website @solana/web3.js@^1.98.4`
from that project and import `ProgramClient` from
`@pairkey/sdk/program`. The root export provides the unified `PairKeyClient`.
