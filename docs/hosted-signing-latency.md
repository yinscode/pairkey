# Hosted DKLS message-signing latency — October 13, 2026

These measurements use the public hosted account/EVM message path on the
development demo. A server-held demo account authorized each unique message;
the probe verified the returned signature and signer receipts. It did not
broadcast a transaction. Each row is one live sample, not a p50 or p95 claim.

| Configuration | Donor | Prepare | Submit | Wait for job | Verify | End to end |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Sequential exchange, unoptimized development build | warm | 1,033 ms | 1,135 ms | 30,990 ms | 763 ms | 33,922 ms |
| Concurrent exchange, unoptimized development build | warm | 1,004 ms | 998 ms | 28,766 ms | 1,030 ms | 31,799 ms |
| Concurrent exchange, optimized development build | cold | 813 ms | 542 ms | 12,073 ms | 861 ms | 14,292 ms |
| Concurrent exchange, optimized development build | warm | 803 ms | 546 ms | 12,073 ms | 902 ms | 14,326 ms |
| Optimized build after disabling diagnostic logs | cold | 792 ms | 541 ms | 12,824 ms | 886 ms | 15,045 ms |

The optimized warm run's coordinator trace measured 10,302 ms in the DKLS
exchange and 72 ms in repeated registration. Both workers retained the same
donor generation and advanced together to use 2. A local real-DKLS integration
trace counted 26 authority views per signature before the admission change. In the optimized hosted run,
individual views took about 500 ms; roughly 460 ms was two sequential Solana
RPC reads (`getMultipleAccounts` and `getBlockTime`). The coordinator and
browser polling layers account for part of the remaining difference between
the exchange and observed completion. The browser now polls at 750 ms through
the first 20 seconds, then backs off to 2.5 seconds.

The coordinator now requests both signers' exchanges concurrently. A later
worker change checks finalized Solana authority once per signer at DKLS start,
then retains only local replay, expiry and incident checks during the exchange.
An already admitted request may finish after a policy or program-state change;
the change applies to subsequent requests. The timings above predate this
admission change and are not measurements of its latency. `scripts/build-hosted-demo.sh` sets development `opt-level=2`
and keeps debug assertions enabled; the development-attestation release gate
remains in force. `PAIRKEY_LATENCY_TRACE` enables timing-only logs, and the
standalone `crates/pairkey-demo/examples/latency_probe.rs` provides a repeatable
hosted message-signing probe. The live service has diagnostic logging disabled.

The Rust hosted client also now advances its caller-supplied verification time
by elapsed network time. Previously, an approval issued in the next clock
second could fail local validation after a slow preparation request. This was
a separate client-side failure, before the signing job began.

The per-frame RPC calls were the next latency target. The fresh hosted
measurement below quantifies the effect of reducing DKLS admission to one
authority view per signer.

## One authority view per signer — deployed October 13, 2026

Each DKLS signer now reads finalized Solana authority once before starting its
protocol exchange. Local claim expiry, replay and incident checks remain in
place during the exchange. A request admitted before a policy or program-state
change may complete; the change applies to later requests.

The same hosted account/EVM probe verified every resulting signature and both
signer receipts. Before deployment, two requests took 13,730 and 14,359 ms end
to end. The first request after restart took 4,698 ms, followed by 3,175 ms.
Five more warm requests took 3,105, 3,124, 3,196, 3,193 and 4,101 ms; their
median was 3,193 ms. The two-request before sample had a 14,045 ms median,
so the observed median fell by about 77%. These are small live samples, not
tail-latency guarantees. They measure the account source, which makes no
`pairkey_approve` simulation; program-source latency remains unmeasured.

## FROST authority admission — deployed October 13, 2026

The FROST worker now reads finalized Solana authority once per signer at the
first signing round, rather than once at each of the three signing rounds. Both
signers run concurrently within each round. The hosted off-chain flow still
performs approval preparation and a pre-signing check, so this change only
removes the two later signing-round views per signer.

The same public `https://pairkey.com/api/v2` account-message probe signed three
distinct messages per chain before and after the worker rollout. It verified
each result and both signer receipts, without broadcasting a transaction.
The old release was `donor-reuse-20261013`; the new release is
`frost-once-20261013`. Medians include approval preparation, submission, job
polling at 750 ms intervals, and verification on the caller's connection.

| Chain / FROST scheme | Before median | After median | Change | After job-wait median |
| --- | ---: | ---: | ---: | ---: |
| Solana / Ed25519 | 4,535 ms | 2,992 ms | −34.0% | 1,667 ms |
| NEAR / Ed25519 | 4,546 ms | 2,918 ms | −35.8% | 1,667 ms |
| Zcash / RedPallas | 4,687 ms | 3,120 ms | −33.4% | 1,723 ms |
| Bitcoin / secp256k1 BIP-340 | 4,602 ms | 2,896 ms | −37.1% | 1,665 ms |

The three before samples were 4,535/4,535/4,475 ms for Solana,
4,687/5,403/4,625 ms for Zcash, 4,544/4,602/4,717 ms for Bitcoin, and
4,550/4,531/4,546 ms for NEAR. The three after samples were 2,848/4,202/2,992 ms for Solana,
3,288/3,120/3,065 ms for Zcash, 2,896/3,033/2,889 ms for Bitcoin, and
2,918/2,966/2,912 ms for NEAR. The 4,202 ms Solana sample had a 1,109 ms
submission, rather than the other two samples' 588/752 ms. These are small
observational samples, not a p95 or latency guarantee. Job wait includes
750 ms polling and cannot be interpreted as pure signer CPU or RPC time.
An EVM regression check on the new release took 4,746 ms for the first
post-restart donor and 3,117 ms for the next warm donor; both signatures and
receipts verified. These two samples are not a new DKLS latency distribution.

To reproduce a chain's account-message timing, set
`PAIRKEY_LATENCY_CHAIN=solana|near|zcash|bitcoin|evm` and
`PAIRKEY_LATENCY_ATTEMPTS=3` when running
`cargo run -p pairkey-demo --example latency_probe --locked`. The probe prints
prepare, submit, wait, verify and total milliseconds for every verified result.

## Warm DKLS latency breakdown — October 13, 2026

Four live account/EVM message signatures were profiled with timing-only worker
and coordinator logs on the `frost-once-20261013` development release. The
first signature prepared a fresh donor; the next three reused it. The warm
requests took 4,008, 3,992 and 4,887 ms end to end with 750 ms client polling.
The coordinator reported 68–93 ms for repeated key registration, 0 ms at its
millisecond resolution for donor status, and 884–967 ms for the signing
command. The signing command **includes** its worker's authority view, so the
figures below must not be added to one another as separate stages.

| Stage | Warm observation | What it includes |
| --- | ---: | --- |
| Approval preparation | 587–634 ms | Gateway request and approval-rule preparation; not separately traced inside the gateway |
| Approval submission | 645–733 ms | One worker authority view per signer, concurrent; the two Solana reads alone took about 458 ms |
| Job admission check | About 458 ms of Solana reads | A second authority view per signer, concurrent, before coordinator job reservation |
| DKLS signing command | 884–967 ms | A third view (worker view 544–573 ms), then native signing and relay work; subtracting the view leaves roughly 0.3–0.4 s, an estimate rather than an independently timed stage |
| Result delivery | Up to 1 s gateway polling, then client polling | The gateway checks the coordinator once per second; the probe checks the gateway every 750 ms by default |
| Client verification | 203–206 ms | Signature and both signer receipts |

Within each Solana authority view, `getMultipleAccounts` took a median
228–230 ms and the following `getBlockTime` took 227–230 ms. They are
sequential because the second call uses the slot returned by the first. The
three views on the critical path therefore contribute about 1.4 s of Solana
RPC wait, although the two signers run each view concurrently.

To isolate result polling, the same probe was run with
`PAIRKEY_LATENCY_POLL_MS=100` after the trace was disabled. Its two warm
requests took 3,202 and 3,284 ms end to end, with 1,775 and 1,732 ms spent
waiting for the job. The three traced warm requests at 750 ms polling waited
2,523, 2,526 and 3,328 ms. These are separate small samples, so the observed
difference is indicative, not an exact causal estimate. The gateway's 1-second
poll remains in both runs.

The next straightforward latency change is to deliver coordinator completion
to the gateway promptly and shorten or replace client polling. Reducing the
three authority views requires a separate authorization-design review;
removing a check without preserving its policy and revocation behavior would
change the security semantics. Warm donor reuse itself avoids about 450 ms of
fresh donor preparation in the traced cold run, but leaves the per-signature
DKLS command in place.
