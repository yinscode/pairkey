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
