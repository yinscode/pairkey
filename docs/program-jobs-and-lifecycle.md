# Solana program control and durable signing jobs

October 12, 2026. The application path uses a Solana controller program/PDA. That program publishes COMMITs, sets policy, grants/revokes sessions and freezes namespaces through registry CPI. Each worker independently checks finalized Solana state before releasing signing output. EVM remains a destination. No passkey/OIDC broker, HTTP signing authority or additional control chain is introduced.

The account-controller compatibility flows remain regression tests. The focused application demo uses only program/CPI authorization.

## Application flow

1. Register the program-controlled namespace and enroll a backend key with `Client::signing_key`, verifying both pinned worker identities.
2. Build a canonical `Intent` and `Commit`. Have the controller program publish the exact COMMIT, or grant a bounded EVM session under the current policy.
3. Submit `Client::submit_intent(&request)`. This returns a deterministic job ID for the exact request, including signing protocol, certificate, authorization and attempt ID.
4. Poll with `poll_intent`, wait with `wait_intent`, or subscribe through the existing `/jobs/:id/events` SSE route. `poll_intent`/`wait_intent` verify completed signatures and both identity receipts against the original request. SSE is a progress hint; verify the final result before use.
5. Submit the signed transaction to its destination separately. The coordinator never submits destination transactions or retries transfers.
6. Revoke the session or freeze the namespace through the controller program. This affects future signing after observation; retained job results and previously issued signatures remain retrievable/usable.

`POST /jobs` accepts `{ "signing": <SignRequest> }` for DKLS23/RedPallas; the existing Ed25519 request shape remains supported. Multi-suite results use `status: queued | working | complete | failed`, with the signed response under `result` on completion. Polling and SSE share the existing `/jobs/:id` paths. `POST /jobs/:id/cancel` requests cancellation of a multi-suite job. The older `/multi/sign` route submits the same durable job and waits for it; it no longer starts duplicate signing for an identical submission.

A compact Rust application client is `sdk/examples/program_jobs.rs`: it checks the example-controller PDA, enrolls the key, publishes a CPI COMMIT, waits for Solana finalization, submits a job and verifies its result. It takes a JSON configuration containing coordinator/RPC endpoints, owner keypair path, identity pins, `KeyRequest`, payload, request ID and fresh attempt ID. It assumes an already registered namespace with the default COMMIT policy. It does not automatically retry a Solana approval or destination operation after an ambiguous timeout.

The complete, self-contained local program flow (including native-transfer execution, session grants/revocation and the process-failure matrix) is:

```sh
python3 scripts/install-ci-tools.py
bash experiments/silence-dkls23/bootstrap.sh build --release --locked
bash scripts/build-programs.sh
cargo build --workspace --features pairkey-worker/dev-simulation --locked
bash scripts/demo-program-jobs.sh
```

## Retry and cancellation contract

- Repeat the **same exact request** to recover its retained job ID/result. No worker call is made for a cached completed result, including after coordinator replacement.
- A coordinator restart changes queued/working jobs to `failed` with code `interrupted` and `may_have_signed: true`. It never automatically resumes them. A crash between signing and durable result publication is necessarily ambiguous.
- A queue cancellation before work starts reports `may_have_signed: false`. In-flight cancellation reports `true`, burns/releases local resources through cleanup, and cannot retract output already exposed. Terminal jobs are immutable. Job cancellation is delivery control, not revocation of Solana authority.
- For an explicit retry, first reconcile any destination execution. Use `multi::fresh_attempt(&request, new_random_id)` to change only the signing attempt, then submit that request. COMMIT bytes, intent and delegate proofs stay bound; workers recheck current authority. A fresh signing attempt does not create a fresh destination nonce.
- A signing failure may still have produced output. `signing_failed`, `timeout`, `internal_failure` and `interrupted` are not proof of nonissuance. A local client wait timeout also does not cancel the job; keep polling its ID.
- The native D transport-abort journal retains its existing limit. Jobs expose `code: rate_limited` and `retry_after_secs` (currently 61) for this specific refusal. The client does not silently resubmit. The fault harness explicitly waits and uses a fresh attempt.

Fresh RedPallas nonces and a fresh D donor are used for each executed request. A retry never restores a nonce or donor from the job file. The job file contains public request/receipt material, not signing roots. Raw RedPallas messages still need application replay semantics; repeated valid signing is not exactly-once application execution.

## Persistence and bounds

`Config.jobs_file` selects the coordinator snapshot. The CLI defaults it to `<config-file>.jobs.json` when omitted. The parent directory must exist. One process holds an exclusive OS file lock for that path. Snapshots have version/configuration binding, a 32 MiB bound, private file permissions, atomic replacement and file/directory sync. Corrupt, oversized or incompatible snapshots refuse startup. A failed write makes the live store unavailable instead of reporting an unpersisted completion.

There are at most 64 admitted jobs across the existing capacity pool, 64 combined SSE/synchronous result waiters, and 256 retained multi-suite records. Completed records become eligible for removal after 24 hours when new work is admitted. Live records are not evicted. Applications should persist their verified results; after retention expiry, resubmitting old bytes can start new signing. The legacy Ed25519 result cache remains memory-only; these new persistence/idempotency guarantees apply to the multi-suite job envelope.

All multi-suite jobs and key enrollment share one protocol lock. A signing job has a 150-second execution bound once it starts. The owner retains the lock and its capacity permit through cleanup, even if the HTTP client disconnects. Cleanup resets both native children and clears/cancels RedPallas owners. Every subsequent job repeats a successful reset barrier before work starts. Key enrollment also retains its owner through disconnects and bounded cleanup.

Neither this filesystem lock nor the coordinator snapshot protects against storage rollback, cloned machines or another coordinator using different storage. The coordinator remains untrusted. Worker nonce ownership, native journals and Solana authority checks enforce signing restrictions independently.

## Durable incident handling and versions

Each development worker locks `<canonical-root-file>.incident.lock` and stores a sticky incident latch at `<canonical-root-file>.incident`. Authenticated FROST failures and native quarantine/configuration failures set the latch under the issuance lock before returning the error. Restarting the worker or resetting its backend does not clear it. Unknown or partial latch contents are treated as an incident; read errors refuse startup. Persistence errors refuse the current operation and leave the live worker stopped; storage must be investigated before replacement.

There is no HTTP unquarantine endpoint. Operators must investigate, freeze affected namespaces/retire the affected set on Solana as appropriate, and follow an explicitly reviewed recovery/reprovisioning procedure. Deleting a latch is not recovery. Root recovery and an independently durable cross-provider incident authority remain outside this local implementation. Native D pairing-wide quarantine journals continue to apply as well.

Multi-suite transport requests, signed backend information and receipts now require protocol version 2. Key derivation and destination public keys do not change. Workers, coordinator and SDK must be upgraded together. Old/missing request versions fail before signing; the tests send an otherwise valid older-version request directly to both workers. Existing Solana registry encodings are unchanged by this lifecycle increment.

## Verification

The program-only process matrix covers D registration, donor preparation, signing start and signature receipt; and RedPallas begin, finish and result. At each stage it cancels a job, kills/restarts the coordinator, and kills/restarts worker A. Five additional cases publish program/CPI freezes before result issuance, require refusal, then unfreeze and verify a fresh attempt. This is 26 stage/action cases using actual worker/coordinator processes and unmodified signing binaries. If a worker dies after producing the signature, a valid complete result is permitted and verified.

The same harness checks duplicate submissions, queued cancellation, SSE, completed-result persistence, no worker calls when fetching cached results, fresh-attempt recovery and native rate-limit backoff. A transport gate exists only in the test executable. The usual account/CPI signing, EVM session, expiry/revocation, substitution, restart and freeze tests remain in the gate.

CI additionally runs the standalone native invariant suite and nine donor lifecycle/fault tests, including native handoff cutoffs with positive/bypass controls, registration process death, donor age/use/generation limits, partial retirement refusal and pairing-wide incident persistence. `research-faults` is enabled only for the isolated test executable; the deployment sidecar is built separately without it. The evidence collector checks expected test counts and all 26 matrix entries to reject an empty/misfiltered test run.

Passing these tests establishes the exercised local lifecycle behavior. It does not establish arbitrary crash/power-loss coverage, independent provider trust, protected entropy, rollback resistance or cryptographic proof obligations.

The final local gate passed: 48 host tests, six SBF runtime tests against rebuilt programs, 15 native invariants, nine native donor lifecycle tests, both complete process demos and all 26 job matrix cases. The native abort limit was observed and its 61-second backoff respected. The standalone Rust client example also passed Clippy with warnings denied. See [public lifecycle evidence](program-jobs-test-evidence.json). The GitHub workflow remains ready locally; no hosted Linux run is claimed.
