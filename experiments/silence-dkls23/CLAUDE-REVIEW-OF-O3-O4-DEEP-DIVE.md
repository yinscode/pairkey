# Claude review of O3-O4-DEEP-DIVE.md

2026-10-11. Reviewed [O3-O4-DEEP-DIVE.md](O3-O4-DEEP-DIVE.md) and its parent
[FOCUSED-OT-POOL-COMPOSITION-REVIEW.md](FOCUSED-OT-POOL-COMPOSITION-REVIEW.md) as committed in
`f4e9a7c`, with the probe sources, outputs and manifest in `review-evidence/`. Also re-checked
[OT-POOL-MINIMAL-REVIEW-SPEC.md](OT-POOL-MINIMAL-REVIEW-SPEC.md), whose only change since my review
in [CLAUDE-REVIEW-OF-MINIMAL-SPECS.md](CLAUDE-REVIEW-OF-MINIMAL-SPECS.md) is the link to the focused
review; that review stands, with two additions in section 5 below. Every claim marked verified was
checked against the pinned source, the audit text or the SoftSpokenOT chapter text extracted today.
Both probes were rerun independently in my isolated snapshot of `73f318a`, whose code equals HEAD.
No exploit asserted; no code, parameter or dependency change proposed.

## 1. Verdict

Sound, and it moves the O3 and O4 discussion to the right place. Its two results hold: the
selective-acceptance probe is correct, reproduces, and is the SoftSpokenOT selective-abort leakage
at the base-OT level, shared with native DKG; and the O4 transition table matches the code, with the
channel probe exercising the real channel. The remaining O3 lemma is stated precisely and is the
right question for Silence. My refinements concern how the leakage is named, what single use
changes about it, the statistical strength of the committed probe run, and two wording points.

## 2. Claims checked

| Claim in the deep dive | Source | Result |
|---|---|---|
| The native receiver decodes only the chosen branch | `endemic_ot.rs:239-269`, `m_b_values[random_choice_bit]` | verified |
| The native sender decodes both receiver points, so the mirror attack on the sender is not available | `endemic_ot.rs:134-180` | verified |
| The probe's mutation hits branch 0 of base OT 0 | `EndemicOTMsg2 { m_b_list: [[PointBytes; 2]; LAMBDA_C] }`, `repr(C)`, `endemic_ot.rs:38-44` | verified |
| An accepted setup reveals that the first base choice was 1 | `all_but_one.rs:121-180, 229`: `random_choices[j]` is `y*`, built from the complemented choice bits with the first as the high bit, so `& 8 == 0` means choice 1 | verified |
| The pool maps the decode error to a peer violation; native DKG calls the same function | `src/pool_worker.rs:168`; `keygen/dkg.rs:540-543` maps it to `InvalidMessage`, which the lifecycle treats as a violation | verified |
| SoftSpokenOT separates PPRF consistency, Theorem 6.2, from output conversion, Theorem 5.1 with a TCR hash assumption, and models selective aborts as guess sets with abort notification, including against the base-OT receiver | chapter text, Theorem 5.1 and 6.2 statements, selective-abort paragraph and figure 1 caption | verified |
| TOB-SILA-13 partially resolved; fix commits replaced MtA with the RVOLE protocol reviewed in Appendix F | audit fix review, printed pp. 58-63 | verified |
| Zero masks are `±Reduce(H(label, seed, D, label))` with `D = digest_i`; both coins are in the completed transcript, which the package id commits to | `sign/dsg.rs:169-183, 234, 876-914`; `src/pool.rs:273-289, 243-248` | verified |
| The channel probe exercises the real exchange | `Wire::receive` reads `control`, `src/wire.rs:63-72`, so the crossed queues carry the actual frames; the asserted kind and action match `src/wire.rs:318-329` | verified |
| O4 transition table | my own row-by-row review in [OT-POOL-REVIEW.md](OT-POOL-REVIEW.md) | consistent |

## 3. Independent rerun

Both probes were copied unchanged from commit `f4e9a7c` into my isolated snapshot of `73f318a`, whose
code equals HEAD, with the same native pin, locked dependencies and the warm build cache from the
earlier isolated suite run. Command: `cargo test --locked --offline --features research-faults`, the
o3 probe as an integration test and the o4 probe as a child module of `wire.rs` at
`src/wire/o4_setup_channel_probe.rs`. Two strengthened o3 variants with fixed trial counts and an
assertion on every accepted setup ran alongside; the 64-trial source is
`review-evidence/o3_selective_abort_probe_ext.rs`, the 256-trial run differs only in the count.

```
o3 probe:  Observed 1 accepted PPRF setup(s), all with first base choice 1; 1 typed decode rejection(s).  ok
o3 x64:    64 trials: 41 accepted (all with first base choice 1), 23 decode rejections.  ok
o3 x256:   256 trials: 120 accepted (all with first base choice 1), 136 decode rejections  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 395.39s
o4 probe:  2 matching-context controls succeeded; 20 context/phase mutations rejected on both sides with typed Burn/Context errors.  ok
```

All passed. The multi-trial variants remove the one-sample weakness noted in section 4, item 3: had
the packing claim been wrong, about half of the accepted setups would have failed the assertion. The
64-trial split of 41 to 23 is about two standard deviations from even, which is plausible chance at
that sample size; the 256-trial run is included to check that the first base choice bit is unbiased,
since a biased choice bit would be a finding of its own. Its result, 120 accepted to 136 rejected, is
consistent with a fair bit, so the earlier skew was chance. Log with provenance:
`review-evidence/o3_o4_probes_claude_rerun.output.txt`.

## 4. Refinements and requested changes

1. **Name the leakage precisely.** The honest receiver's base choice is uniform; what the probe
   shows is the adversary's knowledge conditioned on acceptance. In the paper's model this is a
   selective-abort guess on the receiver's secret output, and the receiver here is the party that
   becomes the extension sender holding the correlation secret. A wrong guess aborts and, in the
   pool, quarantines; a right guess costs nothing and leaks one bit of that setup's secret. Saying
   "biased hidden choices" risks suggesting the honest distribution is wrong. Suggested wording:
   leaky correlation secret under the paper's guess-set model, shared with native DKG.
2. **Single use changes the value of a successful guess.** With one entry per signature, a lucky
   guess leaks a bit of a correlation secret that serves exactly one extension. Under Silence's
   per-keyshare reuse, lucky guesses accumulate against the same secret across every signature under
   that key. Both are bounded by quarantine on the first wrong guess. This is an argument for
   per-attempt freshness, whether by migration per attempt or by a pool, and against long reuse. It is
   a trade-off note for the decision record, not a parameter recommendation and not a defect in the
   native model, whose security bound is meant to absorb this leakage.
3. **Statistical strength.** The committed run stopped at the first accepted sample, so the packing
   claim rested on one observation and would have passed with probability one half even if wrong.
   My variant runs 64 trials and asserts on every accepted one; adopt it or raise the trial count.
4. **O4 table, abort-to-retry row.** "Incident rules remain effective" should read: attributable
   failures publish an incident; timeouts and context disagreements burn without one, as the deep
   dive's own section 2 says.
5. **Zero-mask argument, step 3.** A corrupt party that waits for the honest round-1 message can
   grind its own round-1 session id to choose `D`, and with it the honest mask value, at no abort
   cost. The two-party argument makes this harmless because the mask is a public function both
   parties know, but it is an adaptive query the argument must tolerate, not only the withheld-reveal
   case.
6. **All-honest distribution.** Agreed that it is the wrong target. My results note never claimed
   equality with the all-honest distribution; it said the pool produces material "distributed as native
   DKG's". I have reworded that to equal behaviour under the same adversary, including this leakage.
7. **Paper access.** The SoftSpokenOT chapter is retrievable and its text extracted; the manifest can
   record that the theorem references were checked against it rather than inferred.

## 5. Additions to the pool review specification

- Section 2: name the base-OT selective-abort leakage as part of the setup contract to be assessed,
  with its quarantine-on-failure dependency, and record the single-use versus reuse observation.
- Section 4: require the multi-trial form of the selective-acceptance probe and a role-swap case in
  the channel matrix, both parties claiming the same role under one context.

## 6. Paste-ready TL;DR for Astra

Reviewed O3-O4-DEEP-DIVE.md and the focused review against the pin, the audit text and the
SoftSpokenOT chapter text. Both results hold and both probes reproduce independently in my snapshot,
including a 64-trial variant that asserts the first-choice property on every accepted setup. The
packing claim, the message layout, the single-branch decode, the pool and native error mappings, the
theorem split and the fix-review wording are all verified. Refinements: call the probe result leaky
correlation secret under the paper's guess-set model rather than biased choices; note that single use
limits a lucky guess to one extension while per-keyshare reuse accumulates them, bounded in both
cases by quarantine on the first wrong guess; the committed probe rested on one accepted sample;
qualify the abort-to-retry row since burns publish no incident; add the free round-1 grinding of D to
the zero-mask argument. My notes now say "same behaviour under the same adversary" instead of "same
distribution". The pool spec review stands with two additions: the leakage in section 2 and the
multi-trial and role-swap cases in section 4.
