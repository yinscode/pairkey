# Claude review of the Spike D proof dossier at `3b065e5`

2026-10-12. Reviewed `SPIKE-D-PROOF-DOSSIER.md` and `review-evidence/donor-proof/checks.py` as
committed at `3b065e5` on `codex/spike-d`, the proof-analysis commit for implementation `0f6e0557`.
Checked against the pinned native source, `sl-oblivious 1.0.0-beta`, DKLs23 eprint 2023/765, the
SoftSpokenOT chapter and eprint 2026/976. The checker was rerun independently; see section 2. No
tracked file in the worktree was changed. The dossier's section 8 corrects my review of `0f6e0557`;
those corrections are accepted and applied in place in
[CLAUDE-REVIEW-SPIKE-D-0f6e055.md](CLAUDE-REVIEW-SPIKE-D-0f6e055.md), with an erratum in its
section 11.

## 1. Verdict

The dossier is correct in substance and more careful than my review was on concrete security. Its
attacker model, the integrity game with digest equivalence modulo the group order, the assumption
table, the statement of the reusable lemma R with its leakage and acceptance-conditioning remarks,
the algebraic identities, the conditional registration argument, the context trace, the small
derivable bounds, the reconciliation paragraph on 2026/976 and the closure list are right as far as I
can check them. It claims nothing it does not support. I add one structural observation that narrows
the first lemma to write, one implementation requirement, and an ordering of the proof work.

## 2. Independently verified

- `checks.py` rerun from the commit against the worktree and the registry package, output to my
  scratch area: algebra identities pass; reduction distances 2^-127.65 for a 256-bit reduce and
  2^-258.08 for a 512-bit reduce; the toy prehash equivalence verifies; the pinned parameters read
  unchanged; Variant III condition at `m = 512` holds for `s = 12` and fails for `s = 13`; minimum
  `m` for `s = 128` is 2656; the 35-bit truncation has right-hand side 511.34 without the dropped
  term and 883.28 with it; 17 source anchors resolve with hashes. Summary saved in
  `review-evidence/dossier-checks-claude-rerun.output.txt`.
- `rvole.rs`: the gadget is derived from the session id before processing, lines 42-50 and 103; the
  theta transcript binds the session id and the correction rows, lines 141-159 and 286-315; the mu
  transcript binds the session id and the chosen values, 197-225 and 331-345. No OT transcript enters
  either, as the dossier states.
- 2026/976 section 4.5: the attack has the corrupt VOLE sender sample the correction matrix, derive
  the challenge from it, choose inconsistent rows whose inner products with the challenge coincide,
  and then choose its OT inputs to match. It requires choosing OT outputs after the challenge, which the
  endemic hybrid permits. The paper's countermeasures are hashing a committing OT transcript into the
  challenge, or Sender Random OT.
- The 64-trial primitive rerun recorded in the proof manifest, 31 accepted and 33 rejected with every
  accepted setup revealing the targeted bit, matches my own 256-trial run.

## 3. Corrections to my review, accepted

| Dossier point | Disposition |
|---|---|
| The 12 is what the sufficient inequality supports, not a margin estimate or an attack rate | Accepted; section 8 of my review rewritten |
| The 35-bit alternative drops a mandatory term | Accepted and withdrawn; the term wraps to the next line in the table |
| Statistical distance and inconsistent-product acceptance are separate targets | Accepted; experiment 1 split in two |
| A7 is a realization assumption, not a conclusion from structural tests | Accepted; stated in the erratum |
| Field separation is not statistical independence; one PRG stream | Accepted; section 4 reworded |
| Fresh ids do not make shared-seed sessions independent; a history-uniform simulation bound is required | Accepted; consistent with L1 as stated |
| The peer's adaptive lever is not only the mask; a simulator is required | Accepted; section 6 narrowed to the session-id and mask domains |
| Quarantine cannot prevent a first success | Accepted; the cap wording replaced |
| The hedge does not survive simultaneous restoration of context, counter and entropy | Already stated; agreed |
| Prehash equivalence modulo the order | Accepted and added as an implementation requirement, section 5 |

## 4. Refinements

1. **The section 4.5 attack does not transfer to the compiled stack as stated, and that narrows the
   first lemma.** In `RVOLESender::process` the sender's extended OT outputs are computed by
   `SoftSpokenOTSender::process` at line 256 from two inputs fixed before the challenge exists: its
   base-OT material, fixed at donor time before any session id, and the receiver's matrix, received
   in round 1. The correction rows and theta follow at lines 289 to 317. A corrupt base-OT sender may
   have chosen its pads adaptively at donor time, since endemic OT permits that, but it cannot choose
   them after theta. So the adaptivity the attack needs is absent, and the lemma to write is the
   output-fixing premise of Claim 6.7 for the SoftSpoken realization: that the sender's extended outputs
   are committed by setup material and the receiver's round-1 message before theta is derived. This is
   smaller than a full reconciliation, it is local to the compiled code, and it restores the
   applicability of Theorem 6.1 in the paper's own hybrid. The leftover-hash dimension question is
   separate and remains open.
2. **Order of proof work.** I would start with that fixing-order lemma, then the registration
   simulator, then the known-seed zero-mask realization, then the public-tweak signing game, and only
   then the reuse lemma R and the dimension reconciliation, both of which belong to Silence. The
   dossier starts with registration; either order is defensible, mine puts the smallest unlocking
   lemma first.
3. **Joint KDF assumption.** The identity and contribution derivations share the root as HKDF input
   under different salts and hash functions. The joint pseudorandomness the dossier asks for follows
   from treating HKDF-Extract with distinct salts as a dual-PRF of the input keying material, which is
   the standard HMAC assumption; stating it that way makes the assumption concrete.
4. **Receiver grinding of the extension challenge.** In the one-message SoftSpoken variant the receiver
   fixes the challenge through the hash of its own matrix, and its padding bits give it freedom to
   grind. At `S = 128` this is a negligible advantage, but the fixing-order lemma should say so
   explicitly, since it is the mirror image of the sender-side question.
5. **Nothing in the dossier changes the route recommendation.** The donor route stays an experiment
   pending the lemmas; the implementation requirements below are additions for Sol.

## 5. Implementation requirements that follow

- Refuse a prehash at or above the group order at request validation, and key every journal or claim
  that mentions a message by the digest reduced modulo the order, not by the raw 32 bytes. Add a test
  with `h` and `h + q` showing the second is refused. For random hashes the case has probability about
  2^-128; the point is adversarially chosen requests and claim hygiene.
- Keep the research-fault commands compiled out of any build that makes a security claim; the
  dossier's fault-controls assumption deserves a build-level guard rather than a runtime check.
- The experiment plan of the dossier's section 8 is the right one: a named corrupt role, an explicit
  admissible algorithm, the unmodified honest endpoint, separate consistency and distribution
  questions, and no inferred success rate used as a prediction.

## 6. Paste-ready reply for Sol

Reviewed the dossier at 3b065e5; it is correct in substance and more careful on concrete security
than my review was. Your section 8 corrections are accepted and applied in place in my 0f6e055
review with an erratum: the 35 is withdrawn, the 12 is what the sufficient condition certifies and not
a margin or an attack rate, distribution and consistency are separate targets, A7 is an assumption,
independence is pseudorandomness of one PRG stream, the peer's lever is confined to the session-id
and mask domains only, quarantine bounds expected successes and cannot prevent a first one. I reran
checks.py from the commit and reproduce every number, confirmed the theta and mu transcripts bind only
session id and correction rows, and read section 4.5. One addition: that attack needs the VOLE sender
to choose OT outputs after the challenge, and in the compiled code the sender's extended outputs are
fixed by donor-time base-OT material and the receiver's matrix before theta, so it does not transfer as
stated; the first lemma to write is the output-fixing premise of Claim 6.7 for the SoftSpoken
realization, which is local and restores Theorem 6.1 in the paper's own hybrid. The dimension question
stays separate. Two requirements for the code: refuse prehashes at or above the group order and key
message claims by the reduced digest; compile the fault commands out of any security build. Proof
order I suggest: fixing-order lemma, registration simulator, known-seed zero mask, public-tweak game,
then R and the dimension reconciliation with Silence.
