# PATCH 09 — Fix the word-basis trust check (relative, honest-doctor-calibrated)

> Apply BEFORE launching the overnight sweep (PATCH-08). Fixes a real bug in the
> word-basis trust gate introduced by PATCH-06 §6.5.
>
> BUG (found in the PATCH-08 test run): the word-basis check compared the WORD-basis
> Gram-Schmidt norm against the PERIOD-basis usability threshold. Word bases are
> legitimately larger (NewBasisDel grows the norm), so the check marked the HONEST
> doctor's own word basis "unusable" in ~10/10 periods — even though the doctor's
> search demonstrably worked in all of them. Consequence: every break got stamped
> "untrusted" and discarded, and the strict gate produced FALSE NEGATIVES (an earlier
> run reported "consistent negative result" after throwing out its only break). This is
> the dangerous direction — the guardrail was rejecting true results.
>
> PATCH-06's instruction "reuse the audited threshold, don't invent one" was WRONG for
> the word basis. Do NOT fix this by inventing a new absolute threshold either. Fix it
> with a RELATIVE test calibrated against the honest doctor, who is known-usable by
> construction.

---

## 1. The correct check — relative to the honest doctor

The honest doctor's word basis IS usable at every period (their search works — that's
ground truth). Use it as the calibration reference. The attacker's recovered word basis
is credible IFF it is not much larger than the honest doctor's word basis at the SAME
period:

```python
WORD_FACTOR = 3.0   # state explicitly; attacker basis within this factor of honest = credible

def word_basis_trust(honest_word_gs, attacker_word_gs, factor=WORD_FACTOR):
    # honest_word_gs is known-usable (doctor's search works). The attacker's basis is
    # "as good as usable" if it's within `factor` of the honest one at this period.
    approved = attacker_word_gs <= factor * honest_word_gs
    return {
        "approved": approved,
        "honest_word_gs": honest_word_gs,
        "attacker_word_gs": attacker_word_gs,
        "ratio": attacker_word_gs / honest_word_gs if honest_word_gs > 0 else float("inf"),
        "factor": factor,
    }
```

- Both norms are the balanced-representative GS-norms of the WORD basis (post
  NewBasisDel), one for the attacker's `SK*w|i`, one for the honest `SKw|i`.
- This is self-calibrating: no absolute threshold, no calibration guesswork. It asks
  "is the attacker's basis comparable to the one that provably works," which is exactly
  the right question.

---

## 2. Where it plugs into the trust gate

The per-cell / per-period trust decision (PATCH-07/08) becomes:

```python
trusted_break_at_period = (
    level2_search_break              # same N0 on the frozen DB
    and negative_control_failed      # garbage basis did NOT match (per cell)
    and word_basis_trust(honest_word_gs_i, attacker_word_gs_i)["approved"]
)
```

- `l2_matches_wordpred` from PATCH-06 is now defined via this relative approval, not
  the old absolute threshold: prediction "usable" == `word_basis_trust(...).approved`.
- A period counts as a trusted break only if all three hold. A survives verdict still
  requires the negative control to have failed (trustworthy) and no trusted break.

---

## 3. MANDATORY verification before the sweep

Re-run the PATCH-08 test data (or a fresh small run at n=4, J=4) and CHECK:

- **The honest doctor's word basis is approved in ~all periods.** With the relative
  check, `word_basis_trust(honest, honest)` is trivially approved (ratio 1.0 ≤ factor),
  and honest-vs-honest must be ~10/10. If the honest basis is still marked unusable,
  the check is STILL wrong — do not proceed.
- **Report the approval rate for the honest doctor** in the Results view (it should be
  ~100%). This is the sanity light: if it ever drops well below 100%, the trust gate is
  miscalibrated again and its verdicts must not be believed.
- **Re-examine the two cells that broke under controls-only.** With the fixed check, do
  they now register as TRUSTED breaks (attacker ratio within factor) or do they get
  excluded (attacker basis genuinely much larger than honest)? Either outcome is fine —
  but now it's a MEANINGFUL distinction instead of a blanket rejection. Report the
  ratios for those cells.

---

## 4. Headline gate decision (resolves Claude Code's question)

Once §3 passes (honest approval ~100%), **strict becomes correct and is the headline
default.** Rationale: strict now = "same N0 AND negative control failed AND attacker
basis comparable to the known-usable honest basis" — a genuinely corroborated verdict,
no longer a false-negative machine.

- Keep "negative controls only" as a secondary view for transparency (shows what the
  word-check adds/removes).
- The conclusion generator still uses TRUSTED cells only, and still refuses to claim a
  negative result while any break is excluded *solely* by the word-check — but now that
  exclusion is a real signal (attacker basis too degraded), not an artifact. Keep the
  excluded-breaks list visible with ratios.

---

## 5. Tests

- `test_word_check_relative_not_absolute`: honest-vs-honest word basis is always
  approved (ratio 1.0 ≤ factor), regardless of n or m. This is the regression test for
  the exact bug found.
- `test_honest_approval_rate_high`: on a real run, honest doctor's word basis approved
  in ≥ ~90% of periods (ideally 100%).
- `test_trusted_break_requires_all_three`: a break with a huge attacker/honest ratio
  (> factor) is excluded; one within factor + control-failed + same-N0 is trusted.
- `test_wordpred_uses_relative`: l2_matches_wordpred is computed from word_basis_trust,
  not from any absolute period threshold.
- `test_excluded_break_list_has_ratios`: breaks excluded by the word-check appear with
  their attacker/honest ratio, so morning-you can judge them.

---

## 6. Order
1. Replace the word-basis check with the relative `word_basis_trust` (§1).
2. Rewire the trust gate and l2_matches_wordpred to use it (§2).
3. Run §3 verification: confirm honest approval ~100%; report the two prior break
   cells' ratios. DO NOT launch the sweep until honest approval is ~100%.
4. Surface honest-approval-rate and excluded-break ratios in the Results view.
5. Keep strict as headline default; controls-only as secondary.
6. Then use the n=4,8 grid fix and launch the overnight sweep.
Report: honest approval rate, the two cells' attacker/honest ratios under the fixed
check, and confirmation that strict no longer produces a false "no break".
