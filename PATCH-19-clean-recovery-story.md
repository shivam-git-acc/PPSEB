# PATCH 19 — Clean recovery story: what actually determines break vs no-break

> The current per-period display shows basis GS-norm, which does NOT predict recovery
> (observed: GS 6.08 recovered, GS 5.33 did not). That's because GS-norm is only a
> DISTRIBUTIONAL bound; recovery is decided by the REALIZED trapdoor norm ‖Trap‖ and the
> ciphertext DECODE MARGIN. This patch measures the right variables, kills the sampling
> noise, and produces a clean recovery-rate curve — turning the "inconsistent norm"
> puzzle into a mechanistic finding.
>
> Applies to the attack code (public-key AND stolen-key) and adds an analysis panel.
> Reuses locked implementation (PATCH-12). Honesty rules unchanged (same-N0 success,
> frozen DBs, negative control, timeouts ≠ secure).

---

## 1. Measure the RIGHT variables (per attack attempt)

For every trapdoor the attacker tests, record:
- `trap_norm` = ‖Trap‖ of the REALIZED sampled trapdoor vector (balanced reps). NOT the
  basis GS-norm — the actual vector that goes into Verify.
- `decode_margin` = `floor(q/4) − max_i |y_i − floor(q/2)|` where `y = CT1 − Trap^T·CT2`.
  Positive margin → Verify decodes correctly (match possible); negative → fails. This is
  the continuous quantity that actually decides success.
- `basis_gs` = the basis GS-norm (keep it — to SHOW it does NOT predict recovery).
- `recovered` = (N0_star == N0_legit) as before.

So each attempt yields (basis_gs, trap_norm, decode_margin, recovered). basis_gs is the
old proxy; trap_norm / decode_margin are the true predictors.

---

## 2. Kill the sampling noise (rate, not coin flip)

- **records_per_period ≥ 30** (up from 0–1). Enough targets that per-period recovery is
  a stable fraction, not a coin flip.
- **Multiple trapdoor samples per (period, keyword): SAMPLES ≥ 50** (e.g. 100). SamplePre
  is randomized; sample many trapdoors and compute a RECOVERY RATE = fraction of samples
  that decode correctly, plus the distribution of trap_norm / decode_margin over samples.
- **repeats ≥ 3** for the whole period build (different frozen DBs) to average out DB luck.
- Report recovery RATE per period (e.g. 0.82), not a single yes/no. A rate is smooth and
  plottable; a single outcome is not.

---

## 3. The clean plots (the deliverable)

**Plot 1 — recovery rate vs realized trap_norm.** x = trap_norm (binned), y = fraction of
attempts that recovered. Expect a clean monotone drop → a sigmoid crossing where trap_norm
pushes decode_margin negative. THIS is the law: recovery is controlled by realized
trapdoor length.

**Plot 2 — decode_margin distribution, recovered vs failed.** Two histograms
(recovered attempts, failed attempts) over decode_margin. Expect clean separation at
margin = 0: recovered cluster at positive margin, failed at negative. This is the
mechanistic proof — the margin is the deciding line.

**Plot 3 — the falsification: recovery vs basis_gs.** Same y (recovery rate), x = basis
GS-norm. Expect NO clean separation / non-monotone (this reproduces the 6.08-recovers-
5.33-doesn't puzzle). Caption: "basis GS-norm does not predict recovery — it is only a
distributional bound; the realized trap_norm (Plot 1) and margin (Plot 2) do."

Show Plots 1–3 together: two variables that predict cleanly, one (the old one) that
doesn't. That contrast IS the clean story.

---

## 4. Optional — the monotone sweep (strongest version)

Deliberately vary the sampling width σ used to generate trapdoors (attacker side) across
a range, holding parameters fixed. As σ grows, trap_norm grows, decode_margin shrinks,
recovery rate should fall smoothly 1 → 0. Plot recovery rate vs σ. A smooth curve from
"always recovers" to "never recovers" is the cleanest possible demonstration that
recovery is governed by trapdoor length crossing the decode threshold — a controlled
law, not anecdotes. (Keep it honest: this is about the decode/usability mechanics, not a
claim about the scheme's asymptotic security.)

---

## 5. The clean statement (auto-filled from measured data)

> "Recovery is governed by the REALIZED trapdoor norm and the ciphertext decode margin,
> not the basis GS-norm. Over {records_per_period} records × {SAMPLES} trapdoor samples ×
> {repeats} repeats: recovery rate falls monotonically as realized trap_norm rises
> (Plot 1), and recovered vs failed attempts separate cleanly at decode_margin = 0
> (Plot 2). Basis GS-norm does not predict recovery (Plot 3), explaining earlier
> single-shot anomalies (e.g. GS 6.08 recovered while GS 5.33 did not) as sampling
> variance on the wrong variable. Break occurs iff a sampled trapdoor keeps the decode
> margin positive; at the paper's parameters this happens with high probability at
> LLL-level effort."

Every number from measured runs. Keep the standing caveats (demo params; one attack
family; same-N0 success criterion).

---

## 6. UI

- In the attack result rows (Network tab + the demo tabs), REPLACE the shown "attack
  basis GS x.xx" with "recovery rate r%, mean ‖Trap‖ t, mean margin m" — the variables
  that matter. Keep basis_gs available in a details expander (labelled "distributional
  bound — does not predict recovery; see analysis").
- New "Recovery Analysis" panel (or a section in an existing analysis tab) holding
  Plots 1–3 and the optional σ-sweep, with the auto-statement.

---

## 7. Tests

- `test_records_metrics_trapnorm_margin`: each attempt records trap_norm and decode_margin.
- `test_recovery_is_rate`: per-period recovery is a fraction over SAMPLES, not a bool.
- `test_margin_separates`: over a run, recovered attempts have decode_margin > 0 and
  failed have decode_margin <= 0 (assert the separation holds — the mechanistic claim).
- `test_trapnorm_predicts_better_than_gs`: correlation(recovery, -trap_norm) is stronger
  than correlation(recovery, -basis_gs) on the measured data. (Quantifies "trap_norm is
  the right variable.")
- `test_sigma_sweep_monotone` (if §4 built): recovery rate is (weakly) monotone
  decreasing in σ.

---

## 8. Order
1. Record trap_norm + decode_margin per attempt (public-key AND stolen-key paths).
2. Bump records_per_period≥30, SAMPLES≥50, repeats≥3; compute per-period recovery RATE.
3. Plots 1–3 (recovery vs trap_norm; margin histograms; recovery vs basis_gs falsifier).
4. Optional σ-sweep (Plot 4) for the monotone law.
5. Swap the UI display from basis_gs to rate/trap_norm/margin; basis_gs to a details expander.
6. Auto-statement from measured data.
Report: Plot 1 (recovery vs trap_norm), Plot 2 (margin separation), Plot 3 (basis_gs
does NOT predict), and the correlation numbers from test_trapnorm_predicts_better_than_gs.
