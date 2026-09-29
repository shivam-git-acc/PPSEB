# PATCH 07 — (n, J) sweep of the end-to-end attack

> Apply after PATCH-06. Purpose: replace the single (n=4, J=4) data point with a grid
> sweep over n and J, so the forward-security conclusion rests on a MAP of outcomes,
> not one cell. Runs the FULL PATCH-06 end-to-end attack (frozen DBs, fair BKZ tooling,
> same-N0 Level-2 test, word-basis cross-check, negative control) at every (n, J) cell
> and reports the outcome grid.
>
> FRAMING (honesty): the goal is to CHARACTERIZE the attack across parameters, not to
> confirm it fails. If any cell genuinely breaks (same-N0 AND word-norm agrees AND
> negative control fails), that cell is a real break — report it, do not bury it. A
> map that is "fails everywhere tested" and a map with "breaks in corner X" are both
> valid, publishable results.
>
> GUARDRAILS (all inherited per cell, non-negotiable): frozen DBs; attacker reads only
> stolen sk + public data; Level-2 = same N0; word-basis cross-check must AGREE or the
> cell is flagged "untrusted"; negative control must fail per cell or the cell is
> flagged "untrusted"; verdict from measured data.

---

## 1. The sweep

```python
def sweep_end_to_end(n_values, J_values, params_base, reducer, h1_variant="low_norm",
                     time_budget_s=600, records_per_period=None):
    grid = []
    for n in n_values:
        for J in J_values:
            if J < 2:            # need at least one past period
                continue
            t0 = time.time()
            res = run_end_to_end(n, J, params_base, reducer, h1_variant)  # PATCH-06
            dt = time.time() - t0
            # per-cell trust gates (from PATCH-06 machinery)
            control_ok   = res["negative_control_failed_L2"]      # True = control failed as it should
            wordpred_ok  = all(p["l2_matches_wordpred"] for p in res["per_period"])
            trusted      = control_ok and wordpred_ok
            grid.append({
                "n": n, "J": J, "m": res_m(n),
                "threshold": res["threshold"],
                "L2_broken_periods": res["L2_broken_periods"],
                "L3_broken_periods": res["L3_broken_periods"],
                "any_break": bool(res["L2_broken_periods"]),
                "control_failed_as_expected": control_ok,
                "word_pred_agrees": wordpred_ok,
                "trusted": trusted,
                "runtime_s": round(dt, 1),
                "per_period": res["per_period"],   # keep for drill-in
            })
            if time.time() - t0 was cumulative... enforce total budget:
            if total_elapsed() > time_budget_s:
                mark_remaining_cells_skipped(); break
    return grid
```

- Defaults: `n_values = [4, 6, 8]`, `J_values = [3, 4, 5, 6]` (editable in UI).
- `records_per_period`: use the value that fixed the period-3 artifact (the larger DB
  from the PATCH-06 drill-in, e.g. 20–50). Keep it fixed across the sweep and DISPLAY
  it — a small DB inflates spurious matches, so state the size used.
- TIME BUDGET: BKZ at n=8 is slow (PATCH-03 measured ~38s/period; a J=6 n=8 cell is
  minutes). Enforce a hard total budget; skipped cells render as "skipped (budget)",
  not as "survives". Never report an unrun cell as a pass.

---

## 2. Per-cell trust — a cell's verdict is only valid if BOTH guardrails pass

For each cell, the verdict is one of:
- **survives** — L2_broken_periods empty, control failed as expected, word-pred agrees.
- **BREAK @ periods X** — L2_broken_periods non-empty, control failed as expected,
  word-pred agrees (a TRUSTED break — real, report it).
- **untrusted** — control passed unexpectedly OR word-pred disagreed on any period.
  Do NOT report survives or break for this cell; render it amber "untrusted — inspect"
  and require a drill-in before any claim. (This is what caught the period-3 artifact.)
- **skipped** — time budget.

A cell can only contribute to the headline conclusion if it is `trusted`. Untrusted
cells are shown but excluded from "fails everywhere" / "breaks at X" statements.

---

## 3. UI — outcome grid (Forward Security tab, new "Parameter sweep" panel)

- Inputs: n list, J list, reducer (default bkz), records/period (default = the fixed
  fixed value), "Run sweep" button, plus the time budget.
- Render a HEATMAP / grid: rows = n, cols = J, each cell coloured:
  - grey/green = survives (trusted)
  - red = trusted break (show which periods)
  - amber = untrusted (guardrail disagreement)
  - hatched = skipped
- Cell tooltip/click → the full per-period table for that (n, J): period, periods_back,
  period_gs, word_gs (attacker), threshold, N0_legit, N0_star, L2, L3, word-pred-agree.
- Below the grid, an auto-generated summary from TRUSTED cells only:
  - "Across {k} trusted cells (n∈{...}, J∈{...}, records/period={r}, fair BKZ tooling),
    the end-to-end attack recovered no past period's search capability in {a} cells and
    broke period(s) {..} in {b} cells." Fill from measured data.
  - Keep the standing caveats (demo params; one attack family; L2≠L3).
- Always show: records/period used, reducer, and the count of untrusted/skipped cells
  (transparency — don't hide cells that didn't yield a clean verdict).

---

## 4. What the sweep is allowed to conclude

- If ALL trusted cells survive → "The functional attack fails across all tested
  (n, J) at demonstration parameters — a consistent negative result, not a single
  data point. Cryptographic-parameter behaviour remains open (needs large-n BKZ)."
  This is the strong, honest version of what you're after.
- If SOME trusted cell breaks → report exactly which (n, J, periods). "The attack is
  parameter-sensitive: it fails in most tested cells but recovers period(s) X at
  (n, J) = ... ." A real break in even one trusted cell is a finding — surface it.
- Untrusted/skipped cells are reported as such and excluded from the conclusion.

Do NOT state "fails for all parameters" — you only tested a grid. Say "across all
tested (n, J)". Precision matters here.

---

## 5. Tests

- `test_sweep_grid_shape`: returns one cell per (n, J) with J≥2; skipped cells marked.
- `test_cell_trust_gates`: a cell with control_ok=False or wordpred_ok=False is
  labelled "untrusted" and excluded from the summary counts.
- `test_summary_uses_trusted_only`: the auto-summary's counts include only trusted cells.
- `test_skipped_not_survives`: a budget-skipped cell is never counted as survives.
- `test_records_per_period_fixed_and_shown`: the sweep uses one records/period value and
  it appears in the result payload.
- `test_break_cell_is_real`: any cell reported as BREAK has non-empty L2_broken_periods
  AND control failed AND word-pred agreed (a trusted break).

---

## 6. Order
1. Wrap PATCH-06 `run_end_to_end` in `sweep_end_to_end` with per-cell trust gates.
2. Enforce the time budget; mark skipped cells.
3. Build the grid/heatmap UI with click-through to per-period tables.
4. Auto-summary from TRUSTED cells only; show records/period, reducer, untrusted/skipped counts.
5. Run n∈{4,6,8}, J∈{3,4,5,6} (trim if budget tight); report the grid.
Report the outcome grid image + the trusted-cell summary + any untrusted cells and why.
