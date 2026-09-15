# PATCH 02 — Forward Security: threshold audit + scaling sweep

> Apply after PATCH-01. Two tasks: (A) make the usability threshold NUMBER auditable
> and guarantee the formula, the drawn line, and the verdict logic all use the SAME
> value; (B) add an n ∈ {4,6,8} scaling sweep behind a button. Task A is BLOCKING —
> do it first and re-run before presenting anything, because a wrong threshold flips
> BROKEN/survives labels.

---

## TASK A — Threshold audit (BLOCKING)

### A.1 The problem to fix
The chart's dashed usability line currently sits near ~7 (BROKEN at 6.09, survives at
12.04). But the stated binding formula `sigma / (C * sqrt(log m))` with sigma=4, C=1,
m=72 evaluates to ~1.93, NOT ~7. The formula, the drawn line, and the verdict logic
may be using three different numbers. This MUST be reconciled — the entire
BROKEN/survives verdict pivots on this one value.

### A.2 Single source of truth
There must be exactly ONE function that returns the threshold, and the chart line, the
verdict logic, and the trace note must ALL read from it. No second copy anywhere.

```python
def usability_threshold(params) -> dict:
    import math
    C = float(params.usability_C)          # expose in UI; default state it explicitly
    m = params.m
    sigma = params.sigma
    q = params.q

    log_m = max(math.log(m), 1.0)
    sampling_cap = sigma / (C * math.sqrt(log_m))          # SamplePre width condition
    decode_cap   = (q / 4.0) / (sigma * math.sqrt(m))      # verification decode margin

    cap = min(sampling_cap, decode_cap)
    binding = "sampling" if sampling_cap <= decode_cap else "decode"
    return {
        "threshold": cap,
        "binding_bound": binding,
        "sampling_cap": sampling_cap,
        "decode_cap": decode_cap,
        "C": C, "m": m, "sigma": sigma, "q": q, "log_m": log_m,
    }
```

Note: with defaults (sigma=4, C=1, m=72, q=257):
  sampling_cap = 4 / sqrt(ln 72) = 4 / 2.068 ≈ 1.93
  decode_cap   = 64.25 / (4 * 8.485) ≈ 1.89
So the TRUE threshold ≈ 1.9, binding bound ≈ decode (they're close). **This is far
below the ~7 line currently drawn.** If ~1.9 is correct, then candidates at 6.09 and
6.47 are ABOVE threshold → they should read "survives", NOT "broken". The current
headline may be WRONG. Re-run and see where the labels actually fall.

### A.3 IMPORTANT — do not silently "fix" the threshold to keep the break
Two legitimate possibilities, and you must report whichever is true:

1. **Threshold really is ~1.9** → then at these params even 1-back survives, and the
   honest verdict becomes: *"the trivial transform fails AND LLL does not bring any
   period below the usability bound at n=4 — forward security SURVIVES the attack at
   demo params."* That is a perfectly good, honest finding. Report it. Do NOT inflate
   C or loosen the bound to manufacture a break.

2. **The ~7 line reflects a different, defensible threshold** (e.g. a looser but
   still-justified "basis is usable if gs_norm < sigma*sqrt(m)/something", or you
   decide the decode bound should use a different constant). If so, WRITE DOWN the
   exact definition and why, and use it consistently. But it must be a principled
   choice made BEFORE looking at which verdicts it produces — state the definition,
   then let the labels fall where they fall.

The cardinal rule: **pick the threshold definition on cryptographic grounds, print its
number and derivation, and accept whatever verdicts result.** Never tune it to the
answer you want.

### A.4 Show the derivation on the chart and in the trace
- Draw the binding threshold line, labelled with its numeric value AND which bound
  (sampling/decode) is binding, e.g. `usability ≈ 1.93 (sampling bound)`.
- Optionally draw both caps as two faint lines so the viewer sees the margin.
- Emit a `note` trace event carrying the full dict from A.2 (all sub-values), so the
  exported JSON lets anyone recompute it by hand.
- In the verdict summary block, print one line:
  `threshold = {threshold:.3f}  (binding: {binding_bound}; C={C}, m={m}, sigma={sigma}, q={q})`

### A.5 Re-run and re-read
After A.1–A.4, re-run J=5 and J=8 and report the NEW verdict table. Expect the
BROKEN labels to move (possibly disappear). Whatever happens is the real result.

### A.6 Tests
- `test_threshold_single_source`: the value used by the chart payload, the verdict
  function, and the trace note are byte-identical (assert same float).
- `test_threshold_matches_formula`: usability_threshold(default) == min(sampling,
  decode); assert ≈1.9 for defaults so the number can't silently drift.
- `test_verdict_uses_threshold`: a candidate at threshold*0.99 → broken; at
  threshold*1.01 → survives.

---

## TASK B — Scaling sweep (high value, after Task A)

### B.1 Goal
Answer "does the LLL break survive as n grows, or is it a low-dimension artifact?"
Run low-norm H1 at n ∈ {4, 6, 8} (optionally 10 if fast), fixed J, and measure how
many earlier periods fall below the (audited) usability threshold after LLL.

### B.2 Implementation
```python
def scaling_sweep(J, n_values, base_params):
    rows = []
    for n in n_values:
        p = replace(base_params, n=n)          # m re-derives from n
        chain, lost_at, thr = build_chain_with_health(J, "low_norm", p)
        broken = []
        for i in range(J-1):                    # each earlier period
            cand_lll_gs = recover_and_lll(chain, i, p)   # audited, balanced, in-lattice
            if cand_lll_gs <= thr:
                broken.append({"periods_back": J-1-i, "after_lll_gs": cand_lll_gs})
        rows.append({
            "n": n, "m": p.m, "threshold": thr,
            "num_broken": len(broken),
            "broken": broken,
            "min_after_lll": min([b["after_lll_gs"] for b in broken], default=None),
            "runtime_s": ...,
        })
    return rows
```
- Keep J modest (e.g. 6) so n=8 stays fast. Time each n; if a step exceeds ~10s, stop
  and report partial results with a note rather than hanging the UI.
- Reuse the SAME audited threshold function — do not introduce a second bound here.

### B.3 UI — behind a "Run scaling sweep" button (it's slower)
- A line/bar chart: x = n, y = number of periods broken after LLL (and a second series
  = min after-LLL norm vs threshold).
- A small table: n, m, threshold, #broken, min after-LLL norm, runtime.
- A one-line auto-generated verdict:
  - if #broken decreases toward 0 as n grows →
    "Break shrinks with dimension — consistent with a low-dimension (LLL) artifact;
     forward security likely holds at secure parameters. Reported honestly."
  - if #broken stays flat/grows →
    "Break persists across tested dimensions — stronger evidence of a structural
     forward-security weakness. Still requires BKZ at cryptographic n to confirm."
  - Always keep the existing n=4 / BKZ caveat banner.

### B.4 Honesty
This sweep is the most likely thing to CHANGE your headline. Whatever the trend, the
UI states it plainly. "The break is a low-dimension artifact" is a perfectly strong,
honest finding — arguably stronger than a fragile break, because it shows you tested
scaling instead of overclaiming from a single n.

### B.5 Test
- `test_scaling_sweep_runs`: returns one row per n with well-formed fields; threshold
  identical across rows (same params except n); num_broken monotone-or-reported.

---

## Order of operations
1. TASK A fully (blocking) → re-run J=5, J=8 → record the real verdicts.
2. Only then TASK B → run the sweep → record the trend.
3. Update the Finding-2 verdict summary to reflect BOTH the audited single-n result
   and the scaling trend. Every number sourced from measured runs.
