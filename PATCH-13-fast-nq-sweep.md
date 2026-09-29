# PATCH 13 — Fast (n, q) sweep: both attacks, correctness-gated, small q set

> Builds on PATCH-11 (2D sweep + companion-matrix H2) and PATCH-12 (locked
> implementation + correctness gate). This is the trimmed, fast version: sweep (n, q)
> directly with a small q list, run BOTH attacks per cell, gate every cell on
> correctness. m is DERIVED per cell (m = 2n·ceil(log2 q)); it is NOT an axis and NOT
> user-tunable — it just follows q.

---

## 0. Grid (small & fast)

- `n_values = [4, 8]`                 # n=6 excluded: needs companion-matrix H2 (PATCH-11 §A), not implemented. Only powers of 2 supported at these q.
- `q_values = [257, 1153, 4099]`      # all prime; ~8, ~11, ~12 bits
- `m` per cell = `2 * n * ceil(log2(q))`  — DERIVED, recomputed per cell, displayed.
- `J = 4` (short chain — the point is the (n,q) boundary, not deep periods).
- `repeats = 2`, modest records/period (use the value that fixed the earlier
  small-DB artifact, ~40).
- Hard per-cell timeout ~90s so the whole 3×3 grid finishes fast (minutes, not hours).

Note: n ∈ {4, 8} only (both powers of 2), so the EXISTING H2 works — no companion-matrix
H2 (PATCH-11 §A) needed. n=6 is out of scope here (would require that H2 fix). Do not
implement PATCH-11 for this run.

---

## 1. Per cell: derive m, gate correctness, then both attacks

For each (n, q):

1. **Derive m** = 2·n·ceil(log2 q). Recompute here — never reuse a global/cached m.
   Assert m >= 2*n*log2(q). Store m in the cell record and show it in the UI.
2. **Correctness gate (PATCH-12 §2), all five checks:** A·T≡0; matching→1/non-matching
   →0; honest search returns correct N0; decrypt round-trips; honest period AND word
   basis < usability threshold. Plus the new m-check:
   `m == 2*n*ceil(log2 q)` and `m >= 2*n*log2(q)`.
   If ANY check fails → cell = `"n/a (honest incorrect)"`; do NOT run/report attacks.
3. **Attack 1 — public-key-only** (no secret, no TrapGen): basis from pk + q·I → BKZ →
   trapdoor → search frozen CT. Break = same N0.
4. **Attack 2 — stolen-key backward** (sk_J → R^{-1}·sk_J → BKZ → SK*_r|i → trapdoor →
   search). Break = same N0.
5. **Negative control** (fixed): BKZ'd garbage basis must NOT return honest N0. If it
   does → cell = "untrusted".
6. **Verdict** (pk supersedes stolen):
   - not control_ok            → "untrusted"
   - Attack 1 breaks           → "BROKEN (public-key only)"
   - else Attack 2 breaks      → "forward-security break (stolen key)"
   - else                      → "attack failed (secure vs these attacks)"
   - honest gate failed        → "n/a (honest incorrect)"
   - H2 invalid                → "n/a (H2)"
   - timeout                   → "secure(untested): timeout"

Store per cell: n, q, m, threshold, all 5 correctness results, Attack1 (N0_star vs
N0_legit), Attack2 (N0_star vs N0_legit), control result, verdict, runtime.

---

## 2. UI — one grid, m visible

- **Grid heatmap:** rows = n (4, 8), cols = q. Cell shows the VERDICT colour AND, in
  small text, `m=<value>` for that cell — so you can SEE m grow left→right as q grows
  (e.g. n=4: m=72 → 88 → 96 across q=257,1153,4099). This directly shows the
  m-follows-q relationship you asked about, without making m an axis.
- Colours: red = public-key-only break; orange = stolen-key break; green = attack
  failed; grey = timeout; hatched = n/a (honest incorrect or H2); amber = untrusted.
- Click a cell → detail: the 5 correctness checks (pass/fail + numbers), then both
  attacks' N0_legit vs N0_star, the control line, and m/threshold for that cell.
- Auto-conclusion (measured, valid cells only):
  > "Over n∈{4,6,8}, q∈{257,1153,4099} (m=2n·⌈log2 q⌉ derived per cell): public-key-only
  > attack breaks {cells} — including q=257; stolen-key adds nothing where pk already
  > breaks. Attack fails/times out at {cells}. Correctness gate passed at {cells},
  > n/a at {cells}. Boundary (if visible) sits near {…}. Demo-scale q; not asymptotic
  > security."
- Keep both attacks visible (as before). Keep standing caveats.

---

## 3. Tests

- `test_m_derived_per_cell`: m == 2*n*ceil(log2 q) for each (n,q); no global cache used
  (run n=4 at q=257 and q=4099, assert different m).
- `test_m_lower_bound`: m >= 2*n*log2(q) every cell.
- `test_correctness_gate_per_cell`: a cell failing any of the 5 checks is n/a and its
  attacks are excluded.
- `test_both_attacks_run_per_valid_cell`: valid cells have Attack1 and Attack2 results.
- `test_pk_supersedes_stolen`: pk break → verdict "public-key only".
- `test_control_reduced_garbage_fails`: BKZ'd garbage → not honest N0.
- `test_h2_valid_for_grid`: H2 differences invertible for all (n,q) in the grid
  (n∈{4,8}, powers of 2 — the existing H2 handles these).

---

## 4. Order
1. Per-cell m derivation (m = 2n·ceil(log2 q)) + the m checks added to the correctness
   gate. (No H2 change needed — n∈{4,8} are powers of 2.)
2. Run correctness gate per cell; only passing cells proceed to attacks.
3. Both attacks + fixed control + pk-supersedes-stolen verdict per cell.
4. Grid UI showing verdict + m per cell; click-through detail; auto-conclusion.
5. Run the 2×3 grid (n∈{4,8}, q∈{257,1153,4099}; fast, per-cell timeout 90s).
Report: the grid image (verdict + m per cell), the correctness pass/fail per cell, and
the two attacks' per-cell N0 comparison. Confirm m grows with q.
