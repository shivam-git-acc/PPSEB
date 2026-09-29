# PATCH 15 — Wide security-boundary run + stolen-key attack on the same axis

> Extends PATCH-14. Two additions: (1) use the available compute (hours) to run a WIDER
> (n,q) grid with higher BKZ blocks and longer timeouts, so cells resolve to broke /
> attack_failed instead of dumping into the useless "timeout" bucket; (2) add the
> STOLEN-KEY (forward-security) attack ON THE SAME bit-security x-axis, judged relative
> to the public-key-only attack.
>
> Reuses PATCH-12 locked implementation, PATCH-14 security estimate + public-key attack,
> PATCH-08 persistence/resume. Overnight-friendly.
>
> HONESTY: the stolen key only "provides a forward-security break" if it succeeds where
> the PUBLIC-KEY-ONLY attack does NOT. Same-N0 on frozen DB; negative control (BKZ'd
> garbage) must fail; timeouts are "unmeasured", never "secure"; scope claims to
> measured vs estimated.

---

## 1. Wider grid (use the hours)

- n ∈ {4, 8, 16}      (16 pushes into higher security — likely the boundary)
- q ∈ {257, 1153, 4099, 12289, 40961}   (all prime; ~8 … ~16 bits)
- σ from the scheme's setting (state it), m = 2n⌈log2 q⌉ derived per cell.
- Skip only cells that fail the correctness gate (PATCH-12) or H2 (n∈{4,8,16} are all
  powers of 2, so existing H2 is fine — no PATCH-11 needed).
- Per-cell HARD timeout: raise to 20–40 min (you have hours). A BKZ block ladder up to
  a high beta (e.g. up to 40–50) per cell. The goal: each cell should either BREAK or
  run the ladder to completion (attack_failed) — minimise "timeout".
- Total budget: set an overall wall-clock cap (e.g. 8–10h) with checkpoint-and-stop.
- repeats = 1 for the big cells (deterministic-ish given seed), 2 for the small fast
  ones. State per cell.

Persistence (PATCH-08): append each cell to results/secbound_<id>.jsonl, resume on
restart, per-cell try/except, background job. You can close the tab.

---

## 2. Add the stolen-key attack per cell (same axis)

For each (n, q) that passes correctness, run BOTH attacks and record both:

**Attack 1 — public-key-only** (PATCH-14): basis from pk + q·I → BKZ ladder → trapdoor →
search frozen CT. `pk_broke`, `pk_beta`, `pk_runtime`, `pk_timed_out`.

**Attack 2 — stolen-key backward** (PATCH-06/12): steal sk_J, compute R^{-1}·sk_J → BKZ
ladder → SK*_r|i → trapdoor → search frozen CT_i (i earlier). `stolen_broke`,
`stolen_beta`, `stolen_runtime`, `stolen_timed_out`. Attacker reads ONLY sk_J + public.
(Short chain, e.g. J=3–4, one earlier target period — key security, not long chains.)

**Negative control** (fixed): BKZ'd garbage basis → must NOT return honest N0, per cell.

### Per-cell verdict (relative — this is the honest core)
```
if not control_ok:                    "untrusted"
elif pk_broke:                        "BROKEN (public-key only)"     # stolen adds nothing
elif stolen_broke:                    "forward-security break (stolen key REQUIRED)"
elif pk_timed_out or stolen_timed_out:"unmeasured (timeout)"
else:                                 "attack failed (secure vs both, this budget)"
```
The ONLY cell type that demonstrates a genuine forward-security break is
"stolen key REQUIRED" — pk-only failed there but the stolen key succeeded. Count and
highlight those specifically. If there are NONE, that is the honest finding: the stolen
key never helps beyond what the public key already does, at every tested cell.

---

## 3. Plots (both attacks, security axis)

**Plot 1 — dual break-vs-bits:** x = estimated bits (PATCH-14 estimator), two series:
- public-key-only outcome (red=broke / green=failed / grey=timeout)
- stolen-key outcome (orange=broke / green=failed / grey=timeout)
per (n,q) point. The story reads directly: where BOTH are red at low bits → no key
security; where pk is green but stolen is orange → genuine forward-security break; where
both green/grey at high bits → attacks don't win (or unmeasured).

**Plot 2 — the "does the stolen key help?" panel:** for each cell, a 2-state indicator
(pk_broke, stolen_broke). Caption auto-fills: "In {k} of {N} cells the stolen key
succeeded where the public key alone failed (genuine forward-security break); in {m}
cells both broke (stolen key redundant); in {p} cells neither broke within budget."

**Plot 3 — size/time vs bits** (from PATCH-14): trapdoor bytes and honest testing proxy
vs estimated bits, paper's params marked — the efficiency-vs-security tension.

Mark the paper's demo params on all plots.

Auto-conclusion (measured + estimated, scoped):
> "Across n∈{4,8,16}, q∈{257…40961} (est. security {min}–{max} bits, {backend}): the
> public-key-only attack breaks all cells ≤ ~{X} bits, including the paper's parameters
> (~{Y} bits). The stolen-key attack provides a break BEYOND the public key in {k} cells
> {list, or 'no cells'}. {If k==0:} the stolen key never succeeded where the public key
> failed — so at tested parameters 'forward security' is either vacuous (pk already
> breaks) or the stolen-key attack is no stronger than public knowledge. {If k>0:}
> genuine forward-security breaks occur at {those cells}, i.e. pk-secure but
> stolen-key-broken. Cells ≥ ~{Z} bits are unmeasured (BKZ timeout within {T}), not
> proven secure. Demo-scale n; estimator gives the axis, attacks confirm the low end."

---

## 4. Tests

- `test_both_attacks_per_cell`: valid cells carry pk_* and stolen_* fields.
- `test_stolen_reads_only_stolen_sk`: Attack 2 reads only sk_J + public (assert).
- `test_verdict_forward_break_requires_pk_fail`: "forward-security break" verdict only
  when pk_broke==False and stolen_broke==True.
- `test_pk_supersedes_stolen`: pk_broke==True → verdict "BROKEN (public-key only)".
- `test_timeout_not_secure`: timed_out never labelled secure.
- `test_control_per_cell`: BKZ'd garbage fails per cell or cell is untrusted.
- `test_resume_wide_grid`: kill/resume, no double-counted cells.

---

## 5. Order
1. Widen grid + raise timeouts + BKZ block ladder (§1); wire PATCH-08 persistence.
2. Add Attack 2 (stolen-key) alongside Attack 1 per cell; fixed negative control.
3. Relative verdict (§2) — forward-security break ONLY when pk fails but stolen wins.
4. Plots 1–3 + auto-conclusion; mark paper params.
5. Launch overnight (8–10h cap, resume-safe). Discard superseded runs.
Report: dual break-vs-bits plot, the "does the stolen key help?" count, the paper-params
point, and the auto-conclusion with X (measured break ceiling) and any genuine
forward-security-break cells.
