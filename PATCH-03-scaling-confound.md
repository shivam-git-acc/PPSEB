# PATCH 03 — Resolve the forward-security scaling confound (time-boxed, with fallback)

> Apply after PATCH-02. Goal: make the dimension-scaling sweep TRUSTWORTHY by keeping
> the *legitimate* key chain usable at n = 6, 8, so that `#broken` measures attack
> difficulty rather than "nothing left to break."
>
> This is the fiddly part of the project. Work the levers IN ORDER and STOP at the
> first one that keeps the legit chain usable across n ∈ {4,6,8}. Do NOT jump to the
> hard lever. There is a hard fallback (§4) that is a perfectly acceptable result.
>
> HONESTY GUARDRAILS (unchanged, non-negotiable):
> - Never tune a parameter to manufacture or hide a break. Fix the confound on
>   theoretical grounds only; accept whatever verdict results.
> - Every threshold/verdict still comes from the single audited source (PATCH-02 §A.2).
> - If the confound cannot be removed within the time budget, ship the fallback and
>   SAY it's a fallback.

---

## Diagnosis (state this in the module docstring)

The legit basis Gram-Schmidt norm grows with m; the usability threshold
`σ/(C·√log m)` (sampling bound) rises only ~1/√log m. So as n (hence m) grows, the
legit basis outruns the threshold and `correctness_lost_at` triggers BEFORE any attack.
`#broken → 0` at n≥6 is therefore contaminated. We must keep the legit chain usable
across dimensions so the sweep isolates attack difficulty.

---

## LEVER 1 — dimension-aware σ (TRY FIRST; cheap)

The SamplePre requirement is `σ ≥ ‖T̃‖ · ω(√log m)`. A fixed σ=4 violates this once
‖T̃‖ grows. Scale σ with the MEASURED root-basis quality per dimension:

```python
def sigma_for_params(root_sk, params, safety=1.2):
    # standard SamplePre width: sigma >= ||T~|| * sqrt(log m) * const
    g = gs_norm(balanced(root_sk, params.q))
    return safety * g * math.sqrt(max(math.log(params.m), 1.0))
```

- In the sweep, for each n: build the root, compute `sigma = sigma_for_params(...)`,
  and use THAT sigma for all NewBasisDel / SamplePre at that n.
- The usability threshold uses the SAME sigma (it already depends on sigma), so the
  threshold rises consistently — this is the point: both sides scale together on
  theory, not by hand.
- **This is not cheating:** σ is *required* to scale with basis quality; a fixed σ was
  the bug. Emit a `correction`/`note` event: "σ scaled per dimension per SamplePre
  width requirement σ ≥ ‖T̃‖·√log m; paper/earlier build used fixed σ."

CHECK AFTER LEVER 1: run the sweep, look at `correctness_lost_at` for n=4,6,8.
- If all are `—` (chain usable everywhere) → CONFOUND FIXED. Skip Levers 2–3. Go to §3.
- If n=6,8 still lose usability → the root basis itself is too poor; go to LEVER 2.

---

## LEVER 2 — stronger reduction on the legit basis (only if Lever 1 insufficient)

The root basis from TrapGen is LLL-reduced; LLL quality decays in higher dimension.
Improve the reduction so ‖T̃‖ is smaller at n=6,8.

Preferred: use a library BKZ rather than hand-rolling.
```python
# Use fpylll (pip install fpylll) for BKZ if available; fall back to repeated LLL.
try:
    from fpylll import IntegerMatrix, BKZ, LLL
    def strong_reduce(basis_int, block=10):
        M = IntegerMatrix.from_matrix(basis_int.tolist())
        BKZ.reduction(M, BKZ.Param(block_size=block))
        return matrix_from(M)
except ImportError:
    def strong_reduce(basis_int, block=10):
        # fallback: multiple LLL passes with delta close to 1
        return repeated_lll(basis_int, delta=0.99, passes=3)
```

- Apply `strong_reduce` to the root basis AND to each NewBasisDel output (re-reduce
  the delegated basis before use). Re-measure ‖T̃‖.
- IMPORTANT: reducing the LEGIT basis is legitimate (the honest key holder would use
  the best basis they can). Reducing it does NOT help the attacker — the attacker's
  LLL is applied separately to the recovered candidate. Keep the two reductions
  clearly separate in code and in the trace.
- If fpylll won't install in the environment (network-restricted), use the repeated-LLL
  fallback and note it.

CHECK AFTER LEVER 2: same test — is `correctness_lost_at == —` for all n?
- Yes → CONFOUND FIXED → §3.
- No → go to LEVER 3 decision.

---

## LEVER 3 — decision point (do NOT implement unless you have time to spare)

A proper Micciancio–Peikert gadget trapdoor would fix this cleanly but is a multi-day
implementation with high risk of subtle bugs. For this eval timeline, DO NOT implement
it. Instead go to the FALLBACK (§4). If, and only if, Levers 1–2 succeeded, you never
reach here.

---

## 3. If the confound is FIXED — the clean sweep

Re-run n ∈ {4,6,8} (10 if fast) with the confound removed. Now `#broken` is
trustworthy. Report the real trend and the honest verdict:

- `#broken` stays > 0 or grows with n → **"Break persists across tested dimensions —
  strong evidence of a structural forward-security weakness under low-norm H1. Secure
  parameters still require BKZ, but the low-dimension-artifact explanation is now
  ruled out."** (This is the strong outcome.)
- `#broken` shrinks to 0 with n, AND `correctness_lost_at == —` everywhere (i.e. the
  legit chain WAS usable, so 0 means genuinely unbroken) → **"Break is a low-dimension
  (LLL) artifact; forward security holds at the tested larger dimensions. Reported
  honestly."** (Clean negative — also a strong, publishable-style result.)

Either way, the verdict is now DEFENSIBLE because the confound banner no longer
applies. Update / remove the amber "confound" box accordingly, and keep the n / BKZ
caveat only to the extent it still holds.

Add a column to the sweep table: `SIGMA (per n)` and `LEGIT ‖GS‖ (per n)` so a reader
sees the legit chain stayed usable (legit ‖GS‖ < threshold at every n). This is the
proof the confound is gone — make it visible.

---

## 4. FALLBACK (if Levers 1–2 don't fix it within your time budget)

Ship the Path-1 framing, clearly labelled:

> "Scaling is inconclusive in this lab: keeping the legitimate key chain usable at
> n ≥ 6 requires higher-quality basis delegation than our from-scratch NewBasisDel
> provides (even with σ-scaling and stronger reduction). We therefore report the
> confirmed n=4 break and mark the secure-parameter scaling question as open — its
> resolution needs a gadget-based trapdoor (Micciancio–Peikert) and BKZ, which we
> identify as the immediate next step."

Keep the confound banner. This is an honest, strong mid-eval result. Do not disguise
it as a clean scaling conclusion.

TIME BUDGET: spend at most a bounded effort on Levers 1–2 (Lever 1 is minutes; Lever 2
is an hour or two including fpylll). If not fixed by then, take the fallback and move
on to polishing Findings 1 and 3. Do not sink the week here.

---

## 5. Tests

- `test_sigma_scaling_keeps_legit_usable`: with dimension-aware σ, assert
  `correctness_lost_at is None` for n=4 (and for n=6 if Lever 1/2 succeeded).
- `test_legit_reduction_helps`: strong_reduce lowers ‖T̃‖ vs plain LLL on the same
  basis (only if Lever 2 used).
- `test_attacker_and_legit_reductions_separate`: assert the attacker's LLL is applied
  to the recovered candidate only, never sharing state with the legit-basis reduction.
- `test_sweep_reports_legit_gs_per_n`: sweep rows include sigma and legit_gs, and the
  verdict logic reads correctness_lost_at (so a contaminated 0 can never be reported
  as "unbroken").

---

## Order
1. LEVER 1 (σ-scaling). Re-run sweep. Check correctness_lost_at.
2. If needed, LEVER 2 (strong reduce, prefer fpylll). Re-run. Check again.
3. If fixed → §3 clean verdict, add sigma/legit_gs columns, drop confound banner.
4. If not fixed within budget → §4 fallback, keep banner, move on.
Report which lever resolved it (or that you fell back) in the Finding-2 summary.
