# PATCH 14 — "Security Boundary" tab: break vs. estimated security level

> A NEW tab that gives the clean, defensible story we could never get from forward
> security alone: at what SECURITY LEVEL does the public-key-only attack succeed vs
> fail. The x-axis is the canonical lattice security estimate (bits), NOT any hand-tuned
> threshold. Empirical attack success and the estimator should agree, and their
> agreement IS the clean conclusion.
>
> This does not replace the (n,q) sweep (PATCH-13) — it re-plots the same public-key
> attack against a principled x-axis and adds the estimator. Reuses the locked
> implementation (PATCH-12) and the public-key-only attack (no secret, no TrapGen).
>
> HONESTY (the whole point): we do NOT claim "forward security holds above X". We claim
> "the public-key-only attack breaks the scheme below ~X-bit security; above it the
> attack times out, so key security reduces to the standard LWE-hardness question the
> estimator quantifies." Scope every statement to what was measured vs estimated.

---

## 1. The security estimate (canonical, not fuzzy)

For each (n, q, σ), compute an estimated bit-security of the underlying LWE/SIS instance.
Two backends, in preference order:

**Backend A — the lattice-estimator (preferred, canonical).**
The Albrecht et al. "lattice-estimator" (https://github.com/malb/lattice-estimator).
It typically needs SageMath. If Sage is available:
```python
from estimator import LWE, ND
params = LWE.Parameters(n=n, q=q, Xs=ND.DiscreteGaussian(sigma),
                        Xe=ND.DiscreteGaussian(sigma))
est = LWE.estimate(params)                 # dict of attack costs
bits = min(a.rop for a in est.values()).log2()   # log2 of best attack's operation count
```
Report `bits` and which attack (usvp/bdd/dual) was cheapest.

**Backend B — Lindner–Peikert-style estimate (fallback, no Sage).**
If the estimator/Sage won't install (network-restricted env — check the allowed
domains), use the standard root-Hermite-factor route, which is a documented formula,
not a constant I invent:
```
# To find a short vector in an m-dim q-ary lattice, BKZ must reach root-Hermite
# factor delta_0 where the shortest findable vector ~ delta_0^m * det^(1/m).
# For L^perp_q(A): det = q^n, dim = m. Attack succeeds if BKZ can reach the delta_0
# that yields a vector short enough to be a usable trapdoor (GPV bound).
# Map delta_0 -> BKZ block size beta via the standard fit
#   delta_0 ≈ (beta/(2*pi*e) * (pi*beta)^(1/beta))^(1/(2(beta-1)))
# then bit-cost ≈ 0.292*beta (classical BKZ, Becker et al.) or 0.265*beta (quantum).
```
Implement the delta_0 <-> beta fit and report `beta` and `bits ≈ 0.292*beta`. Label
the backend used ("lattice-estimator" or "lindner-peikert-fit") in every result and
plot caption — so the provenance of the number is explicit.

Do NOT use any threshold constant of the form σ/(C·√log m) here. That was the fuzzy
one. The security estimate is the principled x-axis.

---

## 2. The experiment per (n, q)

Reuse the public-key-only attack (PATCH-12/13, no secret, no TrapGen):
1. Compute `bits` (§1) for this (n, q, σ). Store backend + cheapest-attack.
2. Run the public-key-only attack with a HARD timeout T (e.g. 120s) and a fixed BKZ
   block-size ladder (try increasing beta until break or timeout). Record:
   - `broke` (bool): did BKZ find a basis yielding a working trapdoor (same N0)?
   - `beta_used`: the block size at which it broke (or the max tried before timeout).
   - `runtime`, `timed_out`.
3. Correctness gate first (PATCH-12): if the honest scheme is invalid at this (n,q),
   mark n/a — no attack point.
4. Negative control (BKZ'd garbage must fail) — else "untrusted".

Outcome per cell: `broke=True` (attack won) / `timed_out` (couldn't within budget —
NOT "secure", just unmeasured) / `attack_failed` (ran to completion, no working
trapdoor) / `n/a` / `untrusted`.

---

## 3. Grid to sweep (pick to straddle the boundary)

- n ∈ {4, 8}, q ∈ {257, 1153, 4099} (reuse PATCH-13's locked, working set).
- Optionally add a couple of LARGER (n,q) purely to show the attack TIMING OUT as
  security rises (e.g. n=8 q=40961, or n=16 q=12289) — these will likely time out, and
  that's the point: they populate the "unmeasured/secure" side of the plot.
- σ from the scheme's setting (state it). J small / single-period is fine — this is
  about key security of ONE public key, not chains.

Reuse PATCH-08 persistence (jsonl + resume) if any cell is slow.

---

## 4. The clean plot (the deliverable)

**Plot: x = estimated security (bits), y = public-key attack outcome.**
- Each (n,q) cell = one point at its `bits`, coloured:
  red = broke, grey = timed_out (unmeasured), green = attack ran & failed, hatched = n/a.
- Expect: broke points cluster at LOW bits; timed_out at HIGH bits; a visible boundary
  region between. Draw a shaded "break region" up to the highest bits at which any cell
  broke, labelled "empirically broken ≤ ~X bits".
- Mark the PAPER'S demo parameters (q=257, n=4 and n=8) with a distinct marker and a
  callout: "paper's Figures 3–6 parameters — ~Y bits — inside the broken region."
- Second axis / companion plot: trapdoor size (bytes = m·⌈log2 q⌉/8) and honest testing
  proxy vs bits — showing that reaching high bits blows up size/time, i.e. the paper's
  efficiency only exists at low (insecure) bits. (Ties to the reproducibility finding.)

Auto-conclusion (measured + estimated, stated with scope):
> "Public-key-only attack (no secret key) vs estimated LWE security: the attack
> recovers a working trapdoor for all tested cells at ≤ ~{X} bits, including the paper's
> demonstration parameters (~{Y} bits). At ≥ ~{Z} bits the attack times out within the
> {T}s budget — UNMEASURED, not proven secure; there key security reduces to standard
> LWE hardness (estimator: {backend}). Consequently the paper's 'forward security' and
> 'confidentiality' claims are vacuous at the parameters it evaluates (public key alone
> breaks search), and the security level at which they could hold coincides with
> trapdoor sizes and timings far larger than the paper's Figures report. Demo-scale n;
> estimator provides the security axis, our attack confirms the low-bit boundary."

Never label a timed_out cell "secure" — always "unmeasured (BKZ timeout)".

---

## 5. Tests

- `test_security_estimate_backend`: returns bits + backend label + cheapest-attack for
  (n,q,σ); backend A if Sage present else B; both paths tested.
- `test_lp_fit_monotone`: fallback bits increase with n and with n·log q (sanity).
- `test_pk_attack_point`: each valid cell yields (bits, broke, beta_used, runtime).
- `test_timeout_not_secure`: a timed_out cell is labelled unmeasured, never "secure",
  never counted in a "secure" claim.
- `test_paper_params_marked`: q=257 n∈{4,8} points carry the "paper demo" flag and fall
  in the broken region on the measured data.
- `test_control_and_correctness_gates`: n/a and untrusted cells excluded from the
  boundary conclusion.

---

## 6. Order
1. Implement the security estimate: try lattice-estimator (Sage); if unavailable, the
   Lindner–Peikert delta_0<->beta fallback. Label backend everywhere.
2. Wire the public-key-only attack with a BKZ block-size ladder + hard timeout,
   recording beta_used / broke / timed_out.
3. Correctness + negative-control gates per cell (reuse PATCH-12).
4. New "Security Boundary" tab: the bits-vs-outcome plot + paper-params marker +
   size/time-vs-bits companion + auto-conclusion.
5. Run n∈{4,8}×q∈{257,1153,4099} (+ optional larger cells to populate the timeout side).
Report: the bits-vs-outcome plot, the backend used, the paper-params point, and the
auto-conclusion with its measured X / estimated Z boundary values.
