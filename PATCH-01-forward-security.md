# PATCH 01 — Forward Security module: corrected verdict logic + legit-basis usability

> Apply to `backend/attacks/forward_sec.py` and the Forward Security UI tab.
> Reason: the current verdict column is misleading under `naive_uniform` H1 — it
> compares the attacker's candidate against a *legit basis that has already diverged*
> (GS-norm ~1e19), so "survives both" is meaningless there. The naive_uniform case is
> a CORRECTNESS-collapse story, not a forward-security story. This patch separates the
> two, makes the usability threshold explicit and justified, and adds an honest
> parameter-scaling caveat.

---

## 1. The core reframing (put this at the top of the module as a docstring)

The paper omits H1's construction. The two natural instantiations FAIL DIFFERENTLY,
and Finding 2 is that dilemma:

- **naive_uniform H1** (R = uniform invertible mod q): ‖R‖ ~ q/2, so `NewBasisDel`
  inflates the delegated basis norm by a large factor each period → **KeyExt loses
  correctness within a few periods.** Forward security is moot because the scheme
  doesn't even function. Report: "correctness collapse at period k."

- **low_norm H1** (R = I + strictly-upper-triangular small N): correctness holds, but
  `R^-1` is also low-norm, so the public transform `R^-1 · sk_J` yields a valid
  (long) earlier-period basis, and **LLL re-reduction recovers a USABLE earlier basis
  for recent periods** at demo params → **forward-security weakness.**

Net finding: *both* natural H1 choices lose — one to correctness, one to forward
security. The proof's silence on H1's distribution is load-bearing.

---

## 2. Make the usability threshold explicit and defensible

Do NOT hard-code `q/4`. The real question is "is this basis short enough to be a
usable trapdoor for SamplePre at this sigma?" The standard condition for SamplePre to
output correctly-distributed short preimages is roughly:

```
usable(T)  ⟺  gs_norm(T) ≤ USABILITY_FACTOR * sigma * sqrt(m)   ... (sampling bound)
             AND  gs_norm(T) is small enough that decryption noise < q/4   ... (decode bound)
```

Implement a single explicit function and SHOW its value + which bound is binding:

```python
import math

def usability_threshold(params) -> dict:
    # sampling bound: SamplePre needs gs_norm(T) * omega(sqrt(log m)) <= sigma-related cap.
    # We use the standard sufficient form: T is usable for width sigma if
    #   gs_norm(T) <= sigma / (C * sqrt(log(m)))     (C a small constant, state it)
    # Equivalently, given a fixed T, the minimal usable sigma is C*gs_norm(T)*sqrt(log m).
    C = 1.0  # state this constant explicitly in the UI; it is a modelling choice
    m = params.m
    sampling_cap = params.sigma / (C * math.sqrt(max(math.log(m), 1.0)))

    # decode bound: verification decodes correctly while noise < q/4; a basis of
    # gs-norm g induces preimages of norm ~ g*sigma*sqrt(m), and the accumulated
    # inner-product noise must stay < q/4. Express as a cap on gs_norm:
    decode_cap = (params.q / 4.0) / (params.sigma * math.sqrt(m))

    cap = min(sampling_cap, decode_cap)
    binding = "sampling" if sampling_cap <= decode_cap else "decode"
    return {
        "threshold": cap,
        "binding_bound": binding,
        "sampling_cap": sampling_cap,
        "decode_cap": decode_cap,
        "note": "USABILITY_FACTOR/C is a modelling choice; stated so the verdict is auditable.",
    }
```

Emit a `note` trace event carrying this dict at the start of the experiment, and draw
BOTH caps as reference lines on the chart (or at least the binding one, labelled with
which bound it is). The borderline low_norm verdicts depend on this number, so it must
be visible and justified — never an unexplained `q/4`.

---

## 3. Per-period legit-basis usability check (the naive_uniform fix)

Before judging the attacker, judge the *legitimate* chain. If the legit basis itself
is unusable at period i, the whole forward-security question is undefined there.

```python
def build_chain_with_health(J, h1_variant, params):
    root_pk, root_sk = trapgen(params)
    chain = [{"period": 0, "pk": root_pk, "sk": root_sk}]
    thr = usability_threshold(params)["threshold"]

    correctness_lost_at = None
    for j in range(1, J):
        pk_prev, sk_prev = chain[-1]["pk"], chain[-1]["sk"]
        R = H1(pk_prev, j, variant=h1_variant)
        pk_j = mod(pk_prev @ inv(R, params), params.q)
        sk_j = new_basis_del(pk_prev, R, sk_prev, params.sigma)
        g = gs_norm(balanced(sk_j, params.q))          # BALANCED reps before norm!
        legit_usable = g <= thr
        if not legit_usable and correctness_lost_at is None:
            correctness_lost_at = j
        chain.append({"period": j, "pk": pk_j, "sk": sk_j,
                      "R": R, "legit_gs": g, "legit_usable": legit_usable})
    return chain, correctness_lost_at, thr
```

**Two must-dos flagged inline above:**
- `balanced(...)`: map every entry to `(-q/2, q/2]` BEFORE computing any GS norm.
  (Left in `[0,q)` the norms are inflated — this was the earlier artifact.)
- Compute `R^-1` correctly per variant:
  - `low_norm` (R = I + N, det = 1): invert **over the integers** (exact, low-norm).
  - `naive_uniform`: only a mod-q inverse exists; use it, and EXPECT the blowup — that
    blowup IS the correctness-collapse finding.

---

## 4. Per-period verdict — three-tier, and gated on legit usability

```python
def verdict_for_period(row, thr):
    # row has: legit_gs, legit_usable, cand_trivial_gs, cand_lll_gs, in_lattice
    if not row["in_lattice"]:
        return "candidate not in lattice (bug — investigate)"
    if not row["legit_usable"]:
        # legit chain already broke here — forward security is undefined/moot
        return "correctness lost (legit basis unusable)"
    trivial_ok = row["cand_trivial_gs"] <= thr
    lll_ok     = row["cand_lll_gs"] <= thr
    if trivial_ok:
        return "BROKEN (trivial transform)"
    if lll_ok:
        return "BROKEN (after LLL reduction)"
    return "survives (trivial + LLL) at these params"
```

Key change vs current build: **if the legit basis is unusable, the verdict is
"correctness lost", NOT "survives both".** Under `naive_uniform` this will (correctly)
turn the whole table into a correctness-collapse story: the first ~2–3 rows may still
show usable legit, then it flips to "correctness lost" for the rest.

Also record, per variant, the summary:
```python
summary = {
  "variant": h1_variant,
  "correctness_lost_at": correctness_lost_at,   # None if chain stays usable
  "broken_periods_trivial": [...],
  "broken_periods_after_lll": [...],
  "survives_periods": [...],
  "threshold": thr,
}
```

---

## 5. LLL step — verify membership AFTER reduction

The "in lattice: true" check must run on the POST-LLL candidate, not the pre-LLL one.

```python
cand_trivial = balanced(mod(Rprod_inv @ target_sk, params.q), params.q)
cand_lll     = lll_reduce(cand_trivial_over_the_correct_ring)   # see note
assert all_columns_zero_mod_q(pk_i @ cand_lll, params.q), "LLL left the lattice!"
row["cand_trivial_gs"] = gs_norm(cand_trivial)
row["cand_lll_gs"]     = gs_norm(cand_lll)
row["in_lattice"]      = True  # only after the assert passes
```

Note on LLL: reduce the basis of the lattice `L⊥_q(pk_i)` that the candidate spans —
i.e. LLL over the q-ary lattice (include the `q·I` vectors so reduction stays in the
lattice), then take the shortest usable sub-basis. Do NOT LLL the raw integer matrix
in a way that leaves the q-ary lattice.

---

## 6. Parameter-scaling caveat (MANDATORY on the UI + in the summary)

At `n=4` LLL is near-optimal, so "BROKEN after LLL" is expected and does NOT imply a
break at cryptographic parameters. The UI must display, whenever any BROKEN verdict
appears:

> ⚠ Demonstration parameters (n=4). LLL is near-optimal in low dimension, so recovery
> here does not establish a break at secure parameters. Scaling requires BKZ analysis
> at cryptographic n, which this lab does not perform. The result shown is: *the
> forward-security question reduces to lattice reduction on R⁻¹·sk_J, and at demo
> params that reduction succeeds for recent periods.*

Emit this as a `note` event too, so it's in the exported JSON.

If runtime allows, add an optional sweep: run low_norm at n ∈ {4,6,8} and plot
"periods broken after LLL vs n" — showing whether the break shrinks as n grows. This
directly addresses scaling and is high-value. Keep it behind a "run scaling sweep"
button (it's slower).

---

## 7. UI changes (Forward Security tab)

- **Two sub-views or a variant toggle** with DISTINCT headline per variant:
  - low_norm → headline: "Forward-security weakness (LLL recovers recent periods)"
  - naive_uniform → headline: "Correctness collapse (KeyExt diverges) — FS is moot"
- Chart:
  - low_norm: three series (legit, candidate-trivial, candidate-after-LLL) + threshold
    line(s), log scale — as now, it's good.
  - naive_uniform: plot legit_gs vs threshold and mark the "correctness lost at period
    k" point with a vertical marker. Do NOT plot the attacker candidate as if it's a
    meaningful comparison here — annotate that the legit chain is already broken.
- Verdict table: add a `LEGIT USABLE?` column. Colour "correctness lost" rows
  distinctly from "BROKEN" rows — they are different findings.
- Always render the threshold value + which bound is binding (from §2).
- Always render the n=4 scaling caveat banner when any BROKEN appears.

---

## 8. Tests to update (backend/tests/test_forward_sec.py)

- `test_naive_uniform_correctness_collapse`: with naive_uniform, assert
  `correctness_lost_at is not None` and is small (≤ ~4 at n=4).
- `test_lownorm_chain_stays_usable`: with low_norm, assert legit basis usable for all
  periods (`correctness_lost_at is None`).
- `test_verdict_gated_on_legit`: construct a row with legit_usable=False and assert
  verdict == "correctness lost (...)", regardless of candidate norms.
- `test_lll_stays_in_lattice`: assert post-LLL candidate satisfies `pk_i @ cand ≡ 0`.
- `test_balanced_norm_smaller`: for a random matrix, gs_norm(balanced) ≤ gs_norm(raw
  [0,q)) — guards against the earlier inflation artifact.
- `test_threshold_explicit`: usability_threshold returns both caps and names the
  binding one.

---

## 9. What the corrected tab should CONCLUDE (verdict summary block)

Render this, filled from measured data:

> **Finding 2 — the H1 dilemma (both natural instantiations lose):**
> • naive_uniform H1 → correctness collapses at period {correctness_lost_at}; scheme
>   non-viable, so forward security is moot.
> • low_norm H1 (required for correctness) → trivial R⁻¹ transform fails (candidate
>   ‖GS‖ ≫ threshold), but LLL re-reduction recovers a *usable* earlier basis for
>   periods {broken_periods_after_lll} at n={n}.
> • The paper specifies no H1 construction; this dilemma is a consequence of that
>   omission, and the security proof's silence on H1's distribution is load-bearing.
> ⚠ Demo params (n={n}); scaling to secure n needs BKZ — not claimed here.

Keep every number in this block sourced from the measured run — never hard-coded.
