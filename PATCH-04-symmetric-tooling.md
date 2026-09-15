# PATCH 04 — Symmetric tooling: give the ATTACKER BKZ too

> Apply after PATCH-03. One purpose: close the "defender got BKZ, attacker only got
> LLL" asymmetry. After PATCH-03 the legitimate chain is BKZ-reduced but the attacker's
> recovered candidate is still only LLL-reduced. A fair test gives BOTH sides the same
> reduction strength. This is the last step to make the Finding-2 no-break result
> unimpeachable.
>
> HONESTY GUARDRAILS (unchanged): single audited threshold; verdict from measured
> norms; never tune to an outcome. If attacker-BKZ now breaks a period, that is a REAL
> break — report it, do not suppress it.

---

## 1. What to change

In the forward-security attack path, the attacker currently does:
`candidate = balanced(R_prod_inv @ target_sk)  →  LLL  →  measure ‖GS‖`.

Replace the attacker's LLL with the SAME reduction routine the defender uses
(`strong_reduce` / fpylll BKZ from PATCH-03), applied to the attacker's candidate over
the correct q-ary lattice.

```python
def attacker_recover(chain, i, params, reducer):
    R_prod      = product_of_R(chain, i+1, J)          # public
    R_prod_inv  = integer_inverse(R_prod)              # I+N products invert over Z
    target_sk   = chain[J-1]["sk"]                     # the stolen current basis
    cand_raw    = balanced(R_prod_inv @ target_sk, params.q)
    # reduce over the q-ary lattice L^perp_q(pk_i): include q*I vectors so reduction
    # stays in the lattice, then reduce with the SAME strength as the defender.
    cand_qary   = stack_with_qI(cand_raw, chain[i]["pk"], params.q)
    cand_red    = reducer(cand_qary)                   # <-- BKZ now, not LLL
    cand_final  = extract_lattice_basis(cand_red, params)
    assert all_columns_zero_mod_q(chain[i]["pk"] @ cand_final, params.q), "left lattice!"
    return gs_norm(cand_final)
```

Pass the SAME `reducer` object to both the legit-basis reduction and the attacker
recovery, so there is literally one reduction strength in play. Record which reducer
was used (`fpylll_bkz` or `lll_fallback`) in the trace and the sweep table.

---

## 2. Run three configurations (show the matrix)

To make the fairness explicit, run and display all three:

| config              | defender basis | attacker reduction | why show it |
|---------------------|----------------|--------------------|-------------|
| `LLL_vs_LLL`        | LLL            | LLL                | the original apples-to-apples |
| `BKZ_defender_only` | BKZ            | LLL                | PATCH-03 state (defender-favoured) |
| `BKZ_vs_BKZ`        | BKZ            | BKZ                | the fair fight (this patch)  |

For each config, per n ∈ {4,6,8}: report `#broken`, `min after-reduction ‖GS‖`,
threshold, `correctness_lost_at`. A small grouped table or a 3-series bar chart
(x = n, series = config, y = #broken) is ideal.

The point of showing all three: it makes visible that the no-break result is NOT an
artifact of under-powering the attacker. If `BKZ_vs_BKZ` still shows `#broken = 0`, the
result is airtight.

---

## 3. Verdict logic (unchanged source, three outcomes)

Read the `BKZ_vs_BKZ` row as the authoritative fairness test:

- `BKZ_vs_BKZ` #broken = 0 at all n (and correctness_lost_at = — everywhere)
  → **"Forward-security mechanism resists the R⁻¹-transform attack even under
    symmetric BKZ tooling, at all tested dimensions. The attack does not recover a
    usable earlier basis. (Demo params; secure-parameter proof still open.)"**
  This is the strong, positive, unimpeachable outcome.

- `BKZ_vs_BKZ` #broken > 0 somewhere
  → **"Under symmetric BKZ tooling the attack recovers a usable earlier basis for
    period(s) X at n = Y — a forward-security break that only appears once the attacker
    is given reduction strength equal to the defender's."** This is a genuine break;
    report it plainly, note it was hidden by the earlier tooling asymmetry.

Whatever the BKZ_vs_BKZ row says is the honest headline for Finding 2's
forward-security axis. Do not average across configs or cherry-pick.

---

## 4. Caveats to keep on the UI (still true)

- Demonstration parameters (n ≤ 8). Even symmetric BKZ at small n does not settle the
  cryptographic-parameter question; a proof or large-n BKZ estimate would. Keep a
  trimmed caveat to this effect.
- This tests ONE attack family (public transform + reduction). "Resists this attack"
  ≠ "provably forward-secure." Keep that wording.
- The durable contribution is the REDUCTION (forward security ⟺ norm growth of a
  public transform) plus the measured outcome under fair tooling — state it that way.

---

## 5. Tests

- `test_attacker_uses_same_reducer`: assert the attacker path and legit path call the
  identical reducer function/config in the BKZ_vs_BKZ run.
- `test_attacker_candidate_in_lattice_post_bkz`: post-BKZ candidate satisfies
  `pk_i @ cand ≡ 0 mod q`.
- `test_three_configs_reported`: sweep returns all three configs with well-formed rows.
- `test_verdict_reads_bkz_vs_bkz`: the Finding-2 forward-sec verdict is derived from
  the BKZ_vs_BKZ row, not the others.

---

## 6. Order
1. Wire the attacker to the shared BKZ reducer over the q-ary lattice.
2. Run all three configs at n ∈ {4,6,8}, J=6.
3. Report the grouped table/chart + the BKZ_vs_BKZ verdict.
4. Update the Finding-2 summary: state the fair-tooling outcome and keep the two
   caveats in §4. Report which reducer backend was actually used.
