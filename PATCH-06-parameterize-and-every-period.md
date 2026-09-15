# PATCH 06 — End-to-end attack must respect user n and J, and attack EVERY past period

> Apply after PATCH-05. Fixes two bugs and generalizes the demo:
> 1. The "Run end-to-end attack (n=4)" and "Compare n=4 vs n=8" buttons IGNORE the J
>    input box and HARDCODE n. Remove all hardcoding.
> 2. The result panel and the comparison table used DIFFERENT J, producing a
>    self-contradiction on screen (panel said "survives at n=4", table said "break at
>    n=4"). One experiment, one (n, J), consistent everywhere.
> 3. Generalize: for a compromise at period J, attack EVERY past period i ∈ {0..J-1}
>    and report each period's recovered sequence number vs the legitimate N0.
>
> HONESTY GUARDRAILS (unchanged, still enforced): frozen DBs; attacker reads only
> sk_J + public data (never honest sk_i); Level-2 success = same N0 on frozen DB;
> negative control must still fail; L2/L3 distinct; verdicts from measured results.

---

## 1. Single parameterized entry point (remove ALL hardcoding)

There must be ONE function that takes n and J from the UI and runs the whole thing.
No `n=4`, no `n=8`, no fixed J anywhere in the button handlers.

```python
def run_end_to_end(n: int, J: int, params_base, reducer, h1_variant="low_norm"):
    params = replace(params_base, n=n)          # m re-derives from n
    # forward: build & freeze J period DBs, evolve honest key 0 -> J-1,
    # then one more step so the key at the COMPROMISE period J-1 is the stolen one.
    history = build_frozen_history(J, params, DICTIONARY, h1_variant)
    stolen_sk = history[J-1].honest_sk_INTERNAL   # the attacker's ONLY secret input
    # NOTE: honest_sk is stored on the forward-pass object but the attacker function
    # below must be given ONLY stolen_sk (period J-1). Assert it never reads other sk_i.

    per_period = []
    for i in range(J-1):                          # every PAST period 0..J-2
        r = attack_period(history, i, J-1, params, reducer, stolen_sk)
        per_period.append(r)                      # r has N0_legit, N0_star, L1/L2/L3
    return {
        "n": n, "J": J, "compromise_period": J-1,
        "threshold": usability_threshold(params)["threshold"],
        "reducer": reducer_name(reducer),
        "per_period": per_period,                 # one row per past period
        "any_L2_break": any(p["level2_search_break"] for p in per_period),
        "L2_broken_periods": [p["period"] for p in per_period if p["level2_search_break"]],
        "L3_broken_periods": [p["period"] for p in per_period if p["level3_plaintext_break"]],
    }
```

- The compromise period is `J-1` (the latest period). The attacker steals the key
  there and reaches back to `0..J-2`. (If you prefer compromise AT J with periods
  0..J-1 frozen, keep it consistent — just pick one convention and label it.)
- `attack_period(..., stolen_sk)` takes the stolen key as an EXPLICIT argument so it
  physically cannot read any other period's honest sk. Keep `test_attacker_never_reads_honest_sk`.

---

## 2. Button / input wiring (the actual bug)

- The J input box value MUST feed `run_end_to_end(n=<current n param>, J=<J box>)`.
- The n MUST come from the left-rail `n` parameter (or a dedicated n input on this
  panel) — never a literal.
- Replace the two buttons with:
  - **"Run end-to-end attack"** → runs `run_end_to_end(n=current_n, J=J_box)`. Label the
    button dynamically, e.g. "Run end-to-end attack (n={current_n}, J={J_box})", so the
    user SEES it will use their values.
  - **"Compare dimensions"** → runs `run_end_to_end` for a user-editable LIST of n
    values (default e.g. [current_n, current_n+2, current_n+4]) at the SAME J from the
    box. The comparison table then shows rows all at the SAME J — no more mismatch.
- Remove `n=4` / `n=8` from all labels and handlers. If you keep a quick-compare, make
  its n-list an input, not a constant.

---

## 3. Consistency guarantee (fixes the on-screen contradiction)

- The single-run panel and the comparison table MUST derive from the SAME
  `run_end_to_end` calls with the SAME J. Never run the panel at one J and the table at
  another.
- Every result object carries `(n, J, compromise_period, reducer, threshold)`. The UI
  MUST display these on both the panel and each table row. A table row without its
  (n, J) label is forbidden.
- Add `test_panel_table_same_J`: the value shown in the panel and the value(s) in the
  comparison table come from calls with identical J.

---

## 4. Every past period gets its sequence number (the thing you want)

For a run at (n, J), render a row PER past period i ∈ {0..J-2}:

| period i | periods back | gs_norm(SK*) | N0_legit | N0_star | L1 | L2 (N0*==N0) | L3 | verdict |

- `N0_legit` = the sequence number the honest doctor got at period i (ground truth,
  from the frozen DB).
- `N0_star` = the sequence number the ATTACKER's reconstructed trapdoor returns on the
  FROZEN CT_i (or `—`/None if no match).
- L2 pass IFF `N0_star == N0_legit` and not None.
- Show BOTH numbers side by side so the viewer sees the match (or mismatch) directly.
  This is the concrete demonstration: "attacker, from one stolen key, recovered the
  exact sequence number the doctor found at each past period — or didn't."

Also keep the NEGATIVE CONTROL visible per run (a summary line):
"control: garbage basis → L2 {failed as expected / UNEXPECTEDLY passed}." If the
control ever passes, banner the whole result as UNTRUSTWORTHY.

---

## 5. Timeline UI (generalized to any J)

- Render J nodes: periods `0..J-2` as attackable past periods + node `J-1` marked
  "attacker steals SK here" (the compromise). Timeline length follows the J input.
- Colour each past-period node by its measured outcome:
  - green = L2 broke (attacker recovered N0 on frozen DB)
  - blue = L2 broke AND L3 broke (also recovered plaintext)
  - grey = attack failed (N0_star != N0_legit)
- Click a node → detail drawer: the reconstruction (R⁻¹·sk_J → BKZ → SK*), gs_norm vs
  threshold, the derived Trap*, N0_star vs N0_legit, and (if reachable) M_star vs M_true.
- The headline sentence under the timeline is generated from measured data and states
  (n, J), which periods broke L2, which broke L3, and the negative-control status.

---

## 6. Honest verdict wording (from measured data, per run)

- If `L2_broken_periods` empty → "At (n={n}, J={J}) the attack recovers NO past period's
  search capability — forward-security functionality resists this attack here."
- Else → "At (n={n}, J={J}) a single stolen SK_{J-1} recovers the old SEARCH capability
  for period(s) {L2_broken_periods} (same N0 as the doctor, on frozen ciphertexts);
  plaintext (L3) for {L3_broken_periods}. Confined to {describe pattern, e.g. periods
  within k of compromise}." Keep the demo-params / one-attack-family / L2≠L3 caveats.

Do NOT print "break confirmed at every dimension" unless every tested (n, J) actually
broke in THIS run's measured data. The earlier such claim was inflated; keep it honest.

---

## 6.5 Measure the WORD-basis norm — the basis SamplePre actually consumes

CRITICAL correctness fix. The current experiment measures the PERIOD basis norm
`‖SK*r|i‖` against the threshold (Level-1 proxy). But SamplePre does NOT consume the
period basis — it consumes the WORD basis produced by one MORE delegation:

```
SK*r|i  --NewBasisDel(pk, βi=H2(w,i), ·)-->  SK*w|i  --SamplePre-->  Trap*w|i
        (period basis)                        (WORD basis)           (trapdoor)
```

`NewBasisDel` GROWS the norm: ‖T̃_word‖ ≲ ‖T̃_period‖ · ‖βi‖ · poly(m). So the word
basis can exceed threshold even when the period basis is under it — which is exactly
what would make Level-1 (period-norm proxy) pass while Level-2 (actual search) fails.
Measuring the word basis EXPLAINS L1-vs-L2 gaps and cross-checks the L2 test.

Instrument the FULL chain for BOTH parties and report all norms per period:

```python
def basis_chain_norms(pk_i, sk_period, i, keyword, params):
    beta   = H2(keyword, i, params)                       # FRD keyword matrix
    sk_word = new_basis_del(pk_i, beta, sk_period, sigma_for(sk_period, params))
    trap    = sample_pre(mod(pk_i @ inv(beta, params), params.q),
                         sk_word, params.mu, sigma_for(sk_word, params))
    return {
        "period_gs": gs_norm(balanced(sk_period, params.q)),   # L1 proxy (current)
        "word_gs":   gs_norm(balanced(sk_word,   params.q)),   # <-- SamplePre input: THE GATE
        "trap_norm": vec_norm(balanced(trap,     params.q)),   # final search vector
        "beta_norm": gs_norm(balanced(beta,      params.q)),   # for the growth factor
    }
```

In `attack_period`, compute this for the ATTACKER (`sk_period = SK*r|i`) AND, from the
frozen history, for the HONEST doctor (`sk_period = SKr|i`). Report side by side:

| period i | honest period_gs | honest word_gs | attacker period_gs | attacker word_gs | threshold |

Use the SAME audited threshold (PATCH-02 single source) — apply it to `word_gs`, since
that is the basis SamplePre needs usable. Do NOT invent a new threshold.

### Predicted-vs-measured cross-check (this is the point)

`word_gs ≤ threshold` PREDICTS that SamplePre yields a working trapdoor → L2 should
break. Compare this prediction to the MEASURED L2 outcome (same-N0). They should agree.

```python
result["word_gs_attacker"]   = attacker_norms["word_gs"]
result["word_pred_usable"]   = attacker_norms["word_gs"] <= threshold
result["l2_matches_wordpred"] = (result["word_pred_usable"] == result["level2_search_break"])
```

- If `word_pred_usable == True` but `level2_search_break == False`: SamplePre or the
  search has an issue — investigate.
- If `word_pred_usable == False` but `level2_search_break == True`: the L2 test is
  likely VACUOUS (a bad basis still "matched") — this is the negative-control failure
  mode; banner it.
- Surface `l2_matches_wordpred` per period; if any row is False, flag the run for
  inspection rather than trusting the verdict.

### Why this matters for honesty
The word-basis norm gives an INDEPENDENT prediction of Level-2 success. When the
word-norm prediction and the measured same-N0 outcome AGREE, the break (or no-break)
is corroborated by two independent signals. When they disagree, you've caught a bug
before the examiner did. Add the word_gs columns and the agreement flag to the
per-period table and the click-through detail drawer.

---

## 7. Tests

- `test_uses_input_n_and_J`: run_end_to_end is called with the UI's n and J; assert no
  literal n/J in handlers (e.g. by running with n=6, J=4 and checking result.n==6,
  result.J==4 and len(per_period)==3).
- `test_attacker_never_reads_honest_sk`: attack_period given only stolen_sk; monkeypatch
  honest sk_i access to raise; attack still runs.
- `test_negative_control_fails`: garbage basis → level2_search_break == False for all
  periods.
- `test_L3_subset_or_equal_L2`: L3_broken_periods ⊆ L2_broken_periods (plaintext can't
  break where search didn't).
- `test_panel_table_same_J`: panel J == table J.
- `test_every_past_period_reported`: per_period has exactly J-1 rows for a run at J.
- `test_word_basis_measured`: each per_period row has word_gs (honest + attacker),
  trap_norm, and beta_norm populated (not None).
- `test_word_gs_ge_period_gs`: word_gs ≥ period_gs on the same side (delegation grows
  the norm) — allow a small tolerance, but it must not be dramatically smaller.
- `test_l2_matches_wordpred_flag_present`: every row carries l2_matches_wordpred; the
  run-level summary counts how many rows disagree.
- `test_wordpred_disagreement_bannered`: if any row has word_pred_usable != L2 outcome,
  the run summary is flagged for inspection (not silently reported as a clean verdict).

---

## 8. Order
1. Extract single `run_end_to_end(n, J, ...)`; delete hardcoded n and fixed J.
2. Wire both buttons to UI n and J; dynamic button labels.
3. Per-past-period rows with N0_legit vs N0_star; negative-control line.
4. §6.5 — instrument the period→word→trapdoor chain; add word_gs (honest + attacker),
   trap_norm, and the l2_matches_wordpred cross-check to every per-period row.
5. Generalized timeline (J nodes); click-through detail (include word_gs vs threshold).
6. Consistency: panel and comparison share J; every result labelled (n, J).
7. Re-run at a couple of (n, J) you choose in the UI; confirm panel and table agree,
   and that word-norm prediction agrees with the measured L2 outcome per period.
Report the reconciled screen: one (n, J), per-period N0 comparison, per-period
period_gs AND word_gs, and control status.
