# PATCH 22 — Proof-level analysis: reduction-loss calculator + evidence-backed coverage map

> Two additions that attack the paper's SECURITY PROOF (Section 5), not just the scheme.
> A — Reduction-loss calculator: the paper's Theorem 1 gives security ≈ p/2m; plug real
> parameters + real LWE hardness through that loss and show the GUARANTEED security is
> vacuous at the paper's parameters.
> B — Coverage map: for each threat, show (1) the demonstrated attack proving it's real,
> and (2) the exact point in the paper's security game where the model cannot express it.
> B is EVIDENCE-BACKED, not an assertions table — every "not covered" cell links to a
> working attack result AND a proof-text pointer.
>
> New "Proof Analysis" tab. Reuses the estimator (PATCH-14) and existing attack results.
>
> HONESTY: A computes a GUARANTEE from the paper's own stated bound — label it "what the
> theorem guarantees", distinct from "what we measured breaks" (the real attacks). A
> vacuous guarantee ≠ a proven break (the scheme might still be secure for reasons outside
> this loose proof) — but it means THIS proof promises nothing at these parameters. State
> that distinction explicitly.

---

## A. Reduction-loss calculator

### A.1 The paper's bound (quote it in the UI)
Theorem 1 / the Analysis in §5.2.5: the challenger C solves LWE with probability ≈ p/2m,
where p = attacker's advantage against ciphertext indistinguishability, m = lattice column
count, and the 1/m factor is C's probability of guessing the break-in time correctly.
So: Adv_LWE(C) ≈ Adv_IND(A) / (2m).

### A.2 What this means for a security guarantee
A reduction says: "breaking the scheme ⇒ solving LWE." Contrapositive: "if LWE needs
2^λ_LWE work, then breaking the scheme needs at least ~2^λ_LWE · (reduction tightness)."
The loss factor 2m WEAKENS the guarantee: the scheme's guaranteed security is
λ_scheme ≥ λ_LWE − log2(2m).
(Because Adv_IND ≤ 2m · Adv_LWE, so an attacker needs the LWE work divided by at most 2m;
in bits, you LOSE log2(2m) bits of guarantee.)

### A.3 The calculator
```python
def reduction_guarantee(n, q, sigma):
    m = 2*n*ceil(log2(q))
    lam_lwe = estimate_lwe_bits(n, q, sigma)        # from PATCH-14 estimator (backend labelled)
    loss_bits = log2(2*m)
    lam_guaranteed = lam_lwe - loss_bits            # what Theorem 1 actually guarantees
    return {
        "n": n, "q": q, "m": m, "sigma": sigma,
        "lwe_bits": lam_lwe,
        "loss_bits": loss_bits,                      # log2(2m)
        "guaranteed_bits": lam_guaranteed,
        "vacuous": lam_guaranteed <= 0,              # proof promises nothing
        "meets_128": lam_guaranteed >= 128,
    }
```
Notes:
- This is a FIRST-ORDER loss (just the stated 2m). If other loss terms exist in the proof
  (e.g. hash-query counts q_H), add them and label each — but at minimum the explicit 2m
  factor is in the paper. State "we account for the explicit 2m loss; additional query-loss
  terms would only lower the guarantee further."
- lam_lwe comes from the estimator; carry its backend label and the "estimator overstates
  difficulty at small n" caveat from PATCH-14.

### A.4 Display (part of the Proof Analysis tab)
- A table over the SAME parameter grid you've used (n∈{4,8}, q∈{257,1153,4001}, plus a
  realistic row n=256,q~12289 for contrast):
  | n | q | m | LWE bits (est) | loss log2(2m) | guaranteed bits | verdict |
  verdict: "VACUOUS (≤0)" / "below 128" / "≥128".
- Expected: at the paper's params, guaranteed_bits is ≤ 0 or tiny → the proof's own bound
  guarantees nothing. At n=256 it may reach useful bits — but that's the row where the
  efficiency claims collapse (link to Boundary tab).
- Big statement: "The paper's Theorem 1 guarantees ≈ (LWE bits − log2(2m)). At its
  demonstration parameters this is {value} bits — the proof promises no security there,
  independent of whether a break exists."
- HONESTY line: "A vacuous guarantee means the proof is empty at these parameters, not
  that the scheme is necessarily broken (that is the separate, measured public-key break).
  Conversely a positive guarantee here would be meaningless because the estimator itself
  overstates difficulty at small n — so treat A as 'the proof's own bound is loose and
  empty at the evaluated parameters.'"

### A.5 Tests
- `test_guarantee_subtracts_loss`: guaranteed_bits == lwe_bits − log2(2m).
- `test_vacuous_at_paper_params`: at n=4,q=257 guaranteed_bits ≤ small threshold (report).
- `test_loss_grows_with_m`: larger m → larger loss_bits.
- `test_backend_labelled`: the LWE estimate carries its estimator backend label.

---

## B. Evidence-backed coverage map

### B.1 Principle
Each row = one threat. Each row carries TWO pieces of evidence, both clickable/visible:
- **Attack evidence:** a pointer to the demonstrated attack in THIS tool (tab + the measured
  result: e.g. "Public-Key tab: β=2 break, 6/6 cells" / "Ledger tab: replay same N0" /
  "Ledger tab: universal CT matched 10/10" / "Ledger tab: freq analysis 75% vs 19%"). This
  proves the threat is REAL (not hypothetical).
- **Model evidence:** a precise pointer into the paper's §5.2 security game showing the
  threat is not expressible — i.e. the oracle/notion that WOULD be needed is absent.

So each "not covered" is backed by: (real attack) + (proof text lacking the needed oracle).

### B.2 The rows (fill model-evidence from the paper's §5.2 game: oracles are Hash,
Trapdoor, Break-in, Challenge, Guess — NO ciphertext-submission oracle, NO authentication,
NO leakage notion, and the hardness assumption is LWE-hard which fails at the params):

| threat | demonstrated attack (tool evidence) | paper's model covers it? | model evidence (proof pointer) |
|---|---|---|---|
| ciphertext indistinguishability | — (this is the proven property) | YES | Theorem 1 proves exactly this |
| key recovery from public key | Public-Key tab: β=2, 6/6 cells | NO | proof assumes LWE hard (§5.2 Setup); at the paper's params LWE is not hard — assumption false, so the theorem's premise fails |
| offline KGA | KGA tab: keyword recovered from pk+trapdoor+dict | NO | game has no keyword-guessing notion; Trapdoor oracle exists but no advantage defined for guessing w |
| universal-ciphertext forgery | Ledger C: planted CT matched 10/10; random matched 0 | NO | no ciphertext-submission/decryption oracle in the game → chosen-ciphertext attacks unmodelled (passive IND-CKA only) |
| trapdoor replay | Ledger A: replay returned same N0, no secret | NO | no authentication of requester anywhere in the game or scheme |
| access-pattern leakage | Ledger B: Tier1 7/7 groups; Tier2 75% vs 19% | NO | game reveals nothing about on-chain observability; leakage function not modelled |
| forward security (as a proven property) | Forward Sec tab: vacuous (pk already breaks) | PARTIAL/ASSERTED | break-in phase is in the game setup but Theorem 1 proves indistinguishability, not an isolated forward-security statement; key-evolution one-wayness never proven |

### B.3 The two meta-findings this map demonstrates
1. **Almost none of the demonstrated attacks are expressible in the paper's security model.**
   Of 7 threats, the model covers 1 (the one it proves). The rest fall outside the game.
2. **The one property it proves (indistinguishability) has a vacuous guarantee at the
   evaluated parameters** (from Impl A). So the proof both (a) covers little and (b)
   guarantees nothing where it does cover.

### B.4 Implementation (make it evidence-backed, not static text)
- Build the table from the ACTUAL latest results of the other tabs where possible: pull the
  measured numbers (β, replay N0 match, plant 10/10, freq 75/19) from stored results so each
  row's "attack evidence" is a LIVE value, not hardcoded. If a result isn't available, show
  "run <tab> to populate" rather than a fake number.
- The "model evidence" column is textual pointers to §5.2 (these are analysis, not runnable
  — that's fine; they're citations to the paper's game). Mark them as "proof-text analysis".
- Each row clickable → expands to: the attack's result detail (from its tab) + the quoted
  game-oracle list showing the gap.

### B.5 Honesty
- Distinguish clearly: attack evidence = DEMONSTRATED (measured in-tool). Model evidence =
  ANALYSIS of the paper's proof (argued from the text, not executed). Label the two columns
  accordingly so no one thinks the "model evidence" is a run.
- "NO" means "the paper's security game cannot express this threat", not "we proved it
  unconditionally insecure". For key-recovery specifically, the premise (LWE-hard) fails at
  the params — state it that way, not "the proof is wrong".

### B.6 Tests
- `test_coverage_pulls_live_results`: rows pull measured values from stored results; missing
  result → "run <tab>", never a fabricated number.
- `test_coverage_two_evidence_columns`: every NO row has BOTH an attack-evidence pointer and
  a model-evidence (proof-pointer) string.
- `test_covered_row_is_theorem1`: the only YES row is ciphertext indistinguishability.

---

## C. Order
1. A: reduction_guarantee() using the PATCH-14 estimator; table over the param grid + the
   n=256 contrast row; vacuous-at-paper-params statement; honesty line.
2. B: coverage map pulling live attack results for the attack-evidence column; proof-text
   pointers for the model-evidence column; two-meta-findings summary.
3. "Proof Analysis" tab holding both, with the DEMONSTRATED vs ANALYSIS labelling.
Report: the reduction-loss table (guaranteed bits at paper params vs n=256), and the
coverage map with live attack numbers in the attack-evidence column.
