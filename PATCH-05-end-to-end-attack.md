# PATCH 05 — End-to-end forward-security attack: frozen per-period DBs + interactive timeline

> Apply after PATCH-04. Purpose: upgrade Finding 2 from a NORM proxy to a FUNCTIONAL
> demonstration. Build the honest doctor's searchable database at each period, FREEZE
> it, evolve keys forward to period J, then let the attacker — holding only SK_{r|J}
> and public R's — reconstruct SK*_{r|i} and attempt the OLD search (and decrypt) on
> the FROZEN period-i database. Success = the attacker's trapdoor returns the SAME
> sequence number N0 the legitimate doctor got.
>
> UX: a clickable period timeline (period 0..J-1). Clicking period i runs the backward
> attack against that period's frozen DB and shows per-level pass/fail live.
>
> HONESTY GUARDRAILS (unchanged + one new, critical):
> - NEW, CRITICAL: the attacker attacks the FROZEN ciphertexts created when period i
>   was current. NEVER regenerate CT_i or CM with the recovered key — that would be
>   circular and prove nothing. The frozen DB is created once, forward, and is
>   immutable. Assert immutability in code.
> - Level-2 success is ONLY "same N0 as the legitimate doctor," on the frozen DB.
> - Level-3 requires reading the paper's Decrypt to confirm what secret it needs.
> - Verdicts from measured results; per-n, per-level; never averaged or cherry-picked.
> - Keep demo-params / one-attack-family caveats.

---

## 0. FIRST: read the paper's Encrypt / Decrypt (blocking sub-task)

Before building Level 3, inspect PPSEB.Encrypt and PPSEB.Decrypt in the paper and
record, in a `note` trace event, EXACTLY what secret material Decrypt consumes:

- Paper: `M0 <- PPSEB.Decrypt(CM0, j, SK_{r||j})`. So Decrypt takes the period secret
  `SK_{r||j}` and nothing else patient-side. IF that is the whole story, then a
  recovered `SK*_{r|i}` that is short enough MAY also decrypt the old record →
  Level 3 is reachable.
- BUT verify there is no separate record-encryption key / patient secret needed. If
  Encrypt uses `pk_{r||j}` only (public) and Decrypt uses `SK_{r||j}` only, Level 3 is
  reachable in principle. If Decrypt needs anything the attacker doesn't have, RECORD
  THAT — "record confidentiality is protected by a separate secret the forward-security
  break does not touch" is itself a finding, and Level 3 is then reported as
  "not reachable by this attack (by construction)."

Emit the conclusion as a `note`: `level3_reachable_in_principle: true|false, because ...`.

---

## 1. Forward pass — build and FREEZE per-period databases

Do this ONCE per experiment, going forward from period 0 to J-1. At each period i, the
"honest doctor / patient" system is in state `(pk_{r|i}, sk_{r|i})`, and we record an
immutable snapshot:

```python
@dataclass(frozen=True)   # frozen => immutability enforced
class PeriodDB:
    period: int
    pk_ri: Matrix                    # public key at period i
    # the searchable database created AT period i (the doctor's real data):
    records: tuple                   # tuple of (N, keyword, M_plaintext)  -- frozen
    CT: tuple                        # tuple of (N, CT_i1, CT_i2) keyword ciphertexts
    CM: tuple                        # tuple of (N, CM_encrypted_record)
    legit_trap_demo: dict            # ONE legitimate (keyword, Trap, N0) as ground truth
    R_into_next: Matrix              # R used to evolve i -> i+1 (public)

def build_frozen_history(J, params, dictionary, h1_variant="low_norm"):
    root_pk, root_sk = trapgen(params)
    history = []
    pk, sk = root_pk, root_sk
    for i in range(J):
        # patient builds a small DB at period i
        records = sample_records(dictionary, k=RECORDS_PER_PERIOD, seed=i)  # (N,kw,M)
        CT = tuple((N, *PEKS_encrypt(pk, kw, i, params)) for (N,kw,M) in records)
        CM = tuple((N, record_encrypt(pk, M, i, params)) for (N,kw,M) in records)
        # ground-truth: legitimate doctor searches for one known keyword
        target_kw = records[GROUND_TRUTH_IDX][1]
        legit_trap = Trapdoor(pk, sk, i, target_kw, params)
        N0_legit   = verify_search(CT, legit_trap, params)   # returns matching N or None
        assert N0_legit is not None, "legit doctor must find its own record"
        R = H1(pk, i+1, variant=h1_variant) if i < J-1 else None
        history.append(PeriodDB(i, pk, records, CT, CM,
                                {"keyword": target_kw, "N0": N0_legit}, R))
        # evolve forward (honest chain)
        if i < J-1:
            pk = mod(pk @ inv(R, params), params.q)
            sk = new_basis_del(history[i].pk_ri, R, sk, sigma_for(sk,params))  # keep usable
    return history
```

Notes:
- `RECORDS_PER_PERIOD` small (e.g. 5). `GROUND_TRUTH_IDX` fixed so N0_legit is stable.
- Keep the legit chain USABLE (PATCH-03 sigma-scaling + reduction) so the honest
  side genuinely works at every period — otherwise the comparison is meaningless.
- `verify_search(CT, trap, params)`: runs PPSEB.Verify over each CT entry, returns the
  N of the matching one (or None). This is the SAME routine used for the attacker.
- FREEZE: PeriodDB is frozen; do not mutate after creation. Attacker reads it only.

---

## 2. Backward attack — reconstruct SK*_{r|i} from the stolen SK_{r|J}

Attacker holds ONLY: `sk_{r|J}` (stolen current), all public `pk_{r|i}` and `R_i`
(hence any product), and the frozen `history[i]` ciphertexts. Never the honest `sk_{r|i}`.

```python
def attack_period(history, i, J, params, reducer):
    Rprod     = product_R(history, i, J)          # R_{i+1} ... R_J   (public)
    Rprod_inv = integer_inverse(Rprod)            # I+N products invert over Z
    sk_J      = history[J-1_stolen_sk]            # the stolen basis (pass explicitly)
    cand_raw  = balanced(Rprod_inv @ sk_J, params.q)
    cand      = extract_lattice_basis(reducer(stack_with_qI(cand_raw, history[i].pk_ri,
                                                            params.q)), params)
    assert all_columns_zero_mod_q(history[i].pk_ri @ cand, params.q)  # in L^perp_q(pk_i)
    sk_star   = cand                              # SK*_{r|i}

    result = {"period": i, "gs_norm": gs_norm(sk_star)}

    # LEVEL 1: norm proxy
    thr = usability_threshold(params)["threshold"]
    result["level1_norm_ok"] = result["gs_norm"] <= thr

    # LEVEL 2: actual OLD keyword search on the FROZEN db
    kw = history[i].legit_trap_demo["keyword"]
    try:
        trap_star = Trapdoor(history[i].pk_ri, sk_star, i, kw, params)  # uses SK*
        N0_star   = verify_search(history[i].CT, trap_star, params)     # frozen CT!
    except Exception as e:
        N0_star = None
        result["level2_error"] = str(e)
    result["N0_legit"]   = history[i].legit_trap_demo["N0"]
    result["N0_star"]    = N0_star
    result["level2_search_break"] = (N0_star is not None
                                     and N0_star == result["N0_legit"])

    # LEVEL 3: old record decryption (only if reachable per §0)
    if LEVEL3_REACHABLE and result["level2_search_break"]:
        CM_N0 = lookup(history[i].CM, result["N0_legit"])
        try:
            M_star = record_decrypt(CM_N0, i, sk_star, params)          # paper Decrypt
            M_true = lookup_plain(history[i].records, result["N0_legit"])
            result["level3_plaintext_break"] = (M_star == M_true)
        except Exception as e:
            result["level3_plaintext_break"] = False
            result["level3_error"] = str(e)
    else:
        result["level3_plaintext_break"] = False
        result["level3_reachable"] = LEVEL3_REACHABLE
    return result
```

CRITICAL asserts:
- `history[i].CT` and `.CM` are the FROZEN ones from the forward pass. Add a hash/guard
  so a test can prove they were not regenerated with sk_star.
- The attacker's `Trapdoor` and `verify_search` are the SAME code paths the doctor uses
  — the only difference is `sk_star` vs the honest `sk`.

---

## 3. Success criteria (per period i, per n)

- **Level 1 pass:** `gs_norm(sk_star) <= threshold`.
- **Level 2 pass (THE forward-security functionality break):** `N0_star == N0_legit`
  on the frozen DB. This is the headline pass/fail — a recovered OLD search capability.
- **Level 3 pass (confidentiality break):** `M_star == M_true` via the paper's Decrypt.

Report a table: period i | periods_back | gs_norm | L1 | L2 (N0*==N0) | L3 (M*==M) | verdict.
Run at n=4 and n=6 (the dimensions where PATCH-04 showed break/no-break) with
BKZ_vs_BKZ (fair) tooling. Expectation to VERIFY, not assume: L2 passes at n=4
(matching the norm break), fails at n=6; L3 may lag L2 (stricter decode bound).

---

## 4. UI — interactive period timeline (Forward Security tab, new panel "End-to-end attack")

- A horizontal timeline of periods `0 … J-1`, plus a marker at `J` labelled
  "attacker compromises SK here." Each period node shows a small DB icon
  ("frozen DB: k records").
- **Click a period i** → runs `attack_period(history, i, ...)` and animates:
  1. "Attacker holds SK_{r|J} (stolen) + public R's" (show what's public vs secret).
  2. "Compute R⁻¹ · SK_{r|J} → BKZ-reduce → SK*_{r|i}" (show gs_norm vs threshold; L1 badge).
  3. "Derive Trap*_{w|i} from SK*_{r|i}" (NewBasisDel → SamplePre).
  4. "Search FROZEN CT_i" → show N0_star; compare to N0_legit. Big badge:
     **L2: SEARCH RECOVERED (N0*=N0=..)** or **L2: failed (N0*=.. ≠ ..)** or
     **L2: no match**.
  5. If reachable & L2 passed: "Decrypt CM_{N0} with SK*_{r|i}" → show M_star vs M_true.
     Badge **L3: PLAINTEXT RECOVERED** or **L3: failed (basis not short enough to decode)**.
- Colour each timeline node by outcome: green = L2 (and/or L3) broke this period, grey
  = attack failed here. So the whole timeline shows, at a glance, WHICH old periods are
  compromised from a single stolen SK_{r|J}.
- Side note text: "Honest doctor at period i found N0 using SK_{r|i}. Attacker, with
  only SK_{r|J} from a LATER period, reached back and " + (recovered the same N0 /
  could not). Make the equivalence explicit.
- Keep the fair-tooling matrix result (PATCH-04) visible above so the viewer knows the
  attacker is BKZ-equipped.
- Keep caveats: demo params; one attack family; L2≠L3; and — if some periods break and
  others don't — state the pattern honestly ("periods within X of the compromise break;
  older ones don't, at these params").

---

## 5. The honest headline this produces (fill from measured data)

> **Finding 2 — end-to-end forward-security demonstration (low-norm H1, fair BKZ tooling):**
> A single stolen SK_{r|J} lets the attacker reconstruct SK*_{r|i} for earlier periods.
> At n={n}, this recovers the OLD SEARCH capability for period(s) {list} — the attacker's
> trapdoor returns the SAME sequence number N0 the legitimate doctor obtained, on the
> untouched frozen ciphertext database (Level 2 break). Plaintext recovery (Level 3)
> {succeeds/fails} because {the recovered basis clears / does not clear} the record
> decode bound. At n={n2} no period breaks. This is a functionality-level forward-security
> break at demonstration parameters, confined to periods near the compromise; whether it
> reaches cryptographic parameters is open (needs large-n BKZ estimates).

If NO period breaks under fair tooling at the tested n, report that instead, honestly:
"the recovered basis never yields a working old trapdoor at tested params — the norm
proxy overstated the threat; forward-security functionality resists this attack here."

---

## 6. Tests

- `test_frozen_db_immutable`: CT_i/CM_i hash before and after an attack run are equal
  (attacker did NOT regenerate them).
- `test_legit_doctor_finds_own_record`: N0_legit is not None for every period.
- `test_level2_same_N0_definition`: level2_search_break is True IFF N0_star==N0_legit
  and N0_star is not None.
- `test_attacker_uses_frozen_ct`: attacker's verify_search is called with history[i].CT
  (the frozen tuple), asserted by object identity/hash.
- `test_level3_gated_on_reachability`: if LEVEL3_REACHABLE is False, level3 is always
  False and reports "not reachable", regardless of norms.
- `test_no_break_reported_honestly`: if no period yields N0_star==N0_legit, the summary
  says "resists," not "broken."

---

## 7. Order
1. §0 read Encrypt/Decrypt → set LEVEL3_REACHABLE + note.
2. §1 build_frozen_history (forward, frozen) + legit ground-truth N0.
3. §2 attack_period (backward, fair BKZ) + asserts.
4. §3 run n=4, n=6; record per-level table.
5. §4 interactive timeline UI.
6. §5 fill the honest headline from measured data.
Report per-period, per-level, per-n results. Every claim sourced from a measured N0
comparison, not a norm.
