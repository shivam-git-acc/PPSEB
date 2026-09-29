# PATCH 16 — "Public-Key Break" demo tab: recover the disease keywords from the public key alone

> A dedicated demonstration tab that makes the parameter-insecurity finding VISCERAL:
> the attacker holds ONLY the public key, and recovers WHICH DISEASE each encrypted
> record is tagged with — shown on screen as recovered keywords, next to the ground
> truth. Not "it broke (β=2)" but "here is what we read from public data alone."
>
> Reuses the locked implementation (PATCH-12) and the public-key-only attack (PATCH-14):
> no secret key, no TrapGen. This is a presentation/demo layer over the already-proven
> attack — the finding is real; this shows its consequence.
>
> HONESTY (must be enforced on screen):
> - Recovering the DISEASE KEYWORD (the tag) is the confidentiality break — show it.
> - Recovering the FULL RECORD PLAINTEXT is a SEPARATE, stronger claim — only shown if
>   Decrypt with the attack-derived basis actually round-trips. Label the two distinctly.
> - The attacker uses ONLY the public key + the public ciphertext DB + a disease
>   dictionary. No secret key, no captured trapdoor, no TrapGen. Assert this in code.
> - Same-N0 / same-record matching is the success criterion; negative control must fail.

---

## 1. Setup (what exists on screen before the attack)

- A small medical database the "patient/doctor" side created: e.g. 6–10 records, each
  tagged with a disease keyword from a realistic set (diabetes, hypertension, HIV,
  cancer, asthma, hepatitis, ...). Show it as: record N -> [encrypted keyword CT_N] +
  [encrypted record CM_N]. The plaintext disease is the GROUND TRUTH, hidden from the
  attacker panel but shown to the viewer as "truth" for comparison.
- Clearly mark what the attacker can see: pk (public key), the ciphertext DB (CT_N,
  CM_N — public/on cloud), and a DISEASE DICTIONARY (public knowledge — diseases are
  low-entropy, enumerable). Mark sk as HIDDEN (attacker does NOT have it).

Use parameters where the attack is proven to work fast: n=4, q=257 (paper's params) by
default, selectable.

---

## 2. The attack (public key only — button: "Attack with public key only")

Step through, animated in the trace:
1. "Attacker has only the public key." Show pk, no sk.
2. "Build a lattice basis from pk alone" (stack pk with q·I → the q-ary lattice). No
   secret used — assert `sk` is never read.
3. "Reduce it (BKZ β=2 / LLL-level)" → recovered basis SK_pk. Show its gs_norm next to
   the lattice's expected shortest vector and the honest secret basis norm — the three
   are ~equal (2.79 / 2.9 / recovered). Caption: "the public basis is as short as the
   secret — the secret confers no advantage."
4. "For each disease in the dictionary, generate a trapdoor from SK_pk and search the
   encrypted DB." For each disease d: Trap_d = trapdoor(pk, SK_pk, d); run Verify over
   every CT_N; record which records match.
5. **Recovered labelling:** produce, from public data only, a table:
   record N -> recovered disease (the dictionary word whose trapdoor matched CT_N).

---

## 3. What to SHOW (the conclusive part)

- **Recovered vs Truth table:** for each record N: [recovered disease] | [true disease]
  | ✓/✗. With the public-key attack working, these should MATCH. Big banner:
  "Recovered the disease of {k}/{total} records using only the public key."
- This is the confidentiality break made concrete: the attacker read each patient's
  disease tag from public data. State it exactly that way.
- **Optional stronger claim — full record plaintext (Level 3):** attempt
  `Decrypt(CM_N, SK_pk)` for a matched record. If it round-trips to the true plaintext,
  show "full record recovered: {plaintext}". If it does NOT (basis not short enough for
  the record decode bound), show "record TExt not recovered (decode bound) — but the
  disease tag WAS recovered." NEVER claim plaintext recovery unless Decrypt actually
  round-trips. Keep this visually separate from the keyword recovery.

---

## 4. Controls & honesty (on the same screen)

- **Negative control:** run the same labelling with a BKZ'd GARBAGE basis (not from pk).
  It must FAIL to label records (no consistent matches). Show it side by side: "garbage
  basis → no recovery; public-key basis → full recovery." This proves the recovery is
  due to the attack, not an artifact of a permissive search.
- **No-secret assertion:** a visible "attacker inputs" box listing exactly pk + CT DB +
  dictionary, with sk shown struck-through / locked. Back it with a code assert that the
  attack path never reads sk.
- **Parameter note:** "Demonstrated at the paper's parameters (n=4, q=257). The attack
  is LLL-level (BKZ β=2). At larger parameters the attack cost grows (see Security
  Boundary tab); this demo shows the consequence at the parameters the paper evaluates."

---

## 5. The one-line conclusion (auto-filled, on the tab)

> "Holding only the public key, the disease-keyword dictionary, and the public ciphertext
> database, the attacker recovered the disease tag of {k}/{total} patient records at the
> paper's own parameters (n=4, q=257), using LLL-level effort and no secret key. A
> garbage basis recovers nothing. This directly falsifies the paper's confidentiality
> claim at these parameters: no key compromise is needed to learn which disease each
> encrypted record concerns."

---

## 6. Tests

- `test_pk_demo_no_secret`: the demo attack path never reads sk (assert / monkeypatch sk
  to raise; attack still runs).
- `test_recovered_matches_truth`: at n=4,q=257 the recovered disease labels match ground
  truth for the matched records.
- `test_garbage_control_recovers_nothing`: BKZ'd garbage basis yields no consistent
  record labels.
- `test_level3_gated`: full-plaintext recovery is reported only if Decrypt round-trips;
  otherwise the tab shows keyword-only recovery.
- `test_dictionary_public`: dictionary is treated as public input (no secret leakage
  into it).

---

## 7. Order
1. Build the visible setup (records, disease tags, ciphertext DB, attacker-inputs box).
2. Wire the public-key-only attack → per-disease trapdoor → search → recovered labels.
3. Recovered-vs-Truth table + the k/total banner.
4. Negative control (garbage basis recovers nothing) side by side.
5. Optional Level-3 plaintext attempt, gated on Decrypt round-trip.
6. Auto-conclusion line; parameter note.
Report: the Recovered-vs-Truth table at n=4,q=257, the k/total count, and the garbage-
control result. Confirm the attack path reads no sk.
