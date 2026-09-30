# PATCH 18 — "Network" tab: live doctor / cloud / verifier / attacker simulation

> A capstone interactive tab that stages the whole scheme as a network of nodes and lets
> the user drive real communication AND launch either attack at chosen periods. Ties
> together everything: honest search+decrypt, the public-key-only attack, and the
> stolen-key backward attack — as a live, node-based demo.
>
> Reuses the locked implementation (PATCH-12), frozen per-period DBs (PATCH-06), and the
> public-key-only attack (PATCH-14/16). The stolen-key backward attack is implemented
> FRESH in this tab for the first time (not previously built) — §2A specifies it in full.
> Keyword/plaintext (Level-2/Level-3) gating follows PATCH-16.
>
> HONESTY (enforced in the UI, non-negotiable):
> - Doctor decrypt is real (doctor has sk) → always shows true plaintext.
> - Attacker KEYWORD recovery: shown when the attack's trapdoor matches (same record).
> - Attacker PLAINTEXT recovery (Level 3): shown ONLY if Decrypt with the attack-derived
>   basis round-trips to the true plaintext; otherwise the node shows
>   "keyword ✓ / plaintext ✗ (decode bound)". NEVER fabricate plaintext.
> - Attacker uses ONLY public data (public-key attack) or sk_{stolen}+public (stolen-key
>   attack) — asserted in code; secret inputs shown locked in the attacker node.
> - Frozen DBs: attacks read stored ciphertexts, never regenerate them.

---

## 1. Layout — four nodes on a canvas

A node-graph canvas (doctor ↔ cloud ↔ verifier, attacker tapping the links). Each node
is a card; animated messages travel along the edges when actions run. Keep it clean —
show only the FEW parameters that actually vary, not the full parameter dump.

### Node: DOCTOR (data owner/user)
- Header shows the ACTIVE, CHANGING parameters only: `n`, `q`, `m` (derived), current
  period `j`, and a short key fingerprint (e.g. first 6 hex of a hash of pk_j). Not the
  full matrices — a "details" expander holds those.
- Actions:
  - **Add record**: pick a disease keyword + type a short record text → doctor encrypts
    (PEKS keyword + record) under pk_j → sends to cloud (animate edge). Appears in cloud.
  - **Search**: pick a disease → doctor builds a trapdoor (with sk_j) → sends to verifier.
  - **Advance period**: j → j+1 (KeyExt). Show the period counter tick; past records stay
    on the cloud (frozen).
  - **Decrypt any cloud record**: select any CM on the cloud → doctor decrypts with sk_j
    → shows the TRUE plaintext back in the doctor node. (Always works — doctor has sk.)

### Node: CLOUD (storage)
- Shows the stored DB as a list: period | record N | [CT keyword blob] | [CM record blob]
  | (disease tag hidden — it's encrypted). Grows as the doctor adds records across periods.
- Dumb storage: it just holds and returns blobs. Show it learning nothing.

### Node: VERIFIER (the blockchain/smart-contract search)
- Receives a trapdoor, runs Verify over the cloud's CT blobs, returns the matching
  sequence number(s) N0 to whoever asked. Animate: trapdoor in → N0 out.
- Show that Verify uses NO secret (public test) — this is the point that enables the KGA
  and the public-key attack. A small note: "verification is public; anyone can run it."

### Node: ATTACKER
- Shows ONLY what the attacker holds, per chosen attack:
  - public-key-only: pk_j (public), the cloud CT/CM blobs (public), disease dictionary.
    sk shown LOCKED/struck-through.
  - stolen-key: sk_{stolen period} (the one stolen secret) + public pk/R + cloud blobs.
    Earlier-period secrets shown LOCKED (attacker reconstructs them via §2A).
- Controls (see §2).

---

## 2. Attacker controls — choose attack, choose periods

- **Attack type toggle:** "Public-key only" | "Stolen key".
  - If Stolen key: a selector for WHICH period's key is stolen (default: latest).
- **Period checkboxes:** a row of checkboxes, one per period that exists on the cloud.
  The user ticks the periods they want to attack. Only ticked periods are attacked.
  (For stolen-key, only periods EARLIER than the stolen period are tickable — reaching
  back; tick a later one and it's disabled with a tooltip "can't reach forward".)
- **"Launch attack" button.** Runs the chosen attack on each ticked period:
  1. Obtain the attack basis (pk-only: from pk_i; stolen: reconstruct SK*_i from
     sk_stolen + public R).
  2. For each disease in the dictionary, trapdoor → search the frozen CT_i on the cloud
     → recover which record = which disease.
  3. Fetch the matching CM_i blobs.
  4. Attempt Decrypt(CM, SK_attack): show plaintext ONLY if it round-trips (Level-3
     gate); else "plaintext ✗ (decode bound)".
- **Per-attacked-period result panel:**
  | period | recovered disease(s) | ciphertext fetched | plaintext (if Level-3) | vs truth |
  Colour ticked periods green (recovered) / red-x (attack failed) on the timeline.

---

## 2A. Stolen-key backward attack — implemented FRESH here (first time)

Not built before. Implement it in this tab, reusing existing primitives:
```python
def stolen_key_attack(stolen_period, target_period_i, history, params, reducer):
    # attacker holds ONLY sk of stolen_period + public pk_i and R matrices + cloud blobs
    assert target_period_i < stolen_period            # can only reach BACKWARD
    sk_stolen = history[stolen_period].honest_sk       # the ONE stolen secret
    R_prod    = product_R(history, target_period_i, stolen_period)   # public
    R_inv     = integer_inverse(R_prod)
    cand      = balanced(R_inv @ sk_stolen, params.q)
    SK_star_i = extract_lattice_basis(reducer(stack_with_qI(cand, history[target_period_i].pk_i,
                                                            params.q)), params)
    assert all_columns_zero_mod_q(history[target_period_i].pk_i @ SK_star_i, params.q)
    return SK_star_i                                   # reconstructed period-i basis
```
Then, per ticked past period: for each disease in the dictionary, build a trapdoor from
`SK_star_i`, search the frozen `CT_i`, recover disease→record, fetch `CM`, and attempt
Decrypt (Level-3 gated). The attacker reads ONLY `sk_stolen` + public data — assert it
never reads `history[i].honest_sk` for i != stolen_period.

Frozen discipline: attacks read the stored `CT_i/CM_i`; never regenerate them with
`SK_star_i` (hash-guard + `test_frozen_cloud_immutable`).

---

## 2B. User-selectable parameters (n, q)

At the top of the Network tab, a compact parameter bar:
- **n** — dropdown: `{4, 8, 16}` (powers of 2; existing H2 supports these). Default 4.
- **q** — dropdown: `{257, 1153, 4001, 12289, 40961}` (all prime; ~8…16 bits). Default 257.
- **m** shown as derived (read-only): `m = 2n⌈log2 q⌉`, updates live when n or q change.
- **Apply / rebuild** button: regenerates the doctor keypair and clears the cloud/history
  for the new (n, q), then the demo runs on the chosen parameters.
- Note next to the bar: "Defaults (n=4, q=257) are the paper's demonstration parameters,
  where both attacks are fast. Larger (n, q) may make attacks slower or exceed a per-
  attack timeout — the Security Boundary tab characterises this."
- Guardrails: only offer (n, q) combinations that pass the correctness gate (PATCH-12);
  if a chosen pair fails correctness or H2, show "not available at these parameters"
  rather than a broken demo. Keep a per-attack timeout so a heavy (n, q) can't hang the UI
  (on timeout, the attacked period shows "unmeasured (timeout)", never "secure").



Because the public key alone already breaks these params, show — for any stolen-key
attack — a small inline note per period: "public-key-only would also recover this period"
(computed) so the demo never implies the stolen key was necessary when it wasn't. If a
period is recoverable by stolen key but NOT by public key alone, flag it GOLD: "genuine
forward-security break (stolen key required)".

Negative-control toggle: "use garbage key" — runs the same flow with a BKZ'd garbage
basis; must recover nothing. Lets the presenter show live that recovery isn't an artifact.

---

## 4. Scripted "demo flow" button (for the eval)

A **"Run demo script"** that walks the whole story hands-free, pausing at each step:
1. Doctor adds 3 records (diseases) at period 0 → cloud.
2. Doctor searches "diabetes" → verifier returns N0 → doctor decrypts that record → true
   plaintext shown. (Honest scheme works.)
3. Advance to period 1, 2 (more records each). 
4. Attacker: public-key-only, tick all periods → recovers diseases (+ plaintext if
   Level-3) from public data alone. Banner: "no secret key used."
5. Attacker: stolen key at period 2, tick periods 0–1 → recovers past diseases +
   ciphertexts; comparison strip shows public key already could too → "forward security
   vacuous."
6. Garbage-key control → recovers nothing.
Each step animates the relevant edges and updates the nodes. This is the eval walkthrough.

---

## 5. Honesty / correctness (enforced)

- Level-3 plaintext gate everywhere (attacker plaintext only if Decrypt round-trips).
- Doctor decrypt always real.
- Attacker input assertions (no sk in pk-only path; only sk_stolen in stolen path).
- Frozen cloud blobs; attacks never regenerate them (hash-guard).
- Only ticked, allowed periods attacked; forward-reach disabled for stolen key.
- Parameter note: default n=4,q=257 (paper's params, both attacks fast); selectable.

---

## 6. Tests

- `test_doctor_decrypt_true_plaintext`: doctor decrypts any cloud record to true M.
- `test_attacker_keyword_recovery`: ticked period → recovered disease matches truth.
- `test_attacker_plaintext_gated`: plaintext shown iff Decrypt round-trips.
- `test_period_checkbox_scope`: only ticked periods attacked; stolen-key can't tick
  forward periods.
- `test_pk_only_no_secret` / `test_stolen_only_stolen_sk`: input assertions hold.
- `test_garbage_control_recovers_nothing`.
- `test_frozen_cloud_immutable`.
- `test_comparison_strip`: stolen-key period marked "pk-only also recovers" unless it's a
  genuine forward-security break.
- `test_stolen_key_backward_only`: stolen_key_attack rejects target_period >= stolen_period
  (can't reach forward); reconstructed SK_star_i is in L⊥_q(pk_i).
- `test_stolen_reads_only_stolen_sk`: the stolen-key path reads only sk_stolen + public;
  monkeypatch other-period honest sk to raise; attack still runs.
- `test_param_selector_derives_m`: changing n or q updates m = 2n⌈log2 q⌉ live.
- `test_param_correctness_gate`: an (n,q) that fails the correctness gate is offered as
  "not available", never runs a broken demo.
- `test_param_timeout_not_secure`: an attack that times out at a heavy (n,q) shows
  "unmeasured (timeout)", never "secure".

---

## 7. Order
1. Canvas + four node cards (doctor/cloud/verifier/attacker), edges, message animation.
2. Parameter bar (§2B): n and q dropdowns, live-derived m, Apply/rebuild, correctness gate.
3. Doctor actions: add record, search, advance period, decrypt-any-cloud-record (real).
4. Verifier: public Verify → N0. Cloud: blob store.
5. Attacker: attack-type toggle, stolen-period selector, per-period checkboxes (scoped).
   Implement the FRESH stolen-key backward attack (§2A) + the existing public-key attack.
   Launch → per-period recovered disease + ciphertext + gated plaintext + vs-truth.
6. Comparison strip (pk-only-also-recovers / gold forward-break) + garbage control.
7. "Run demo script" guided walkthrough.
8. Enforce all §5 honesty rules + tests.
Report: a screenshot of the network with a completed public-key attack and a completed
stolen-key attack across ticked periods, the per-period recovered-vs-truth results, the
doctor decrypting a cloud record to true plaintext, and the n/q selector working.