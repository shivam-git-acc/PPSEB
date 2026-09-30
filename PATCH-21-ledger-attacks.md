# PATCH 21 — Ledger-metadata attacks: replay, access-pattern leakage (Tier 1+2), universal-ciphertext plant

> Three related findings that need NO crypto break and (mostly) NO secret — they exploit
> the paper's central design choice (public on-chain search) and its missing
> authentication / well-formedness checks. All are parameter-independent: they hold even
> if the lattice parameters were secure.
>
> A. REPLAY — capture a doctor's trapdoor off the public ledger, replay it, retrieve the
>    record. No forgery, no key, no auth check in the paper.
> B. ACCESS-PATTERN LEAKAGE — Tier 1 (certain: which records searched, how often, co-access)
>    and Tier 2 (statistical: frequency-match observed access to a public disease
>    distribution → label encrypted records, measured vs ground truth AND vs random baseline).
> C. UNIVERSAL-CIPHERTEXT PLANT (Target 2) — plant CT₂=0,CT₁=⌊q/2⌋𝟙; with no
>    write-authentication and no well-formedness check it verifies against every trapdoor,
>    poisoning all searches.
>
> Reuses locked implementation (PATCH-12), frozen DBs, real Verify. New "Ledger Attacks" tab.
>
> HONESTY (critical, esp. Tier 2):
> - Tier 2 must NOT be circular. The attacker maps observed frequencies to an INDEPENDENT
>   public reference distribution, and labeling accuracy is measured vs ground truth AND vs
>   a random-guess baseline. "Recovered X% vs Y% random" is the claim; X≈Y means it failed.
> - Replay/plant require the paper's actual flow (public trapdoors, no requester auth, no
>   well-formedness check). Confirm the implementation matches the paper (no auth added);
>   if the impl added auth the paper lacks, note it and attack the paper's spec explicitly.
> - Classify: replay = confidentiality (retrieves real record); leakage = confidentiality
>   (infers disease from metadata); plant = integrity/DoS.

---

## A. Replay attack

Flow: doctor searches → Trap submitted to blockchain (public tx) → verifier returns N0 →
cloud returns CM_{N0}. The paper authenticates NO ONE in this path.

```python
def replay_attack(captured_trap, blockchain, cloud):
    # attacker read captured_trap from the PUBLIC ledger (a past doctor tx). No secret.
    N0 = blockchain.verify_and_return_seqno(captured_trap)   # same public Verify
    CM = cloud.fetch(N0)                                      # no requester auth in paper
    return N0, CM     # attacker now holds a real patient's record ciphertext
```
- Demo: doctor runs a real search (Trap goes on-chain). Attacker captures it FROM the
  ledger, replays it, gets the same N0 and the same CM the doctor got. Show attacker
  holding the record ciphertext. If the doctor's key isn't needed to identify the record
  (it isn't — N0 is plaintext), the confidentiality break is: attacker learns WHICH record
  a doctor accessed and pulls that ciphertext.
- Level-3 (optional, gated): can the attacker decrypt CM? Only if they also have a key —
  they don't, so state "attacker obtains the record CIPHERTEXT and its identity, not
  plaintext (unless combined with the key-recovery break)." Keep honest: replay alone gives
  ciphertext + access linkage, not plaintext.
- Control: a random (non-captured) byte string as "trapdoor" must NOT return a valid N0.
- Note: works at ANY parameters — it's an access-control gap, not a crypto break.

---

## B. Access-pattern leakage

### Setup (realistic, non-circular)
- Assign each record a disease drawn from a PUBLIC reference distribution D_ref (e.g. a
  realistic prevalence table: diabetes common, rare diseases rare). Store D_ref separately
  as the attacker's PRIOR — the attacker knows population base rates, NOT the mapping.
- Simulate doctor behaviour: run many searches whose keyword frequencies follow a query
  distribution D_query (may equal D_ref, or differ — test both; state which).
- The ONLY thing the attacker sees: the on-chain (trapdoor_id → N0) transactions + timing.
  NOT the diseases, NOT the mapping.

### Tier 1 — certain, no prior needed
From the (trapdoor→N0) tx log alone, compute and DISPLAY:
- per-record access count (which N0 returned how often) → "hot vs cold records".
- co-access: trapdoors returning overlapping N0 sets → cluster related searches.
- a search-pattern graph over encrypted records.
Claim: "without any crypto or prior, the public ledger reveals which encrypted records are
searched, how often, and which searches are related." Show the histogram + co-access clusters.

### Tier 2 — statistical, uses the public prior (MUST be non-circular)
```python
def frequency_analysis(tx_log, D_ref):
    obs_freq = access_counts_per_record(tx_log)          # observed, from ledger only
    obs_rank = rank_records_by_frequency(obs_freq)       # most→least accessed record
    ref_rank = rank_diseases_by_prevalence(D_ref)        # most→least common disease (PUBLIC)
    labeling = assign(obs_rank[i] -> ref_rank[i])        # frequency-match
    return labeling
```
- Measure: accuracy of `labeling` vs GROUND TRUTH (the hidden record→disease map).
- **Baseline (mandatory, kills circularity):** random-permutation labeling accuracy over
  many shuffles → expected-by-chance accuracy. Report BOTH: "frequency analysis labels
  {X}% correctly vs {Y}% random baseline (n diseases)." The finding is X ≫ Y. If X ≈ Y,
  report honestly that frequency analysis did NOT beat chance here.
- Sweep the number of observed queries (10, 100, 1000, ...) and plot accuracy rising with
  observations → shows leakage accumulates over time.
- Test D_query = D_ref (best case) AND D_query ≠ D_ref (attacker's prior imperfect) → show
  how accuracy degrades when the query distribution differs from the assumed prior. State
  the assumption explicitly.

### The framing point (put on the tab)
Traditional PEKS leaks access pattern to ONE private server. PPSEB's contribution —
public on-chain verification — broadcasts it to EVERYONE. The blockchain converts
single-server leakage into public leakage. The contribution is the vulnerability.

---

## C. Universal-ciphertext plant (Target 2, now demonstrated)

```python
CT_star = (floor(q/2)*ones(1,l), zeros(m,l))     # CT2=0 -> y=CT1=⌊q/2⌋1 for any Trap
blockchain.submit_index_entry(N_star, CT_star)   # no write-auth, no well-formedness check
```
- Demo: plant (N*, CT*). Then doctor searches ANY keyword → verifier returns the real N0
  AND N* (universal match) → doctor's results poisoned. Plant several → every search
  drowns in false N*.
- Control (mandatory): plant a RANDOM ciphertext (not the crafted CT*) → must NOT match
  arbitrary trapdoors. Crafted-matches-all + random-matches-nothing = real forgery, not a
  permissive-Verify artifact.
- Classify: INTEGRITY / DoS (poisons results; reveals no keyword).
- Threat-model note (from our analysis): the paper has neither write-authentication nor
  well-formedness checking, so this succeeds as specified. Authenticated writes mitigate it
  ONLY under a non-compromised-patient assumption; well-formedness verification mitigates it
  even under patient compromise (a malformed CT can't be proven well-formed). State this.

---

## D. UI — "Ledger Attacks" tab

- Three panels: Replay | Access-Pattern Leakage | Universal-Ciphertext Plant.
- **Replay:** doctor searches (Trap → ledger animation) → attacker "capture from ledger"
  button → "replay" → shows same N0 + CM obtained, with "no secret used / no auth in path".
- **Leakage:** controls for #records, #queries, D_ref vs D_query. Tier 1: access histogram
  + co-access clusters. Tier 2: labeling accuracy vs random baseline (big number pair),
  accuracy-vs-#queries curve, and the D_query≠D_ref degradation. All from ledger metadata
  only — show the attacker's view contains no diseases.
- **Plant:** plant CT* button → run a search → results table shows real hit + poisoned N*
  highlighted; random-plant control shows no poisoning.
- Each panel: classification badge (confidentiality / integrity), parameter-independence
  note, and the "blockchain contribution = the vulnerability" framing where it applies.

---

## E. Tests

- `test_replay_returns_same_record`: replayed captured trap → same N0 as the doctor; random
  string → no valid N0.
- `test_replay_no_secret`: replay path reads no sk.
- `test_tier1_access_counts`: access histogram matches the simulated query log exactly.
- `test_tier2_beats_baseline`: on D_query=D_ref with enough queries, labeling accuracy >
  random baseline by a clear margin; assert the baseline is computed and reported.
- `test_tier2_not_circular`: labeling uses only tx_log + D_ref (public prior), never the
  ground-truth map; monkeypatch the map to raise, attack still runs.
- `test_tier2_degrades_offdist`: accuracy with D_query≠D_ref < accuracy with D_query=D_ref.
- `test_plant_matches_all`: CT* matches every trapdoor via real Verify; random ciphertext
  does not.
- `test_plant_classified_integrity`: plant result tagged integrity/DoS, not confidentiality.

---

## F. Order
1. Confirm the impl matches the paper's flow: public trapdoors, no requester auth, no
   well-formedness check, plaintext N0. Note any deviation.
2. A — replay (capture from ledger → replay → same N0/CM) + control + no-secret assert.
3. B — Tier 1 (access counts, co-access) then Tier 2 (frequency-match vs baseline,
   accuracy-vs-queries, off-distribution degradation). Non-circular asserts.
4. C — universal-ciphertext plant + random-plant control + integrity classification +
   threat-model note.
5. "Ledger Attacks" tab with the three panels + framing.
Report: replay (same N0 obtained, no secret), Tier 1 histogram, Tier 2 accuracy vs random
baseline + accuracy-vs-queries curve, and the plant poisoning a search with random-plant
control. Confirm all are parameter-independent.
