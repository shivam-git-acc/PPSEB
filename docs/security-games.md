# Security games the paper does not define

Deck finding 10: PPSEB's security model (§2.2) is one game, ciphertext
indistinguishability with a break-in phase. Of the seven threats the mid-sem
analysis found, it can express one. This document writes down the games for the
other six, plus the two that MedVault-PQ adds (cloud integrity and revocation),
and points each one at the automated test that runs it as an experiment.

**What these are, and what they are not.** Each game is stated in the usual
challenger/adversary form so a reader can see exactly what "the attack
succeeds" means. Each test *instantiates* the game at toy parameters
(n = 4, q = 257 for the lattice parts) and measures the adversary's success.
A passing test is evidence about this implementation at these parameters. It is
not a proof, and nothing here is claimed as one.

Numbering follows the mid-sem deck (findings 1–10). Measured values come from
`python -m medvault.repro` (seed 42; KGA cells are every dictionary keyword × 2
seeds = 20 trials; leakage cells are 10 seeds × 20 records × 300 searches).
Test references are `file::test`, relative to `PPSEB/`.

Modes: **A** PPSEB as published · **A′** A plus a CT₂ shape check on writes ·
**B** keyed HMAC index, signed one-time requests · **C** PPSEB on
`HMAC(K_pd, keyword)` (PAEKS-style).

---

## G0 · Ciphertext indistinguishability (the paper's own game)

The paper's §2.2 game: the adversary picks two keywords, receives a PEKS
ciphertext of one of them in the break-in period, and must say which. Theorem 1
reduces it to LWE with a loss of log₂(2m) bits.

- **Measured.** At n = 4, q = 257 the reduction guarantees at most ≈ 7.4 bits
  (LWE ≈ 14.6 bits minus 7.2 bits of loss). A loose proof is not a break; the
  measured break is G1.
- **Tests.** `backend/tests/test_proof.py::test_guarantee_at_paper_params_is_worthless`,
  `backend/tests/test_proof.py::test_guarantee_is_not_claimed_as_a_break`.

## G1 · Key recovery from the public key (deck finding 2)

**Setup.** The challenger runs TrapGen and publishes `pk`, `μ` and the
ciphertext database. **Adversary** gets only that. **Wins** if it labels the
records with their keywords (and, separately, decrypts them).

- **Measured.** At the paper's parameters the adversary recovers every record's
  tag at BKZ block size 2; a basis from an unrelated lattice recovers nothing.
  This is a parameter failure, not an LWE break.
- **Fix.** Larger, structured parameters (Module-LWE). Design-only: see
  [design-only-fixes.md](design-only-fixes.md#1-module-lwe-redesign).
- **Tests.** `backend/tests/test_pk_demo.py::test_recovered_matches_truth`,
  `backend/tests/test_pk_demo.py::test_garbage_control_recovers_nothing`,
  `backend/tests/test_pk_demo.py::test_pk_demo_no_secret`.

## G2 · Offline keyword guessing (deck finding 3)

**Setup.** The challenger draws the doctor's secret keyword `w*` uniformly from
a public dictionary `D` (|D| = 10) and gives the adversary the search token
`T*` for it. **Adversary models:**

| Model | Holds |
| --- | --- |
| outsider | public key, public parameters, `T*` |
| keyless server | the same, plus every token it serves (no key) |
| insider | the same, plus the doctor's index key `K` |

**Wins** if it outputs `w' = w*`. **Advantage** = Pr[win] − 1/|D|. The
experiment makes every keyword the secret once per seed, which is exactly the
uniform draw.

| Mode | outsider | keyless server | insider |
| --- | --- | --- | --- |
| A | 17/20 | 17/20 | 17/20 |
| B | 0/20 | 0/20 | 20/20 |
| C | 0/20 | 0/20 | 17/20 |
| control: SHA-256(keyword), no key | 10/10 | | |

In modes A and C every miss is a toy-parameter correctness failure (the
honest trapdoor fails on its own keyword, so the doctor's search misses too);
mode C's insider also had one false-positive match on another keyword. The
insider's 100 % (minus those) is expected and reported, not hidden: holding the
key means being able to search. Mode C reaches 0/20 **with the trapdoor on-chain
and Verify public**.

- **Tests.** `backend/tests/medvault/test_traceability.py::test_finding_kga_as_a_rate_with_an_unkeyed_control`,
  `backend/tests/medvault/test_mode_c.py::test_mode_c_kga_as_a_rate`,
  `backend/tests/medvault/test_mode_c.py::test_trapdoor_is_public_on_chain_yet_keyless_guessing_fails`,
  `backend/tests/test_kga.py::test_kga_recovers_secret_keyword`.

## G3 · Replay (deck finding 7)

**Setup.** The adversary observes a complete, valid request from the doctor —
a search or a retrieval — but not the doctor's signing key. **Wins** if the
gateway accepts any request the doctor did not issue in that exact form at that
point: the same bytes again, a modified copy, or a search signature presented as
a retrieval signature.

| Mode | search replay | retrieval replay | forged / cross-used signature |
| --- | --- | --- | --- |
| A | accepted | ciphertext handed over again | (no authentication) |
| B | `reused_nonce` | `reused_nonce` | `bad_signature`; no nonce consumed |
| C | accepted | ciphertext handed over again | (no authentication) |

The replaying party never obtains plaintext (it holds no DEK); what it gains is
the ciphertext and the fact of access.

- **Tests.** `backend/tests/medvault/test_traceability.py::test_finding_replay_captured_trapdoor`,
  `backend/tests/medvault/test_traceability.py::test_finding_replay_captured_retrieval`,
  `backend/tests/medvault/test_traceability.py::test_retrieval_gates_reject_forged_and_cross_used_signatures`,
  `backend/tests/medvault/test_mode_c.py::test_mode_c_does_not_fix_replay_or_forgery`.

## G4 · Result integrity: planting (deck finding 5)

**Setup.** The adversary may submit index entries through the open write path.
**Wins** if a later honest search for a keyword `w` returns a record id the
patient did not index under `w`. Two adversaries: an **outsider**, and a
**registered patient** who may write to their own index.

| Mode | outsider plant | how it is stopped |
| --- | --- | --- |
| A | wins (`CT₂ = 0` matches every search) | — |
| A′ | loses | `malformed_ciphertext`: short CT₂ column; 0 of 1 000 honest ciphertexts refused |
| B | loses | `unsigned_entry`; and no "matches everything" entry exists, since an HMAC entry matches one token |
| C | wins | mode C authenticates keywords, not ciphertexts |

**Not won by the measurements above, and not claimed:** the registered-patient
adversary. A signature proves who wrote an entry, not that it is well formed,
so a malicious patient can still poison their own index. The A′ check is
necessary, not sufficient. Closing G4 for an open ledger needs a
zero-knowledge proof of well-formedness (design-only:
[design-only-fixes.md](design-only-fixes.md#4-zero-knowledge-well-formedness)).

- **Tests.** `backend/tests/medvault/test_traceability.py::test_finding_plant_universal_ciphertext`,
  `backend/tests/medvault/test_wellformed.py::test_canonical_forgery_is_refused_on_write_in_mode_a_prime`,
  `backend/tests/medvault/test_wellformed.py::test_honest_ciphertexts_pass`.

## G5 · Access-pattern leakage (deck finding 6)

**Setup.** `N` records are tagged by drawing from a public prevalence table;
the doctor issues `Q` searches drawn from the same table. An **observer** —
the chain, or the search node — sees its view of those searches. **Tier 1:**
output a partition of the records. **Tier 2:** output a disease label per
record. **Advantage (Tier 2)** = accuracy − accuracy of the same labels
shuffled (chance). The attack code is the mid-sem lab's, unchanged
(`attacks/ledger.py`).

| Observer (10 seeds) | Tier 1 purity | Tier 2 accuracy | chance | beats chance |
| --- | --- | --- | --- | --- |
| mode A, chain | 1.00 | 0.715 | 0.17 | 10/10 |
| mode B, chain | nothing visible | 0.19 | 0.18 | 0/10 |
| mode B, search node | 1.00 | 0.755 | 0.18 | 10/10 |
| mode B, search node, 2 cover searches per real one | 1.00 | 0.355 | 0.18 | 5/10 |
| mode B, search node, 4 cover searches per real one | 1.00 | 0.335 | 0.18 | 4/10 |

Mode B wins the game against the chain observer and loses it against the search
node, which sees tokens and matches by design (R11.10). Cover queries reduce
Tier 2 but never Tier 1. PIR (M5) hides *retrieval* from the storage server;
it does not change the search node's view. Hiding co-access needs oblivious
search: design-only, see [design-only-fixes.md](design-only-fixes.md#2-oram-vs-pir).

- **Tests.** `backend/tests/medvault/test_leakage.py::test_ppseb_chain_leaks_and_hardened_chain_does_not`,
  `backend/tests/medvault/test_leakage.py::test_search_node_still_sees_the_access_pattern`,
  `backend/tests/medvault/test_leakage.py::test_cover_queries_lower_tier2_but_cannot_hide_tier1`,
  `backend/tests/medvault/test_leakage.py::test_matched_record_ids_reach_the_chain_only_where_ppseb_puts_them`,
  `backend/tests/medvault/test_m5_pir.py::test_property_19_live_retrieve_never_calls_targeted_get`.

## G6 · Forward security (deck finding 9)

**Setup (the paper's break-in phase, isolated).** The challenger runs the key
chain to period J and hands the adversary the current secret `sk_J`. **Wins** if
it searches a ciphertext frozen in an earlier period `i < J`.

- **Measured.** Running the chain backwards through the public `R` matrices
  gives a valid but long basis of the old lattice; lattice reduction then
  produces a working old trapdoor. But at these parameters the public key alone
  already does that (G1), so stealing `sk_J` adds nothing: forward security is
  **vacuous here, not broken**. The paper's game has a break-in phase but never
  proves forward security as its own statement.
- **MedVault's response (M7).** A binary epoch tree with erasure: structure
  implemented, `A·T ≡ 0 (mod q)` checked at all 31 nodes, norms measured
  (2.8–4.2 against a 10.57 toy threshold), past epochs refused after erasure.
  This demonstrates structure and cost; it is **not** a forward-security claim.
  See [design-only-fixes.md](design-only-fixes.md#3-forward-security-what-would-make-a-claim-meaningful).
- **Tests.** `backend/tests/test_end_to_end.py::test_end_to_end_experiment_well_formed`,
  `backend/tests/test_end_to_end.py::test_attacker_never_reads_honest_sk`,
  `backend/tests/medvault/test_m7_key_tree.py::test_every_node_satisfies_a_times_t_mod_q`,
  `backend/tests/medvault/test_m7_key_tree.py::test_past_epoch_secrets_are_erased_and_reachable_ones_are_not`.

## G7 · Cloud integrity (added by MedVault-PQ)

**Setup.** The storage server may serve a modified blob, an older version, or
nothing. **Wins** if the doctor accepts and decrypts anything other than the
committed current version. **Measured:** a modified blob is refused at the
content-hash / Merkle check, an older version as `stale_version`, a withheld
one as `withheld`; all before any DEK is used, with no plaintext in any case. Withholding is detected, not prevented.

- **Tests.** `backend/tests/medvault/test_traceability.py::test_finding_stale_or_modified_cloud_data`,
  `backend/tests/medvault/test_m5_pir.py::test_evil_cloud_still_fails_closed_through_pir`.

## G8 · Revocation (added by MedVault-PQ)

**Setup.** After the patient revokes doctor A, A keeps every old key, token,
nonce, envelope and proof. **Wins** if any of them gets a search or retrieval
accepted in the new epoch. **Measured (mode B):** all rejected; doctor B
continues inside their scope. Mode C has no request gates, but A's old key
matches nothing in the new epoch's index. Revocation cannot recall plaintext A
already downloaded.

- **Tests.** `backend/tests/medvault/test_traceability.py::test_finding_no_consent_or_revocation`,
  `backend/tests/medvault/test_m4_consent.py::test_revoked_doctor_is_rejected_and_the_other_still_works`,
  `backend/tests/medvault/test_m6_zk.py::test_property_22_reused_nullifier_is_rejected`,
  `backend/tests/medvault/test_mode_c.py::test_revocation_works_through_the_keys`.

---

## Coverage summary

| Deck finding | Game | Paper's model covers it? | MedVault-PQ outcome |
| --- | --- | --- | --- |
| 1 · Spec defect (Algorithm 2) | — (a correctness defect, not a game) | — | corrected KeyExt; `backend/tests/test_spec_defect.py::test_corrected_version_produces_valid_chain` |
| 2 · Key recovery from pk | G1 | no (premise fails) | design-only (Module-LWE) |
| 3 · Offline KGA | G2 | no | closed for outsider and keyless server in B and C |
| 4 · Reduction loss | G0 | yes, loosely | analysis only |
| 5 · Universal ciphertext | G4 | no | closed for outsiders in A′ and B; registered patient: design-only (ZK) |
| 6 · Access pattern | G5 | no | closed for the chain in B; search node measured, partly mitigated |
| 7 · Replay | G3 | no | closed in B for search and retrieval |
| 8 · Scaling | — (a cost finding) | — | measured in the research arm; Module-LWE design-only |
| 9 · Forward security | G6 | partly (break-in phase, no proof) | vacuous at these parameters; M7 structure only |
| 10 · Security model | this document | — | G0–G8 written, each tied to a test |
