# Graph Report - PPSEB  (2026-10-01)

## Corpus Check
- 61 files · ~66,274 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 2 file(s) not represented in the graph (top: (none) 1, .css 1)

## Summary
- 692 nodes · 1844 edges · 28 communities (22 shown, 2 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 84 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- KGA & Spec Defect Attacks
- MP12 Gadget Trapdoor
- Batch Sweep Engine
- React Frontend App
- FastAPI Endpoints
- Sweep Test Suite
- Forward Security Core
- Build Spec & Findings
- Frontend Dependencies
- End-to-End Attack Infra
- Hash Constructions (H1/H2)
- E2E Experiment Runner
- Linear Algebra & LLL
- Gadget Tests & Sigma
- Attack Period Recovery
- E2E Test Harness
- Frozen History Builder
- Forward Sec Chain Builder
- Negative Controls
- API & UI Concepts
- Safe Matmul & R-Inverse
- Excluded Break Runs
- Frozen CT Tests
- PPSEB Module Init

## God Nodes (most connected - your core abstractions)
1. `default_params()` - 72 edges
2. `Params` - 69 edges
3. `Trace` - 65 edges
4. `trapgen()` - 31 edges
5. `gram_schmidt_norm()` - 29 edges
6. `H1()` - 27 edges
7. `new_basis_del()` - 27 edges
8. `trapdoor()` - 25 edges
9. `end_to_end_experiment()` - 24 edges
10. `_cfg()` - 23 edges

## Surprising Connections (you probably didn't know these)
- `Postquantum Public-Key Searchable Encryption` --semantically_similar_to--> `Lattice-Based LWE Cryptography`  [INFERRED] [semantically similar]
  RIS-1.pdf → CLAUDE.md
- `Finding 2: Forward-Security Norm Weakness` --semantically_similar_to--> `Forward-Security Norm Experiment`  [INFERRED] [semantically similar]
  CLAUDE.md → README.md
- `Finding 1: KGA Break` --semantically_similar_to--> `Keyword-Guessing Attack (KGA)`  [INFERRED] [semantically similar]
  CLAUDE.md → README.md
- `Finding 3: KeyExt Spec Circularity Defect` --semantically_similar_to--> `Specification Defect (KeyExt Circularity)`  [INFERRED] [semantically similar]
  CLAUDE.md → README.md
- `PPSEB Build Specification` --references--> `PPSEB Paper (Xu et al., 2022)`  [EXTRACTED]
  CLAUDE.md → RIS-1.pdf

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Three Concrete Security Findings** — claude_finding_1_kga, claude_finding_2_forward_sec, claude_finding_3_spec_defect [EXTRACTED 1.00]
- **Forward Security Patch Chain** — patch_01_forward_security_verdict, patch_02_threshold_scaling, patch_03_scaling_confound, patch_05_end_to_end_attack, patch_06_parameterize, patch_08_batch_sweep, patch_09_relative_word_check [EXTRACTED 1.00]
- **Core Cryptographic Primitives** — claude_trapgen_algorithm, claude_h1_hash, claude_h2_frd_hash, claude_samplers [EXTRACTED 1.00]

## Communities (28 total, 2 thin omitted)

### Community 0 - "KGA & Spec Defect Attacks"
Cohesion: 0.07
Nodes (57): kga_attack(), ndarray, Finding 1 — offline keyword-guessing attack (KGA). **Claim under test:** PPSEB…, Given only PUBLIC data (pk_rj, mu) plus one captured trapdoor and a dictionary…, _paper_line6_literal(), _paper_line7_literal(), ndarray, Random (+49 more)

### Community 1 - "MP12 Gadget Trapdoor"
Cohesion: 0.05
Nodes (67): binary_decompose(), gadget_basis_k(), gadget_k(), gadget_matrix(), gadget_sample(), gadget_vector(), mp12_parameters(), mp12_sample_pre() (+59 more)

### Community 2 - "Batch Sweep Engine"
Cohesion: 0.05
Nodes (60): api_sweep_export(), lifespan(), PATCH 08 §3: a job whose meta still says "running" belonged to a process that…, acquire_job_lock(), aggregate(), aggregate_cells(), append_record(), break_periods() (+52 more)

### Community 3 - "React Frontend App"
Cohesion: 0.08
Nodes (39): api, App(), TABS, ParamsPanel(), Badge(), Card(), ErrorBanner(), PrimaryButton() (+31 more)

### Community 4 - "FastAPI Endpoints"
Cohesion: 0.08
Nodes (50): Any, api_attack_forward(), api_attack_forward_e2e(), api_attack_forward_e2e_multi(), api_attack_forward_fairness(), api_attack_forward_sweep(), api_attack_kga(), api_attack_spec() (+42 more)

### Community 5 - "Sweep Test Suite"
Cohesion: 0.08
Nodes (50): _cfg(), _finalize(), _ok_record(), fixture, PATCH 08 §8 — tests for the batch-sweep machinery. These deliberately do NOT…, One throwing cell is recorded as an error and the job still finishes., break_rate = broken_trusted_repeats / trusted_repeats., A repeat that failed a guardrail contributes to neither numerator nor… (+42 more)

### Community 6 - "Forward Security Core"
Cohesion: 0.08
Nodes (49): forward_sec_experiment(), SINGLE SOURCE OF TRUTH (PATCH 02 §A.2) for "is a basis with Gram-Schmidt norm g…, suffix[i] = R_{i+1}^-1 . R_{i+2}^-1 ... R_J^-1 (mod q), for i=0..J. suffix[J] =…, Runs the low_norm forward-security reduction at each n in `n_values` (m re-…, Runs all three LLL/BKZ configs (PATCH 04 §2) at each n, using the SAME audited…, scaling_sweep(), _suffix_products(), three_way_reduction_sweep() (+41 more)

### Community 7 - "Build Spec & Findings"
Cohesion: 0.07
Nodes (34): PPSEB Build Specification, Finding 1: KGA Break, Finding 2: Forward-Security Norm Weakness, Finding 3: KeyExt Spec Circularity Defect, H1 Hash (Low-Norm Invertible Matrix), H2 FRD Hash (Full-Rank-Difference Matrix), KeyExt Algorithm (Corrected), Lattice-Based LWE Cryptography (+26 more)

### Community 8 - "Frontend Dependencies"
Cohesion: 0.08
Nodes (24): dependencies, react, react-dom, recharts, devDependencies, autoprefixer, postcss, tailwindcss (+16 more)

### Community 9 - "End-to-End Attack Infra"
Cohesion: 0.14
Nodes (24): _basis_chain_norms(), _build_frozen_history_once(), _hash_cm(), _hash_ct(), Random, Finding 2 — end-to-end forward-security attack (PATCH 05). PATCH 01-04…, PATCH 06 §6.5 — instruments the FULL delegation chain a candidate basis…, PATCH 09: is the attacker's word basis comparable to one that provably works?… (+16 more)

### Community 10 - "Hash Constructions (H1/H2)"
Cohesion: 0.17
Nodes (21): H1(), H1_inverse(), H2(), H2_inverse(), _irreducible_twist(), ndarray, H1 and H2 — the two hash functions the PPSEB paper invokes but never constructs…, Smallest c >= 2 for which f(x) = x^n - c is irreducible over GF(q). Represents… (+13 more)

### Community 11 - "E2E Experiment Runner"
Cohesion: 0.10
Nodes (20): end_to_end_experiment(), Runs the full forward pass (frozen history) then the backward attack against…, A full run at n=4 (fast) returns well-formed rows and a headline consistent…, end_to_end_experiment must actually use the given n and J -- no hardcoded…, A run at J periods reports exactly J per-period rows (0..J-1)., Plaintext recovery (L3) can never break at a period where the search (L2)…, The single-run experiment and the multi-n comparison, called with the SAME J,…, NewBasisDel's delegation GROWS the norm going period -> word basis (PATCH 06… (+12 more)

### Community 12 - "Linear Algebra & LLL"
Cohesion: 0.17
Nodes (18): lll_reduce(), mat_inv_mod(), mat_mod_mixed(), Return M as int64 if every entry fits comfortably in int64, else as `object`…, (A @ B) % q — see `safe_matmul`., Classic (floating-point Gram-Schmidt) LLL reduction of the columns of integer…, Exact modular inverse of a square matrix, mod prime q (via sympy)., to_safe_int_array() (+10 more)

### Community 13 - "Gadget Tests & Sigma"
Cohesion: 0.17
Nodes (15): Dimension-aware sigma (PATCH 03 Lever 1). SamplePre/NewBasisDel's correctness…, sigma_for_params(), _honest_chain(), honest_chain_n4(), _params(), fixture, PATCH 10 §6 — MP12 gadget trapdoor and the honest-correctness gate. MP12 is NOT…, The honest doctor's chain as the end-to-end experiment builds it, with an MP12… (+7 more)

### Community 14 - "Attack Period Recovery"
Cohesion: 0.18
Nodes (13): attack_period(), PeriodDB, ndarray, An IMMUTABLE snapshot of the honest doctor's searchable database at one period.…, The actual R^-1-transform recovery (PATCH 01-04's machinery): the ONLY inputs…, The backward attack against ONE frozen period. Attacker holds only:…, _recover_period_candidate(), CT_i/CM_i content hashes before and after an attack run must be identical — the… (+5 more)

### Community 15 - "E2E Test Harness"
Cohesion: 0.15
Nodes (8): N0_legit must not be None for every period — the honest doctor must be able to…, Every per-period row carries the word-basis cross-check fields (PATCH 06 §6.5):…, Regression for the PATCH 06 bug: the old check compared word_gs to the PERIOD-…, Replaces PATCH 09's 'honest approval rate' test, which can't fail (honest-vs-…, test_legit_doctor_finds_own_record(), test_word_basis_measured(), test_word_check_relative_not_absolute(), test_word_decision_stability_high()

### Community 16 - "Frozen History Builder"
Cohesion: 0.18
Nodes (6): build_frozen_history(), Thin retry wrapper around `_build_frozen_history_once`. The per-run noise…, If no period yields N0_star == N0_legit, the summary must say 'resists', never…, Structural + dynamic proof that the attack path reads only stolen_sk_J, public…, test_attacker_never_reads_honest_sk(), test_no_break_reported_honestly()

### Community 17 - "Forward Sec Chain Builder"
Cohesion: 0.27
Nodes (10): _build_chain(), ndarray, Random, Finding 2 — forward-security norm experiment. PATCH 01 reframing: the paper…, A 'naive' H1 alternative: a UNIFORMLY random invertible m x m matrix mod q —…, Builds the key-evolution chain AND judges the LEGITIMATE basis at every period…, _uniform_invertible(), fpylll_available() (+2 more)

### Community 18 - "Negative Controls"
Cohesion: 0.29
Nodes (7): attack_period_negative_control(), A NEGATIVE CONTROL: feeds a candidate that has NO legitimate relationship to…, stolen_sk_J is a genuine, well-reduced secret basis -- just not for period i (i…, The two controls above must hold reliably, not just for one lucky seed -- run…, test_negative_control_garbage_fails_level2(), test_negative_control_wrong_period_fails_level2(), test_negative_controls_across_seeds()

### Community 19 - "API & UI Concepts"
Cohesion: 0.50
Nodes (5): Backend Dependencies, FastAPI API Surface, React Frontend UI (Lab Instrument), Trace Event Format, Frontend Entry HTML

### Community 20 - "Safe Matmul & R-Inverse"
Cohesion: 0.50
Nodes (4): A @ B, done in `object` (arbitrary-precision) arithmetic. This is intentionally…, safe_matmul(), Audit: R_j = H1(...) = I + N has det = 1 exactly over Z, so it has a genuine…, test_r_inverse_over_z_matches_incremental_mod_q()

### Community 22 - "Excluded Break Runs"
Cohesion: 0.50
Nodes (4): excluded_break_run(), fixture, seed 24956, n=4, J=2, 8 records/period: a real run whose two measured breaks…, small_history()

## Knowledge Gaps
- **34 isolated node(s):** `name`, `private`, `version`, `type`, `dev` (+29 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 259 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `default_params()` connect `Forward Security Core` to `KGA & Spec Defect Attacks`, `MP12 Gadget Trapdoor`, `Batch Sweep Engine`, `FastAPI Endpoints`, `Sweep Test Suite`, `Hash Constructions (H1/H2)`, `E2E Experiment Runner`, `Linear Algebra & LLL`, `E2E Test Harness`, `Frozen History Builder`, `Negative Controls`, `Safe Matmul & R-Inverse`, `Excluded Break Runs`?**
  _High betweenness centrality (0.146) - this node is a cross-community bridge._
- **Why does `Params` connect `KGA & Spec Defect Attacks` to `MP12 Gadget Trapdoor`, `Batch Sweep Engine`, `FastAPI Endpoints`, `Forward Security Core`, `End-to-End Attack Infra`, `Hash Constructions (H1/H2)`, `E2E Experiment Runner`, `Gadget Tests & Sigma`, `Attack Period Recovery`, `Frozen History Builder`, `Forward Sec Chain Builder`, `Negative Controls`?**
  _High betweenness centrality (0.111) - this node is a cross-community bridge._
- **Why does `Trace` connect `KGA & Spec Defect Attacks` to `MP12 Gadget Trapdoor`, `FastAPI Endpoints`, `Forward Security Core`, `End-to-End Attack Infra`, `Hash Constructions (H1/H2)`, `E2E Experiment Runner`, `Linear Algebra & LLL`, `Attack Period Recovery`, `Frozen History Builder`, `Forward Sec Chain Builder`, `Negative Controls`?**
  _High betweenness centrality (0.061) - this node is a cross-community bridge._
- **Are the 39 inferred relationships involving `Params` (e.g. with `envelope()` and `Session`) actually correct?**
  _`Params` has 39 INFERRED edges - model-reasoned connections that need verification._
- **Are the 23 inferred relationships involving `Trace` (e.g. with `envelope()` and `attack_period()`) actually correct?**
  _`Trace` has 23 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `trapgen()` (e.g. with `Params` and `Trace`) actually correct?**
  _`trapgen()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `name`, `private`, `version` to the rest of the system?**
  _34 weakly-connected nodes found - possible documentation gaps or missing edges._