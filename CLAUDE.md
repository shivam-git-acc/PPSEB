# PPSEB Analysis Lab — Build Specification

> **Read this whole file before writing any code.** It defines what to build, the
> exact crypto to implement, the findings the tool must demonstrate, and the UI.
> When a design choice is ambiguous, prefer **faithfulness to the reasoning in the
> "Findings" section** over convenience — the findings are the product.

---

## 0. What this project is

We are analyzing a cryptography paper — **PPSEB** (Xu et al., 2022): *"A Postquantum
Public-Key Searchable Encryption Scheme on Blockchain for E-Healthcare Scenarios."*
The paper proposes a lattice-based (LWE) searchable-encryption scheme, adds a
time-evolving key for "forward security," and puts the search step on a blockchain.

**This is not a reimplementation-for-use project. It is an ANALYSIS project.**
The deliverable is an interactive lab that:
1. Implements a faithful (corrected) version of the scheme's core, and
2. **Demonstrates three concrete findings** — a security break, a specification
   defect, and an open/structural weakness — live, in a browser UI.

The three findings are the reason the tool exists. Everything serves showing them
clearly to an evaluator watching a screen.

---

## 1. Architecture

```
ppseb-lab/
├── backend/                 # Python — the real crypto + attacks
│   ├── ppseb/
│   │   ├── __init__.py
│   │   ├── params.py        # parameter sets (n, q, m, sigma, ...)
│   │   ├── linalg.py        # mod-q linear algebra, norms, Gaussian sampling
│   │   ├── trapgen.py       # TrapGen: (A, T_A) short-basis generation
│   │   ├── samplers.py      # SamplePre, SampleGaussian, NewBasisDel
│   │   ├── hashes.py        # H1 (-> low-norm invertible), H2 (-> FRD matrix)
│   │   ├── scheme.py        # Initialization, KeyExt, Encrypt, PEKS, Trapdoor,
│   │   │                    #   Verify, Decrypt  (the 7 algorithms, CORRECTED)
│   │   └── trace.py         # structured event log for the UI (see §6)
│   ├── attacks/
│   │   ├── kga.py           # Finding 1: offline keyword-guessing attack
│   │   ├── forward_sec.py   # Finding 2: R^-1 * T_j norm experiment
│   │   └── spec_defect.py   # Finding 3: circular Alg-2 vs corrected single-step
│   ├── api.py               # FastAPI app exposing everything to the UI
│   ├── tests/               # pytest — correctness + attack assertions
│   └── requirements.txt
├── frontend/                # React (Vite) + Tailwind — the UI
│   └── (see §7)
├── README.md                # how to run both halves
└── CLAUDE.md                # this file
```

**Backend:** Python 3.11+, `numpy`, `sympy` (for exact mod-q inverses),
`fastapi`, `uvicorn`, `pydantic`, `pytest`. No heavy lattice libraries — implement
the primitives ourselves at small parameters (this is deliberate: it keeps the code
readable and auditable, which matters for an eval).

**Frontend:** React + Vite + TailwindCSS. Talks to the backend over HTTP/JSON.
`recharts` for the plots. No other UI framework.

**Contract between them:** every backend operation returns, alongside its result, a
**trace** — an ordered list of typed events (§6) — so the UI can render *what the
system did*, step by step. This is the whole point of "I want to see everything
happening on screen."

---

## 2. Parameters (start SMALL, make them configurable)

Real lattice params are huge; we run tiny ones so everything is fast and visible.
Expose these in the UI (a "Parameters" panel) with sensible defaults:

| symbol | meaning              | default | notes                                  |
|--------|----------------------|---------|----------------------------------------|
| `n`    | lattice dimension    | 4       | keep tiny for demo (4–8)               |
| `q`    | modulus (prime)      | 257     | small prime, must be prime             |
| `m`    | columns              | `2*n*ceil(log2 q)` ≈ 64 | derived, show it   |
| `sigma`| Gaussian width       | 4.0     | for SamplePre / SampleGaussian         |
| `l`    | keyword test length  | 10      | "security level" Sl in the paper       |

Provide a `params.py` with a `Params` dataclass and a `default_params()`.
**Validate q is prime and m ≥ 2 n log2 q**; surface violations to the UI.

---

## 3. The crypto to implement (faithful, but CORRECTED where the paper is broken)

Implement the seven algorithms. **Where the paper is defective or unspecified, use
the corrections below and MARK them in the trace** (event `type:"correction"`) so the
UI can show "paper says X, we do Y, because Z." The corrections ARE findings.

### 3.1 Objects and shapes (the paper never states these — we fix them)
- `pk_r  ∈ Z_q^{n×m}`  (doctor public key)
- `sk_r  ∈ Z^{m×m}`   (doctor secret = short basis of L⊥(pk_r))
- `mu    ∈ Z_q^n`     (LWE-secret-like vector; used as μ)
- `B_j   ∈ Z_q^{n×l}` (shared random matrix in PEKS — see §3.5, MUST be shared)
- `CT_j1 ∈ Z_q^{1×l}`, `CT_j2 ∈ Z_q^{m×l}`
- `Trap  ∈ Z_q^m`
Emit this shape table to the UI once at init (a "type discipline" panel).

### 3.2 TrapGen  (trapgen.py)
`trapgen(params) -> (A, T)` with `A ∈ Z_q^{n×m}` (≈uniform) and `T ∈ Z^{m×m}` a
short basis of `L⊥_q(A)` (i.e. `A · T = 0 mod q`, T short).
- Acceptable construction for small params: the standard "gadget-free" approach —
  sample `A = [Ā | I]`-style or use the Ajtai/HNF short-basis trick. A pragmatic,
  correct-enough construction: build `A` random, compute a basis of the mod-q
  kernel lattice `L⊥(A)` via the Hermite Normal Form / integer kernel, then reduce
  it (LLL) to get a short-ish basis `T`. Verify `A·T ≡ 0 (mod q)` and report
  `‖T̃‖` (Gram–Schmidt norm).
- **Must expose** `gram_schmidt_norm(T)` — it's central to Finding 2.

### 3.3 H1 — hash to low-norm INVERTIBLE matrix  (hashes.py)
Paper says `H1: Z_q^{n×m} × N → Z_q^{m×m}` with NO construction. **Requirement
(from Lemma 5 / D_{m×m}): output must be low-norm AND invertible.** Implement:
```
H1(pk, j):  seed = SHA256(serialize(pk) || j)
            N = strictly-upper-triangular m×m, entries drawn from {-1,0,1} by seed
            return I + N          # det = 1 → always invertible; low norm
```
Expose `H1_inverse(R)` (exact, over Z since det=±1, or mod q via sympy).
**Trace event:** record ‖R‖ and ‖R⁻¹‖ every time H1 is used — Finding 2 needs both.

### 3.4 H2 — hash to FRD (full-rank-difference) matrix  (hashes.py)
Paper says `H2: {0,1}^{l1} × N → Z_q^{m×m}`, NO construction, but the scheme
inverts β_j AND uses it in NewBasisDel AND the security proof needs invertible
*differences*. Implement an **FRD encoding** (Cramer–Damgård / ABB style):
```
H2(w, j): map (w||j) -> element of F_{q^n}; return its m×m matrix representation
          such that for w≠w', H2(w,j) - H2(w',j) is invertible.
```
If a full F_{q^n} embedding is too much at small params, implement a documented
approximation that still guarantees invertible differences (e.g. companion-matrix
encoding of a degree-n poly), and MARK it as an approximation in the trace.
**Trace event:** `type:"correction", note:"H2 unspecified in paper; instantiated as FRD"`.

### 3.5 PEKS.Encrypt  (scheme.py)  — the B_j-sharing fix
```
beta = H2(w, j)
B    = random Z_q^{n×l}                      # SAME B used in both CT parts
CT1  = mu^T · B + noise_1 + y·floor(q/2)      # 1×l ; y = all-ones vector (keyword present)
CT2  = (pk_rj · beta^{-1})^T · B + noise_2     # m×l
return (CT1, CT2)
```
**CRITICAL:** the paper is ambiguous about whether `B_j` is shared between CT1 and
CT2. It MUST be, or verification never cancels. Emit a `correction` event stating
this, and make `B` shared. (This is a real finding: unstated load-bearing assumption.)

### 3.6 Trapdoor  (scheme.py) — the well-formed call
```
beta = H2(w', j)
sk_w = NewBasisDel(pk_rj, beta, sk_rj, sigma)      # source basis sk_rj -> word basis
Trap = SamplePre(pk_rj · beta^{-1}, sk_w, mu, sigma)  # short vector, (pk·β⁻¹)·Trap = mu
return Trap
```

### 3.7 Verify  (scheme.py)
```
y = CT1 - Trap^T · CT2            # 1×l
match = all( |y_i - floor(q/2)| < q/4  for i in range(l) )
return 1 if match else 0
```
Note the `q/4` decode threshold; the paper's correctness proof (§5.1) says the
noise bound is `< q/5`. Emit a `note` event flagging the `q/4` vs `q/5` mismatch.

### 3.8 KeyExt  (scheme.py) — CORRECTED, single-step, non-circular
The paper's Algorithm 2 has **two circularities**. Implement the corrected
single-step version and emit `correction` events documenting both:
```
# CORRECTION A (line-7 typo): basis arg must be the SOURCE (previous) basis
# CORRECTION B (line-6 circularity): R must reference only period j-1, not j
def keyext(j, pk_prev, sk_prev, params):
    R      = H1(pk_prev, j)                 # uses j-1 data only  -> no fwd reference
    pk_j   = pk_prev · R^{-1}   (mod q)
    sk_j   = NewBasisDel(pk_prev, R, sk_prev, params.sigma)   # source basis sk_prev
    return pk_j, sk_j
```
Keep a `root` (period 0) from TrapGen, then chain KeyExt for periods 1..J.

### 3.9 NewBasisDel + SamplePre + SampleGaussian  (samplers.py)
- `SampleGaussian(center, sigma, basis)` — discrete Gaussian over the lattice.
- `SamplePre(A, T_A, v, sigma)` — short `w` with `A·w = v mod q`, using trapdoor `T_A`.
- `NewBasisDel(A, R, T_A, sigma)` — short basis of `L⊥(A·R⁻¹)` from `T_A`. Faithful
  ABB approach: transform + re-randomize via Gaussian sampling so the OUTPUT basis
  is short and its distribution doesn't leak `T_A`. At small params a correct,
  readable implementation is fine even if not optimally short.
- Every sampler reports the Gram–Schmidt norm of what it produced (for Finding 2).

### 3.10 Encrypt / Decrypt (medical record track)  (scheme.py)
Simple LWE-style public-key encryption of the actual record bytes under `pk_rj`,
with matching decrypt under `sk_rj`. Kept minimal — it's not where the findings are,
but the end-to-end flow needs it so the UI can show "record retrieved & decrypted."

---

## 4. THE THREE FINDINGS (the heart — implement each as a runnable module + a UI tab)

### Finding 1 — KGA break (attacks/kga.py)  → tab "Keyword-Guessing Attack"
**Claim under test:** paper claims resistance to keyword-guessing attacks (incl. quantum).
**Reality:** it's public-key + secret-free public Verify + deterministic keyword
encoding → offline KGA succeeds. Blockchain/LWE don't help.

Implement:
```
kga_attack(captured_trap, period_j, pk_rj, dictionary, params):
    for g in dictionary:
        CT_g = PEKS.Encrypt(pk_rj, g, period_j)   # PUBLIC key only
        if Verify(CT_g, captured_trap) == 1:       # PUBLIC test
            return g, trace
    return None, trace
```
- Threat model to encode explicitly in the trace: *the doctor submits the trapdoor
  as a blockchain transaction → any consensus node sees it.* State this as the
  captured-trapdoor justification. (Emit a `threat_model` event.)
- The demo: user picks a secret keyword from a medical dictionary, the "doctor"
  makes a trapdoor for it, the attacker (who only has `pk`, the trapdoor, and the
  dictionary) recovers the keyword. UI shows each guess being tried and the match.
- **Assertion for tests:** attack returns the correct keyword.

### Finding 2 — Forward-security norm experiment (attacks/forward_sec.py) → tab "Forward Security"
**Claim under test:** stealing `sk_rj` (current) must not reveal earlier `sk_ri`.
**Reduction (state it in the UI):** the period lattices are related by a PUBLIC
low-norm invertible `R`, so `sk_ri`-candidate `= R⁻¹ · sk_rj` is *computable by anyone*.
Forward security then holds **iff `‖R⁻¹ · sk_rj‖` is too large to be a usable basis.**

Implement:
```
forward_sec_experiment(J, params):
    build root, chain KeyExt to period J, capturing each pk_ri, sk_ri, R_i
    target = sk_r{J}                          # the "stolen" current basis
    for i in range(J):                        # try to recover each earlier basis
        R_prod   = product of R_{i+1..J}      # public
        cand     = R_prod^{-1} · target       # attacker's cheap transform
        record:  ‖GS(cand)‖ , ‖GS(sk_ri_legit)‖ , usability_threshold(q/4),
                 membership_check( pk_ri · cand ≡ 0 mod q )
    return table + verdict
```
- Verdict logic per row:
  - `cand` in lattice AND ‖GS(cand)‖ ≈ ‖GS(legit)‖  → **BROKEN**
  - in lattice but much larger, still under usability threshold → **BROKEN (weak)**
  - exceeds usability threshold → **survives trivial attack** (report honestly)
- Run it under BOTH H1 instantiations (the `I+N` low-norm one, and a naive
  uniform-invertible one) to show the dependence on the unspecified distribution.
- **Honesty requirement:** the UI must state clearly whether it demonstrated a
  break or only an inconclusive/structural result. DO NOT hard-code "BROKEN."
  Report the measured norms and let the verdict follow from them.
- Output: a norm-comparison **chart** (recharts) + a per-period table.

### Finding 3 — Spec defect: Algorithm 2 circularity (attacks/spec_defect.py) → tab "Spec Defect"
**Claim under test:** Algorithm 2 (KeyExt) is well-defined.
**Reality:** two circular dependencies; not executable as printed.

Implement a side-by-side runner:
- `run_paper_version()` — attempt KeyExt literally as printed (line-7 uses `sk_rj`
  as input; line-6 R uses `pk_rj`). This should **fail / be non-executable**; catch
  the failure and surface *why* (name-before-defined / basis mismatch).
- `run_corrected_version()` — the single-step corrected KeyExt from §3.8; runs fine.
- UI shows: the two printed circular lines, the three-way justification for the fix
  (input list, Lemma 5 signature, Algorithm-4 analogy), the paper attempt failing,
  the corrected version producing a valid key chain (verify `A·T ≡ 0` each period).
- This is the CERTAIN finding — make it airtight and reproducible.

---

## 5. FastAPI surface (api.py)

Expose (all return `{result, trace, params}`):
```
POST /api/init            {params}                         -> pk/sk handles, shape table
POST /api/keyext          {periods}                        -> key chain + traces
POST /api/encrypt-search  {record, keyword, query_keyword} -> full happy-path flow
POST /api/attack/kga      {secret_keyword, dictionary}     -> Finding 1
POST /api/attack/forward  {J, h1_variant}                  -> Finding 2 (table+chart data)
POST /api/attack/spec     {periods}                        -> Finding 3 (paper vs corrected)
GET  /api/health
```
Keep server state in a simple in-memory session object (single-user demo — fine).
CORS open to the Vite dev server. Every endpoint MUST attach the trace.

---

## 6. Trace format (the "see everything" contract)

Every algorithm appends typed events to a trace list. Event schema:
```json
{
  "step": 3,
  "type": "compute | correction | note | threat_model | matrix | norm | decision | result",
  "title": "short human label",
  "detail": "one or two sentence explanation",
  "data": { "optional structured payload: matrices (as 2D arrays, TRUNCATED if big),
             norms, shapes, guesses, booleans" },
  "algo": "KeyExt | PEKS | Verify | KGA | ...",
  "highlight": true|false
}
```
Rules:
- Matrices bigger than ~12×12: include shape + a truncated preview + full norm, not
  the whole thing.
- `correction` events must carry `paper_says` and `we_do` and `because` fields in `data`.
- `decision` events carry the boolean/verdict and the numeric evidence behind it.
- This trace is what the UI renders as a step-by-step timeline. Design it so a person
  reading the timeline understands the finding WITHOUT reading the code.

---

## 7. Frontend / UI  (the part that must be genuinely good)

React + Vite + Tailwind. Aesthetic: clean, technical, "lab instrument," dark or
neutral theme, monospace for crypto values, generous whitespace. Read
`/mnt/skills/public/frontend-design/SKILL.md` conventions if available.

### Layout
- **Left rail:** Parameters panel (n, q, m, sigma, l) with live validation + an
  "Apply / Regenerate keys" button. Shows the derived `m` and the shape table.
- **Top tabs:** `Overview` · `Happy Path` · `KGA Attack` · `Forward Security` ·
  `Spec Defect`.
- **Main area:** per-tab content.
- **Right / bottom: the Trace Timeline** — always visible — renders the typed events
  from the last operation as an ordered, expandable list. `correction` events styled
  distinctly (e.g. amber), `decision` events with the verdict badge, `matrix` events
  with a collapsible preview.

### Tab contents
1. **Overview** — plain-language summary of the paper, the 3 claims, and the 3
   findings, each linking to its tab. A small architecture diagram (patient / cloud /
   doctor / blockchain).
2. **Happy Path** — user types a medical record + keyword, and a query keyword.
   Button runs the full flow (Encrypt → PEKS → Trapdoor → Verify → retrieve →
   Decrypt). Animate the trace: show data moving patient→cloud→blockchain→doctor.
   Show match/no-match and the decrypted record. Let them try a *non-matching* query
   to see it correctly reject.
3. **KGA Attack** — pick a secret keyword from a dictionary dropdown; "Doctor makes
   trapdoor" then "Launch attack." Show the attacker's view (only pk + trapdoor +
   dictionary). Render each guess being tested with a running list; the matching
   guess flashes. End state: "Keyword recovered: DIABETES — using only public data."
   Include the threat-model note (trapdoor visible on-chain).
4. **Forward Security** — set number of periods `J`, choose H1 variant. "Run
   experiment." Show the key chain being built, then the attacker's `R⁻¹·sk_rj`
   transform per earlier period. Render the **norm-comparison chart** (legit basis
   norm vs attacker basis norm vs usability threshold) and the per-period verdict
   table. The overall verdict must be DERIVED from the numbers, with honest wording.
5. **Spec Defect** — show the two printed circular lines of Algorithm 2 (as a code
   block), the three-way justification, then two buttons: "Run paper version"
   (fails, show the error/why) and "Run corrected version" (succeeds, show valid key
   chain with `A·T≡0` checks). Side-by-side.

### Interaction principles
- Nothing happens silently. Every button press produces a trace the user can read.
- Long ops: show a stepwise reveal (don't dump 60 events at once — stream/animate).
- Every crypto value shown is real (from the backend), never mocked in the frontend.
- Provide a "copy trace as JSON" and "export finding as report" per tab (nice for
  putting in the eval writeup).

---

## 8. Tests (backend/tests, pytest)

- `test_correctness`: matching keyword → Verify=1; non-matching → Verify=0; decrypt
  recovers record. Sweep noise, report failure rate (also exposed to UI as a chart
  later if time).
- `test_kga`: attack recovers the secret keyword from dictionary.
- `test_spec_defect`: paper-version KeyExt raises/does-not-produce-valid-basis;
  corrected-version produces `A·T ≡ 0` for every period.
- `test_forward_sec`: experiment runs, returns well-formed table; assert the verdict
  matches the measured norms (NOT a hard-coded outcome).
- `test_h2_frd`: for random w≠w', `H2(w,j) - H2(w',j)` is invertible mod q.
- `test_h1_invertible`: `H1(pk,j)` invertible and low-norm; `H1_inverse` correct.

---

## 9. Build order (do it in this sequence)

1. `params.py`, `linalg.py` (mod-q ops, norms, GS norm, LLL if needed) + their tests.
2. `trapgen.py` + verify `A·T≡0`, report ‖T̃‖.
3. `hashes.py` (H1, H2) + `test_h1_invertible`, `test_h2_frd`.
4. `samplers.py` (SampleGaussian, SamplePre, NewBasisDel) + norm reporting.
5. `scheme.py` (all 7 algorithms, corrected) + `test_correctness`. Wire `trace.py`.
6. `attacks/spec_defect.py` (Finding 3 — certain, do it first) + test.
7. `attacks/kga.py` (Finding 1) + test.
8. `attacks/forward_sec.py` (Finding 2) + test.
9. `api.py` (FastAPI) + `/api/health` smoke test.
10. Frontend: scaffold Vite+Tailwind, Trace Timeline component, then tabs in the
    order Overview → Spec Defect → KGA → Forward Security → Happy Path.
11. `README.md` with run instructions for both halves.

Commit after each numbered step. Keep functions small and readable — auditability is
a feature here, not a nice-to-have.

---

## 10. Non-negotiables (guardrails)

- **Do not fake results.** Especially Finding 2: the verdict must follow from measured
  norms. If it comes out inconclusive, the UI says inconclusive. An honest
  "we reduced it to this measurable quantity and here's what we measured" is a
  strong eval result; a faked "BROKEN" is a disaster if a professor probes it.
- **Mark every deviation from the paper** as a `correction`/`note` event with
  `paper_says` / `we_do` / `because`. The deviations are findings — surface them,
  don't hide them.
- **Real crypto values only in the UI.** The frontend never invents a matrix or a norm.
- Keep params small so everything runs in <2s; make them configurable, not hard-coded.
- Prefer clarity over cleverness in the crypto — a reader must be able to check it.

---

## 11. One-paragraph pitch (put a version of this on the Overview tab)

PPSEB claims postquantum keyword-guessing resistance, forward security, and
efficiency. This lab implements a corrected, faithful version of its core and shows:
(1) an **offline keyword-guessing attack** that recovers the searched keyword using
only public data — the LWE hardness and blockchain don't prevent it, because the
vulnerability is structural to public-key PEKS with a secret-free tester; (2) that
the **forward-security** question reduces to the norm growth of a public inverse
transform `R⁻¹`, which the scheme's own low-norm requirement on `R` works against;
and (3) that **Algorithm 2 (KeyExt) is not executable as printed** — two circular
dependencies — with a single-step correction grounded in the paper's own Lemma 5.
