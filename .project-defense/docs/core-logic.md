# Core Logic — PPSEB Analysis Lab

> **Project:** PPSEB  
> **Generated:** 2026-10-17  
> **Source:** `.project-defense/project-graph.json` (verified entries only)

## 1. Overview

The lab's core is a small-parameter implementation of searchable encryption plus attack experiments that use the same implementation and trace format. Its most important invariants are modular lattice membership for period keys, a shared PEKS random matrix for cancellation during Verify, and a single-step KeyExt that uses only previous-period values.

Core source: [scheme.py](../../backend/ppseb/scheme.py), [params.py](../../backend/ppseb/params.py), and the modules under `backend/attacks/`.

## 2. Parameter and lattice setup

`Params` derives `m = 2*n*ceil(log2(q))` when omitted. Validation rejects a composite modulus, insufficient `m`, non-positive sampler/noise widths, invalid `n`/`l`, and dimensions incompatible with the H2 block construction ([params.py](../../backend/ppseb/params.py), lines 13–112).

Initialization invokes TrapGen for the period-0 key, samples `mu` and the record-PKE anchor, and records the type/shape table in the trace ([scheme.py](../../backend/ppseb/scheme.py), lines 39–70).

## 3. Searchable encryption and record retrieval

### What happens

For a keyword and period, PEKS computes `beta = H2(w, j)`, derives its inverse, samples one `B` and uses that same `B` for both ciphertext components. Trapdoor generation delegates the previous/current period basis to the word basis and samples a short preimage. Verify computes `CT1 - Trap^T CT2` and decides whether every coordinate is within the decode margin of `q/2`. The API separately encrypts the record and returns its decrypted bytes only after a positive match.

### Why the shared matrix matters

The `B` terms must cancel in Verify. If CT1 and CT2 used independent random matrices, the matching-keyword terms would not cancel. The implementation explicitly marks this assumption as a correction in its trace ([scheme.py](../../backend/ppseb/scheme.py), lines 127–174).

### Edge cases and limitations

- `q` is validated as prime and `m` must satisfy the configured lower bound.
- The API rejects calls before initialization and rejects period numbers not present in the session.
- The record is decrypted only for a match; a no-match returns no plaintext.
- The parameters are deliberately tiny, and chosen noise widths/instantiations are analysis choices rather than production security parameters.
- The Happy Path handler does not write the submitted record to a persistent database.

Evidence: `backend/api.py:195-297`; `backend/ppseb/params.py:13-112`; `backend/ppseb/scheme.py:39-174`.

## 4. Finding 1: offline keyword-guessing attack

The KGA endpoint first uses the doctor's secret basis to produce one trapdoor. Once that value is captured, the attack loops through candidate words, runs public PEKS encryption for each, and runs public Verify against the captured trapdoor. It records each guess and the first match in the trace ([kga.py](../../backend/attacks/kga.py), lines 30–82).

This is a structural property of the public-encryption/public-tester design being examined; the demo does not claim to solve the underlying LWE problem. The blockchain threat model is that the submitted trapdoor is visible to validators/observers.

## 5. Finding 2: forward-security experiment

For each earlier period, the experiment builds the public `R` product and transforms the stolen later-period basis back to a candidate basis, then measures lattice membership and basis quality against a usability criterion. The result is determined from measured norms and selected reduction behavior, not a fixed verdict. The README and module documentation caution that success at tiny dimensions does not establish a break at cryptographic dimensions ([forward_sec.py](../../backend/attacks/forward_sec.py), lines 1–95; [README.md](../../README.md), lines 14–20 and 147–229).

Two H1 constructions are compared because the paper does not specify the distribution. A uniform-invertible transform can make delegated keys unusable; a low-norm transform can preserve correctness while making its inverse transform tractable at demo dimensions. Any conclusion must name the variant, dimensions, reduction level, and measured basis norms.

## 6. Finding 3: KeyExt specification defect

The paper's printed line 6 references `pk_rj` while defining it; line 7 passes `sk_rj` to NewBasisDel while defining `sk_rj`. The paper runner executes each circularity in isolation to report the specific failure. The corrected runner derives `R` from `pk_{j-1}` and derives the new basis from `sk_{j-1}`, then checks `pk_j * sk_j == 0 (mod q)` across the chain ([spec_defect.py](../../backend/attacks/spec_defect.py), lines 15–51 and 83–150; [scheme.py](../../backend/ppseb/scheme.py), lines 73–123).

## 7. Invariants

| Invariant | Why it matters | Evidence |
|---|---|---|
| `pk_j * sk_j == 0 (mod q)` | Each secret basis must belong to the public-key kernel lattice. | `backend/ppseb/scheme.py:105-123` |
| The same `B` is used for CT1 and CT2 | The verifier's shared terms cancel for a matching keyword. | `backend/ppseb/scheme.py:127-174` |
| KeyExt reads only previous-period key material | Avoids the paper's forward/circular dependency. | `backend/ppseb/scheme.py:73-104` |
| A no-match does not return a plaintext | Search rejection gates record decryption. | `backend/api.py:276-297` |
| Attack verdicts are evidence-derived | Prevents the UI from hard-coding a forward-security outcome. | `backend/attacks/forward_sec.py` and its tests |

## 8. Common failure modes and deliberate limits

| What goes wrong | Handling / limit | Evidence |
|---|---|---|
| Invalid or incompatible parameters | Validation returns explicit problems and API responds with 422. | `backend/ppseb/params.py:58-84`; `backend/api.py:195-204` |
| Search requested before key setup | Explicit 400 asks for `/api/init`. | `backend/api.py:221-224` |
| Incorrect period | Explicit 400 states the absent period and directs callers to `/api/keyext`. | `backend/api.py:97-103` |
| Long reduction/job exceeds its budget | Experiment code documents a bounded budget; timeouts are not evidence of security. | `README.md:160-180`; `backend/attacks/forward_sec.py` |
| API exposed to multiple users | Not handled: `SESSION` is global process state and can be reset by init. | `backend/api.py:78-103` |
| Unhandled exception leaks traceback details | The generic handler returns a traceback, appropriate only for a local lab. | `backend/api.py:897-904` |

## 9. Things to improve

- Replace process-global `SESSION` with explicit per-browser/session state if multi-user use is ever intended.
- Restrict CORS and remove traceback detail from production error responses before any remote deployment.
- Improve the skill-generated graph detector for FastAPI; its automatic detector does not extract this backend's route declarations.
- Keep claims about cryptographic security bounded to the tested tiny parameters and specified reduction budget.

## 10. Interview-ready summary

The core logic turns each search into PEKS ciphertext plus a trapdoor, verifies with a modular inner-product cancellation, and decrypts the record only on a match. The attack tabs reuse those real primitives: KGA re-encrypts dictionary guesses, forward-security analysis measures transformed bases, and the spec-defect experiment contrasts the printed circular algorithm with a valid one-step correction. The implementation makes its assumptions visible in traces and avoids presenting toy-parameter measurements as general cryptographic guarantees.

## 11. Evidence appendix

| Claim | File | Lines | Status |
|---|---|---:|---|
| Parameter derivation and checks | `backend/ppseb/params.py` | 13–112 | code-verified |
| Initialization | `backend/ppseb/scheme.py` | 39–70 | code-verified |
| Corrected KeyExt | `backend/ppseb/scheme.py` | 73–123 | code-verified |
| PEKS shared-B correction | `backend/ppseb/scheme.py` | 127–174 | code-verified |
| KGA loop | `backend/attacks/kga.py` | 30–82 | code-verified |
| Forward-security method caveats | `backend/attacks/forward_sec.py` | 1–95 | code-verified |
| Specification defect demonstration | `backend/attacks/spec_defect.py` | 15–150 | code-verified |
| Match-gated record decryption | `backend/api.py` | 263–297 | code-verified |
