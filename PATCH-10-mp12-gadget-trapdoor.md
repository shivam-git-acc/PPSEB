# PATCH 10 — Correct crypto core: Micciancio–Peikert (MP12) gadget trapdoor

> This is a foundational fix, not a tweak. Apply it and re-verify correctness BEFORE
> any further forward-security work. Every trust-gate misfire we've hit traces to one
> root cause: the current TrapGen builds a raw kernel basis + LLL, which produces
> LOW-QUALITY bases whose norm grows badly with m — so even the HONEST doctor's basis
> is borderline-unusable, which is why the word-basis gate keeps flagging the honest
> doctor and the whole forward-security experiment is unreliable.
>
> The scheme (PPSEB) is built on ABB (Agrawal–Boneh–Boyen 2010). The CORRECT, standard
> way to implement ABB-style trapdoors is the Micciancio–Peikert (MP12) GADGET
> trapdoor: "Trapdoors for Lattices: Simpler, Tighter, Faster, Smaller" (EUROCRYPT
> 2012, eprint 2011/501). This gives short bases with CONTROLLED, well-understood norm
> that does NOT degrade the way the current construction does. Replace the core with it.
>
> Reference implementation to MIRROR (compact, correct): the SageMath gist
> https://gist.github.com/malb/7c8b86520c675560be62eda98dab2a6f
> (trap_gen / sample_pre with the gadget G). Port its structure to numpy/sympy.
> Cross-check against MP12 (eprint 2011/501) and Genise–Micciancio (eprint 2017/308)
> for the G-sampling parameters.

---

## 1. The MP12 construction (what to implement)

### Gadget matrix
```
g = (1, b, b^2, ..., b^{k-1}),  k = ceil(log_b q),  b = 2 (default)
G = I_n ⊗ g^T   ∈ Z_q^{n × nk}      # the gadget; L⊥(G) has a KNOWN short basis
```
The kernel lattice of G has a trivial, explicitly-known short basis — that's the whole
point. No LLL, no HNF, no norm blow-up.

### TrapGen  (replaces the raw-kernel + LLL version)
```
Ā  = uniform random in Z_q^{n × (m - nk)}      # public part; use m = 2nk (standard)
R  = small-entry matrix, entries from {-b..b} (the TRAPDOOR)   ∈ Z^{(m-nk) × nk}
A  = [ Ā | G - Ā·R ]  mod q                     ∈ Z_q^{n × m}    # public key
# trapdoor is R itself; the implicit short basis is [[I, -R],[0, I]]-style
return A, R          # NOTE: trapdoor is R (small), not a big basis matrix
```
Key differences from current code:
- The trapdoor is the SMALL matrix R (norm ~b), not an LLL-reduced kernel basis.
- A's quality is controlled by construction; ‖R‖ is bounded by b, INDEPENDENT of the
  norm-growth pathology that's breaking the honest doctor now.

### SamplePre(A, R, u, s)  — invert f_A via the gadget
To find short x with A·x = u mod q:
1. **Perturbation** p ← sample a perturbation so the final output is trapdoor-
   independent (Peikert convolution). For a first correct version at small params you
   MAY use the simpler GPV-style/Klein sampling on the gadget if the convolution is too
   much — but PREFER the MP12 perturbation approach; mark any simplification.
2. **G-sampling**: solve G·z = (u - A·p) via the known gadget short basis — sample z
   from a discrete Gaussian over L^{v}(G) with width α (the gadget sampling width).
   Genise–Micciancio (2017/308) gives the linear-time method; the base-b digit
   decomposition in the gist is the simple correct version.
3. Combine: x = p + [R; I]·z  (map the gadget preimage back through the trapdoor).
Return x with A·x = u mod q, x short and distributed independently of R.

### Parameters (state them, from MP12 / GM18)
- b = 2, k = ceil(log2 q), m = 2nk (so m ≈ 2n log2 q — matches the paper's m).
- gadget width α ≈ (b+1)·η_ε(Z)  (smoothing parameter; use α ≈ 2·sqrt(ln(2m/ε)/π) as
  a concrete choice, state ε e.g. 2^-40).
- final width s ≥ C·‖R‖·α for the convolution to hide R (C a small constant; state it).
Emit all chosen values in a `note` trace event so they're auditable.

---

## 2. NewBasisDel under MP12 (the delegation the scheme needs)

ABB delegation (period→period via H1's R-matrix, keyword via H2's β) must now work with
the MP12 trapdoor, not a full basis. Two correct options:

**Option A (preferred, simplest correct):** ABB delegation with the MP12 trapdoor is
done by SamplePre on the extended matrix — to delegate from A (trapdoor R_A) to
A' = A·M^{-1} (or the tagged [Ā | G - Ā·R + H·G] form), sample a new small trapdoor R'
for A' using SamplePre with R_A. Concretely, ABB's tag construction: the tagged public
matrix A_id = [Ā | G - Ā·R + tag(id)·G]; with R you can sample for any tag. This is how
ABB HIBE actually delegates — use the tag mechanism instead of NewBasisDel on a full
basis.

**Option B (faithful to the paper's wording):** keep NewBasisDel but feed it the MP12
short basis derived from R (the basis [[I,-R],[0,I]] composed with the gadget basis),
so its input basis is genuinely short. This makes the paper's algorithm run on a
good basis instead of a bad one.

Prefer A. In EITHER case the honest doctor's per-period and word bases must come out
SHORT and usable — verify in §4.

---

## 3. Wire into the existing scheme

- Replace `trapgen()` in `backend/ppseb/trapgen.py` with the MP12 version (return A, R).
- Replace `sample_pre()` in `samplers.py` with the gadget-based SamplePre.
- Update `new_basis_del()` to Option A/B above (delegation via tags or via the R-derived
  short basis).
- `scheme.py` KeyExt / Trapdoor / PEKS / Verify / Decrypt logic is UNCHANGED in
  structure — they just now call the correct primitives. The corrected KeyExt from
  PATCH-06 (single-step, sk_prev source) still applies.
- H1 (period, low-norm invertible I+N) and H2 (FRD) are UNCHANGED — they were fine;
  the problem was never them, it was the trapdoor quality.
- Keep balanced representatives everywhere for norms.

---

## 4. MANDATORY correctness gate (do this before touching forward security again)

Re-run and assert ALL of:
1. `A·R`-consistency: `A · [R; I] ≡ G (mod q)` (the gadget relation holds).
2. **Honest end-to-end works at n ∈ {4, 8} and up:** doctor encrypts → PEKS → Trapdoor
   → Verify returns 1 for matching keyword, 0 for non-matching; Decrypt recovers the
   record. At EVERY period of a J=6 chain.
3. **Honest basis is USABLE at every period, every tested n:** gs_norm(honest period
   basis) and gs_norm(honest WORD basis) are both < the audited usability threshold —
   for n = 4, 8 (and ideally 16). This is the key regression: the honest doctor must
   no longer be flagged unusable. The word-basis honest-approval rate (PATCH-09) must
   be ~100%.
4. SamplePre output is short: ‖x‖ ≤ s·sqrt(m) for the stated s, and A·x = u mod q.
5. n is no longer restricted to powers of 2 by the kernel construction — with the
   gadget, any n works for prime q (verify n=4,6,8 all run). (If q must relate to b^k,
   state the actual constraint; with b=2, k=ceil(log2 q), any prime q is fine.)

If honest usability (#3) still fails, STOP — the MP12 port has a bug; do not proceed to
forward security. The honest doctor being usable is the precondition for everything.

---

## 5. What this fixes downstream

- The word-basis trust gate (PATCH-09) will now see honest word bases well under
  threshold → honest-approval ~100% → the gate's verdicts become meaningful.
- The forward-security sweep (PATCH-07/08) becomes trustworthy: with a proper honest
  baseline, "attacker basis comparable to honest" is a real comparison, not a
  comparison against a broken baseline.
- n=6, n=10 stop erroring (gadget works for any n), so the sweep grid fills in.
- The attacker's recovered-basis norms (Plot B) become interpretable against a
  known-good honest curve.

RE-RUN the overnight sweep AFTER this port passes §4. The earlier sweep results (all the
untrusted n=8 cells, the flip-flopping n=4 breaks) are SUPERSEDED — they were measured
against a broken honest baseline and should be discarded, not presented.

---

## 6. Tests

- `test_gadget_relation`: A·[R;I] ≡ G mod q.
- `test_samplepre_correct_and_short`: A·x ≡ u mod q and ‖x‖ ≤ s·sqrt(m).
- `test_honest_usable_all_periods`: honest period AND word basis < threshold for
  n∈{4,8}, J=6, all periods. (The regression test for the whole bug.)
- `test_honest_word_approval_100`: PATCH-09 honest self-approval ~100% after the port.
- `test_any_n_runs`: n∈{4,6,8} all run (no power-of-2 restriction).
- `test_end_to_end_search_correct`: matching→1, non-matching→0, decrypt recovers M, at
  every period.

---

## 7. Order
1. Implement gadget G, MP12 TrapGen (return A, R), gadget SamplePre. Port from the gist,
   cross-check MP12 / GM18 parameters.
2. Update NewBasisDel (tag-based delegation preferred).
3. Wire into scheme.py; keep H1/H2 and corrected KeyExt as-is.
4. Run §4 correctness gate. DO NOT PROCEED until honest usability #3 passes at n=4,8.
5. Re-run PATCH-09 verification (honest approval ~100%).
6. Re-run the overnight sweep; discard the pre-MP12 sweep results.
Report: the §4 gate results (honest period/word norms vs threshold per n), honest
approval rate, and confirmation that n=6/8 now run.
