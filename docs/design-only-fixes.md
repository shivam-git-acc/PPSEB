# Design-only fixes: what they would change and what they would cost

The mid-sem deck (Part 3) proposes fixes of two kinds: change the cryptography,
or change who may do what. MedVault-PQ implements the second kind (modes A′, B
and C, signed one-time requests, PIR, consent and revocation). This document
covers the fixes that were **not** built, for each one: which game in
[security-games.md](security-games.md) it addresses, what it would change, what
it would cost, and what was not measured. Nothing here is a result; where a
number appears it is either measured elsewhere in this repository (and says
where) or an external reference point (and says so).

---

## 1. Module-LWE redesign

**Addresses.** G1 (key recovery from the public key, deck finding 2) and the
scaling finding (deck finding 8).

**Why it is needed.** At the paper's parameters the public key alone yields a
short enough basis with BKZ block size 2, so every downstream property is
moot. Plain LWE needs much larger dimensions to stop that, and the research
arm measured what larger dimensions cost: trapdoor generation grows from
1.13 s at n = 4 to 204.8 s at n = 16 (181×), and the public key is a full
n × m matrix.

**What would change.** Replace `Z_q^{n×m}` with a module over
`R_q = Z_q[x]/(x^d + 1)`: the public key becomes a small matrix of
polynomials, and multiplication drops from O(n²) to O(d log d) with the NTT.
The trapdoor would move to the MP12 gadget construction, a primitive of which
already exists in `ppseb/gadget.py`, because it supports delegation without the
dense-basis norm growth.

**The hard parts.**
- *FRD keyword encoding.* `H2` must map keywords to elements whose pairwise
  differences are invertible. Over `R_q` that needs a ring-specific full-rank
  difference encoding; the current companion-matrix construction does not
  carry over directly.
- *Basis delegation.* `NewBasisDel` (keywords and key evolution) must be
  re-derived for module lattices.
- *The security proof.* Theorem 1 would need redoing; its log₂(2m) loss (G0)
  would change with the new m.

**Reference point, not a computation.** ML-KEM-768 uses module rank 3 over
d = 256, q = 3329 (dimension 768) for its stated security level. A trapdoor-
based PEKS samples preimages and so needs a larger modulus than a KEM; its
parameters have not been derived here.

**What it would not fix.** Offline keyword guessing (G2) is structural to a
public tester and survives any parameter choice; mode C's keyword
authentication would still be needed. Replay, planting and leakage are protocol
findings and are untouched.

**Cost category (deck slide 44):** costs speed (heavier maths per operation,
a full re-derivation).

---

## 2. ORAM vs PIR

**Addresses.** G5 (access-pattern leakage, deck finding 6).

**What PIR does (built, M5).** SimplePIR-style single-server LWE PIR hides
*which record is retrieved* from the storage server. Measured
(`repro.json → pir`): 2 MiB hint, query 64 B at 16 rows to 4 096 B at 1 024 rows,
2 048 B answer, and the server touches every row per query (linear work).
`test_property_19_live_retrieve_never_calls_targeted_get` checks that the
storage side never receives a record id.

**What PIR does not do.** It does not change the search node's view. The search
node computes the matches, so it sees which records answer which token. G5
measures exactly that residual: Tier 2 accuracy 0.755 against the mode B search
node, against 0.19 for the mode B chain.

**What ORAM would change.** With an oblivious RAM (for example Path ORAM) the
server holding the index sees only uniformly random paths, never which bucket
was read. To protect *search*, the index lookup itself would have to run
through ORAM, driven by the doctor's client (which holds the position map), so
that matching happens client-side. Tier 1 and Tier 2 would then lose their
input: the co-access signal that cover queries cannot remove
(`test_cover_queries_lower_tier2_but_cannot_hide_tier1`).

**Cost.** Path ORAM reads and writes O(log N) buckets per access (with a small
constant bucket size), keeps a client-side position map and stash, and needs a
round trip per access. It also turns search into a client protocol, so the
chain can no longer run or verify the search publicly.

**Not measured.** No ORAM was implemented; no bandwidth or latency is claimed.
Result-volume padding (how many records a search returns) would still be needed
on top, since ORAM hides which records, not how many.

**Cost category:** costs openness (search can no longer be a public on-chain
computation) and speed.

---

## 3. Forward security: what would make a claim meaningful

**Addresses.** G6 (deck finding 9).

**Where things stand.** The paper's break-in phase exists, but forward security
is never proven as its own statement. Measured at the paper's parameters, the
backward attack (run the public `R` chain back, then reduce) recovers a working
old trapdoor, but the public key alone already does that (G1), so the stolen key
adds nothing. That is why the claim is *vacuous* here rather than *broken*.

**What MedVault built (M7).** The structure the deck proposes, tree-based key
evolution with erasure: a depth-4 binary tree (31 nodes, 16 epochs), root basis
from TrapGen, each child from NewBasisDel with a node-specific low-norm matrix.
`A·T ≡ 0 (mod q)` holds at every node; Gram–Schmidt norms stay at 2.8–4.2 per
level against a 10.57 toy threshold; PEKS matches 16/16 within an epoch and
0/16 across; a past epoch is refused after its keys are erased. So at depth 4
delegation cost is **not** the obstacle: the norms do not grow level by level.

**What a forward-security claim would need, and does not have here:**
1. *Parameters at which G1 fails.* The deck's boundary measurements broke
   every cell they completed with the public key alone at BKZ block size 2;
   the larger cells were not measured within the compute budget. Until a cell
   resists the public-key attack, the stolen-key game cannot even be posed.
2. *G6 stated and proven on its own*, with the tree's erasure in the model:
   an adversary breaking in at epoch j gets exactly the frontier, and old
   leaves must be unreachable from it.
3. *Real erasure.* Python cannot guarantee that a deleted key is gone from
   memory; a deployment would need key storage that can actually erase.

**Claim allowed:** structure implemented, correctness verified at every node,
norm cost measured. **Not allowed:** "forward security proven" or "forward
secure" (R16.6).

**Cost category:** costs speed (one delegation per tree level per epoch).

---

## 4. Zero-knowledge well-formedness

**Addresses.** G4 (result integrity, deck finding 5) for the adversary that the
built fixes do not stop: a registered patient on an open ledger.

**Why the built fixes stop short.** A signature proves who wrote an entry, not
what it contains. The A′ shape check rejects the canonical `CT₂ = 0` forgery and
any short `CT₂` column, with 0 false rejections in 1 000 honest ciphertexts,
but it is a necessary condition only: it cannot tell an honest uniform-looking
`CT₂` from a dishonest one. Mode B sidesteps the question entirely (an HMAC
entry matches one token), at the price of public verifiability.

**The statement to prove.** "I know `B`, `e₁`, `e₂` with `e₁`, `e₂` short, and a
keyword `w`, such that `CT₁ = μᵀB + e₁ + y⌊q/2⌋` and
`CT₂ = (pk·H2(w, j)⁻¹)ᵀB + e₂`", with `w`, `B` and the noise hidden. The
contract verifies the proof before accepting the entry.

**The hard parts.**
- The linear part is modest: `m·l = 720` noise coefficients and an `n × l`
  mask at the paper's parameters, plus range proofs for the noise.
- `H2` is SHA-256-based with an FRD encoding; proving it inside the statement
  dominates the cost. A variant that commits to the authenticated keyword
  (as in mode C) and proves consistency with the commitment would avoid hashing
  in-circuit, but has not been designed in detail.
- A pairing-based SNARK such as the Groth16 already used for consent (M6)
  would work in principle but is classical, which cuts against the post-quantum
  story; lattice-based proofs of short linear relations are the consistent
  choice and are not in this stack.

**Not measured.** No circuit was built; no proof size, proving time or gas is
claimed.

**Cost category:** costs speed (a proof per entry) and adds a trusted-setup
question if a SNARK with a ceremony is used.

---

## Summary

| Fix | Game | Built? | Main cost | Main limitation |
| --- | --- | --- | --- | --- |
| Module-LWE | G1, scaling | no | full re-derivation; slower per op than toy LWE | KGA remains structural |
| ORAM | G5 | no (PIR built) | O(log N) per access, client state, no public search | volume still leaks |
| Forward security claim | G6 | structure only (M7) | delegation per level | needs parameters where G1 fails |
| ZK well-formedness | G4 | no (A′ stopgap built) | proof per entry; hashing in-circuit | lattice ZK not in stack |
