"""H1 and H2 — the two hash functions the PPSEB paper invokes but never
constructs (CLAUDE.md §3.3, §3.4). Both constructions below are *corrections*
in the sense the paper leaves them unspecified; each use is logged as a
`correction` trace event so the gap is visible, not hidden.

H1(pk, j)  -> Z_q^{m x m}, low-norm AND invertible (paper's Lemma 5 / D_{mxm})
H2(w, j)   -> Z_q^{m x m}, a full-rank-difference (FRD) encoding: for w != w',
              H2(w,j) - H2(w',j) is invertible mod q.
"""

from __future__ import annotations

import functools
import hashlib
import random

import numpy as np
from sympy.polys.domains import ZZ

from .linalg import mat_inv_mod, to_safe_int_array
from .params import Params
from .trace import Trace


# --------------------------------------------------------------------------
# H1: I + (low-norm strictly-upper-triangular nilpotent) -> unit-upper-
# triangular, hence always invertible (det = 1), and low-norm by construction.
# --------------------------------------------------------------------------

def _seed_from(*parts: bytes) -> int:
    h = hashlib.sha256(b"||".join(parts)).digest()
    return int.from_bytes(h, "big")


def H1(pk: np.ndarray, j: int, params: Params, trace: Trace | None = None) -> np.ndarray:
    """H1(pk, j) = I + N, N strictly upper triangular with entries in
    {-1, 0, 1} drawn deterministically from SHA256(pk || j)."""
    m = params.m
    seed = _seed_from(pk.astype(np.int64).tobytes(), str(j).encode())
    rng = random.Random(seed)
    R = np.eye(m, dtype=np.int64)
    for i in range(m):
        for k in range(i + 1, m):
            R[i, k] = rng.choice((-1, 0, 1))

    if trace is not None:
        R_inv = H1_inverse(R)
        from .linalg import matrix_col_norm
        trace.correction(
            "H1(pk, j) instantiated",
            paper_says="H1: Z_q^{n x m} x N -> Z_q^{m x m}, no construction given.",
            we_do="H1(pk,j) = I + N, N strictly upper triangular with entries "
                  "in {-1,0,1} seeded by SHA256(pk || j). det(I+N) = 1 always, "
                  "so H1 is always invertible; entries are tiny, so it is low-norm.",
            because="Lemma 5 / the D_{m x m} requirement demands a low-norm "
                    "*invertible* output; a naive uniform matrix over Z_q would "
                    "be invertible with good probability but NOT low-norm, which "
                    "breaks the norm bounds NewBasisDel/SamplePre need.",
            data={
                "shape": [m, m],
                "R_norm": matrix_col_norm(R),
                "R_inv_norm": matrix_col_norm(R_inv),
            },
            algo="H1",
        )
    return R


def H1_inverse(R: np.ndarray) -> np.ndarray:
    """Exact integer inverse of a unit-upper-triangular matrix R = I + N via
    back substitution (no division needed: R's diagonal is 1, so every step
    is an exact integer subtraction). Since det(R) = 1, this exact integer
    inverse IS the inverse mod any q too (just reduce it mod q).

    Back-substituting a random +/-1 upper-triangular matrix can (rarely, but
    in principle) produce entries that grow much faster than the input size
    suggests — worst case exponentially in m. Computation is kept exact via
    `object` (arbitrary-precision) throughout; only the *returned* array is
    opportunistically downcast to int64, and only when every entry actually
    fits (see `to_safe_int_array`), so a pathological R can't silently
    overflow into a wrong mod-q inverse.
    """
    m = R.shape[0]
    Rint = R.astype(object)
    Rinv = np.zeros((m, m), dtype=object)
    for col in range(m):
        x = [0] * m
        for row in range(m - 1, -1, -1):
            rhs = 1 if row == col else 0
            s = rhs - sum(int(Rint[row, k]) * x[k] for k in range(row + 1, m))
            x[row] = s  # divide by R[row,row] == 1
        for row in range(m):
            Rinv[row, col] = x[row]
    return to_safe_int_array(Rinv)


# --------------------------------------------------------------------------
# H2: full-rank-difference (FRD) encoding via a LOW-NORM twisted-circulant
# embedding of GF(q^n), block-diagonally repeated up to size m (CLAUDE.md §3.4).
# --------------------------------------------------------------------------

# H2's coefficient vector a=(a_0,...,a_{n-1}) is drawn from a SMALL range
# rather than the full [0, q); see the module-level note above H2 for why.
H2_COEFF_RANGE = 11


@functools.lru_cache(maxsize=None)
def _irreducible_twist(n: int, q: int) -> int:
    """Smallest c >= 2 for which f(x) = x^n - c is irreducible over GF(q).
    Represents GF(q^n) = GF(q)[x]/(x^n - c), whose 'multiply by x' operator is
    a simple twisted cyclic shift (x^n = c) rather than a general companion
    matrix — that's what lets `_twisted_circulant` build a matrix whose
    entries are literally the (small) input coefficients, instead of an
    opaque companion-matrix expansion that spreads them across all of Z_q.

    KNOWN LIMITATION: x^n - c is irreducible over GF(q) only for n whose
    every prime factor divides ord(GF(q)*) = q-1 (Lidl-Niederreiter's
    binomial irreducibility criterion) — for q=257, q-1=256=2^8, so this
    holds only for n a power of 2 (2, 4, 8, 16, ...). n=6 (a factor of 3,
    which does not divide 256) has NO valid c at all, for any q with
    q-1=256 — not a search failure, a genuine non-existence. Callers that
    need to vary n (e.g. attacks.end_to_end's dimension sweep) should pick
    n from {2, 4, 8, 16, ...} when q=257, or a different q whose q-1 shares
    n's prime factors otherwise.
    """
    from sympy.polys.galoistools import gf_irreducible_p
    for c in range(2, q):
        f = [1] + [0] * (n - 1) + [(-c) % q]
        if gf_irreducible_p(f, q, ZZ):
            return c
    raise RuntimeError(
        f"no irreducible x^{n} - c exists mod q={q}: every prime factor of n must "
        f"divide q-1={q - 1}. For q=257 (q-1=256=2^8), n must be a power of 2 "
        f"(2, 4, 8, 16, ...); n={n} has a prime factor that does not divide 256."
    )


def _twisted_circulant(a: list[int], c: int, q: int) -> np.ndarray:
    """The n x n matrix representing 'multiply by the field element with
    coefficients a' in GF(q)[x]/(x^n - c). Because x^n = c in this ring,
    shifting a coefficient past position n-1 just re-enters at position 0
    scaled by c: M[i,j] = a[i-j] if i>=j, else c*a[i-j+n] (mod q). Entries
    are the small a_i's themselves (times the small constant c in the
    wrapped corner) — no companion-power blowup.
    """
    n = len(a)
    M = np.zeros((n, n), dtype=np.int64)
    for i in range(n):
        for j in range(n):
            M[i, j] = a[i - j] if i >= j else (c * a[i - j + n]) % q
    return M


def H2(w: str, j: int, params: Params, trace: Trace | None = None) -> np.ndarray:
    """H2(w, j) -> beta in Z_q^{m x m}. For w != w', beta(w,j) - beta(w',j) is
    invertible mod q (full-rank-difference property), because it is the
    block-diagonal repetition of the matrix representing multiplication by a
    nonzero element of the field GF(q^n) — and in a field, multiplication by
    any nonzero element is a bijection, hence its matrix is invertible.

    Low-norm, not just FRD: CLAUDE.md notes H2's output is also "used in
    NewBasisDel" (Trapdoor, §3.6) exactly where KeyExt uses H1's R — and
    NewBasisDel only produces a usable (short) delegated basis when its
    transform argument is low-norm. A plain companion-matrix embedding is
    invertible-difference but NOT low-norm (its entries spread across all of
    Z_q), which blows up Trap's norm past the q/4 correctness margin at these
    toy parameters. We instead represent GF(q^n) as GF(q)[x]/(x^n - c) for a
    small twist c, and draw each coefficient from a small range — the
    resulting matrix's entries ARE those small coefficients (see
    `_twisted_circulant`), so beta stays low-norm the same way H1's R does.
    """
    n, m, q = params.n, params.m, params.q
    repeats = m // n

    seed = _seed_from(w.encode(), str(j).encode(), b"H2")
    rng = random.Random(seed)
    a = [rng.randrange(H2_COEFF_RANGE) for _ in range(n)]
    if not any(a):
        a[0] = 1  # avoid the degenerate zero field element (beta must be invertible)

    c = _irreducible_twist(n, q)
    M_small = _twisted_circulant(a, c, q)

    beta = np.zeros((m, m), dtype=np.int64)
    for r in range(repeats):
        beta[r * n:(r + 1) * n, r * n:(r + 1) * n] = M_small

    if trace is not None:
        from .linalg import matrix_col_norm
        trace.correction(
            "H2(w, j) instantiated as a LOW-NORM FRD encoding",
            paper_says="H2: {0,1}^l1 x N -> Z_q^{m x m}, no construction given, "
                       "yet the scheme inverts beta_j and reuses it inside "
                       "NewBasisDel (Trapdoor, §3.6) exactly where KeyExt uses H1's R.",
            we_do="H2(w,j) maps (w,j) to a small-coefficient field element a "
                  "in GF(q)[x]/(x^n - c) (c found by search, small), represents "
                  "'multiply by a' as a twisted-circulant n x n matrix whose "
                  "entries ARE the small coefficients, then block-diagonally "
                  "repeats it m/n times to reach the required m x m shape.",
            because="Being used inside NewBasisDel means beta needs the SAME "
                    "low-norm property H1's R needs — a full companion-matrix "
                    "FRD is invertible-difference but has entries spread across "
                    "all of Z_q, which (empirically) blows Trap's norm past the "
                    "q/4 decode threshold and breaks Verify's correctness at "
                    "these toy parameters. GF(q^n) is still a field here, so "
                    "for a != a' the difference is a nonzero field element and "
                    "multiplication by it is still a bijection -> still invertible.",
            data={"shape": [m, m], "field_degree": n, "blocks_repeated": repeats,
                  "twist_c": c, "beta_col_norm": matrix_col_norm(beta)},
            algo="H2",
        )
    return beta


def H2_inverse(beta: np.ndarray, q: int) -> np.ndarray:
    return mat_inv_mod(beta, q)
