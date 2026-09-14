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
from sympy.polys.galoistools import gf_irreducible

from .linalg import mat_inv_mod
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
    inverse IS the inverse mod any q too (just reduce it mod q)."""
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
    return Rinv.astype(np.int64)


# --------------------------------------------------------------------------
# H2: full-rank-difference (FRD) encoding via a companion-matrix embedding of
# GF(q^n), block-diagonally repeated up to size m (CLAUDE.md §3.4).
# --------------------------------------------------------------------------

@functools.lru_cache(maxsize=None)
def _irreducible_companion(n: int, q: int) -> np.ndarray:
    """Companion matrix C (n x n, mod q) of a monic irreducible degree-n
    polynomial over GF(q): C represents 'multiply by x' in GF(q^n) = GF(q)[x]/(f).
    Cached per (n, q) for the lifetime of the process so H2 is a consistent
    deterministic function of (w, j) throughout a lab session.
    """
    coeffs = gf_irreducible(n, q, ZZ)  # [1, a_1, ..., a_n], f = x^n + sum a_k x^{n-k}
    d = [(-int(coeffs[n - i])) % q for i in range(n)]  # x^n = sum d_i x^i mod f
    C = np.zeros((n, n), dtype=np.int64)
    for i in range(n - 1):
        C[i + 1, i] = 1
    C[:, n - 1] = d
    return C


def _companion_power_basis(C: np.ndarray, q: int) -> list[np.ndarray]:
    n = C.shape[0]
    powers = [np.eye(n, dtype=np.int64)]
    for _ in range(1, n):
        powers.append((powers[-1] @ C) % q)
    return powers


def H2(w: str, j: int, params: Params, trace: Trace | None = None) -> np.ndarray:
    """H2(w, j) -> beta in Z_q^{m x m}. For w != w', beta(w,j) - beta(w',j) is
    invertible mod q (full-rank-difference property), because it is the
    block-diagonal repetition of the matrix representing multiplication by a
    nonzero element of the field GF(q^n) — and in a field, multiplication by
    any nonzero element is a bijection, hence its matrix is invertible.
    """
    n, m, q = params.n, params.m, params.q
    repeats = m // n

    seed = _seed_from(w.encode(), str(j).encode(), b"H2")
    rng = random.Random(seed)
    a = np.array([rng.randrange(q) for _ in range(n)], dtype=np.int64)

    C = _irreducible_companion(n, q)
    powers = _companion_power_basis(C, q)
    M_small = np.zeros((n, n), dtype=np.int64)
    for i in range(n):
        M_small = (M_small + a[i] * powers[i]) % q

    beta = np.zeros((m, m), dtype=np.int64)
    for r in range(repeats):
        beta[r * n:(r + 1) * n, r * n:(r + 1) * n] = M_small

    if trace is not None:
        trace.correction(
            "H2(w, j) instantiated as an FRD encoding",
            paper_says="H2: {0,1}^l1 x N -> Z_q^{m x m}, no construction given, "
                       "yet the scheme inverts beta_j and needs FRD differences "
                       "for the security reduction.",
            we_do="H2(w,j) maps (w,j) to a field element a in GF(q^n) (via SHA256), "
                  "represents 'multiply by a' as an n x n companion matrix over a "
                  "fixed irreducible polynomial, then block-diagonally repeats it "
                  "m/n times to reach the required m x m shape (a documented "
                  "approximation of a full m-dimensional FRD map).",
            because="GF(q^n) is a field, so for a != a' the difference a-a' is "
                    "a nonzero field element and multiplication by it is a "
                    "bijection -> its matrix is invertible. Repeating an "
                    "invertible n x n block along the diagonal keeps the whole "
                    "m x m difference invertible (block-diagonal determinant is "
                    "the product of block determinants).",
            data={"shape": [m, m], "field_degree": n, "blocks_repeated": repeats},
            algo="H2",
        )
    return beta


def H2_inverse(beta: np.ndarray, q: int) -> np.ndarray:
    return mat_inv_mod(beta, q)
