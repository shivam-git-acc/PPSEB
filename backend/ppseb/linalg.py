"""Mod-q linear algebra, lattice bases, norms and discrete Gaussian sampling.

Everything downstream (TrapGen, SamplePre, NewBasisDel, the FRD hash) is built
out of the primitives here. Matrices that represent *lattice bases* use the
convention **columns are basis vectors** (so a basis `T` of `L_perp_q(A)` for
`A` of shape n x m satisfies `A @ T ≡ 0 (mod q)` and `T` has shape m x m).

We implement our own kernel-basis construction and our own LLL reduction
rather than reaching for a heavy lattice library, per CLAUDE.md: "implement
the primitives ourselves at small parameters ... readable and auditable."
"""

from __future__ import annotations

import random

import numpy as np
import sympy


# --------------------------------------------------------------------------
# Modular arithmetic helpers
# --------------------------------------------------------------------------

def mod_q(x: np.ndarray, q: int) -> np.ndarray:
    """Reduce every entry into [0, q)."""
    return np.mod(x, q)


def centered_mod_q(x: np.ndarray, q: int) -> np.ndarray:
    """Reduce every entry into (-q/2, q/2]."""
    r = np.mod(x, q)
    return np.where(r > q // 2, r - q, r)


def mat_inv_mod(A: np.ndarray, q: int) -> np.ndarray:
    """Exact modular inverse of a square matrix, mod prime q (via sympy)."""
    M = sympy.Matrix(A.astype(int).tolist())
    Minv = M.inv_mod(q)
    return np.array(Minv.tolist(), dtype=np.int64) % q


def rref_pivots_mod_q(A: np.ndarray, q: int) -> list[int]:
    """Gauss-Jordan elimination of A mod q (prime). Returns pivot column
    indices, in the order pivots were found. If it returns fewer than
    A.shape[0] indices, A does not have full row rank mod q.
    """
    M = (A.copy() % q).astype(np.int64)
    n, m = M.shape
    pivot_cols: list[int] = []
    row = 0
    for col in range(m):
        if row == n:
            break
        piv = None
        for r in range(row, n):
            if M[r, col] % q != 0:
                piv = r
                break
        if piv is None:
            continue
        if piv != row:
            M[[row, piv]] = M[[piv, row]]
        inv = pow(int(M[row, col]), q - 2, q)
        M[row] = (M[row] * inv) % q
        for r in range(n):
            if r != row and M[r, col] % q != 0:
                M[r] = (M[r] - M[r, col] * M[row]) % q
        pivot_cols.append(col)
        row += 1
    return pivot_cols


def find_full_rank_partition(A: np.ndarray, q: int) -> tuple[list[int], list[int], np.ndarray]:
    """Partition A's m columns into an invertible n x n block (A1, at column
    indices `a1_idx`) and the remaining m-n columns (`a2_idx`), via RREF.
    Returns (a1_idx, a2_idx, A1_inv_mod_q).
    """
    n, m = A.shape
    a1_idx = rref_pivots_mod_q(A, q)
    if len(a1_idx) < n:
        raise ValueError(
            f"A does not have full row rank mod q={q} "
            f"(found rank {len(a1_idx)} < n={n}); resample A."
        )
    a2_idx = [c for c in range(m) if c not in set(a1_idx)]
    A1 = A[:, a1_idx]
    A1_inv = mat_inv_mod(A1, q)
    return a1_idx, a2_idx, A1_inv


def particular_solution(
    A: np.ndarray, v: np.ndarray, q: int,
    partition: tuple[list[int], list[int], np.ndarray] | None = None,
) -> np.ndarray:
    """Any t0 in Z_q^m with A @ t0 = v (mod q)."""
    n, m = A.shape
    if partition is None:
        partition = find_full_rank_partition(A, q)
    a1_idx, _a2_idx, A1_inv = partition
    t0 = np.zeros(m, dtype=np.int64)
    t0[a1_idx] = (A1_inv @ v) % q
    return t0


def kernel_basis_mod_q(
    A: np.ndarray, q: int,
    partition: tuple[list[int], list[int], np.ndarray] | None = None,
) -> np.ndarray:
    """A full-rank integer basis (columns) of L_perp_q(A) = {x in Z^m : Ax=0 mod q}.

    Construction (documented in CLAUDE.md §3.2): pick an invertible n x n
    submatrix A1 (columns a1_idx) and the remaining columns A2 (a2_idx). Then

        basis = [ q*e_j for j in a1_idx ]  U  [ w_k for k in a2_idx ]

    where w_k has a 1 in position a2_idx[k], and -(A1^-1 A2[:,k]) mod q placed
    into the a1_idx coordinates. In the coordinate order (a1_idx, a2_idx) this
    is the block-triangular matrix [[q I_n, Y], [0, I_{m-n}]], determinant
    q^n — exactly the index of L_perp_q(A) in Z^m, so it is a genuine basis,
    not merely a spanning set. The vectors are long (entries ~q); LLL
    reduction (see `lll_reduce`) shortens them into a usable trapdoor basis.
    """
    n, m = A.shape
    if partition is None:
        partition = find_full_rank_partition(A, q)
    a1_idx, a2_idx, A1_inv = partition
    A2 = A[:, a2_idx]

    basis = np.zeros((m, m), dtype=np.int64)
    col = 0
    for j in a1_idx:
        basis[j, col] = q
        col += 1
    Y = centered_mod_q((-(A1_inv @ A2)) % q, q)  # n x (m-n), small representatives
    for k, a2_col in enumerate(a2_idx):
        basis[a2_col, col] = 1
        basis[a1_idx, col] = Y[:, k]
        col += 1
    return basis


# --------------------------------------------------------------------------
# Norms / Gram-Schmidt
# --------------------------------------------------------------------------

def vec_norm(v: np.ndarray) -> float:
    return float(np.linalg.norm(v.astype(float)))


def gram_schmidt(B: np.ndarray) -> tuple[list[np.ndarray], list[list[float]]]:
    """Real Gram-Schmidt of the columns of integer/float matrix B.
    Returns (Bstar, mu) with Bstar a list of float vectors and mu[i][j] the
    projection coefficient of b_i onto b_j* (j < i).
    """
    m, k = B.shape
    Bstar: list[np.ndarray] = []
    mu = [[0.0] * k for _ in range(k)]
    for i in range(k):
        bi = B[:, i].astype(float).copy()
        for j in range(i):
            denom = float(np.dot(Bstar[j], Bstar[j]))
            mu[i][j] = float(np.dot(B[:, i], Bstar[j])) / denom if denom > 0 else 0.0
            bi -= mu[i][j] * Bstar[j]
        Bstar.append(bi)
    return Bstar, mu


def gram_schmidt_norm(B: np.ndarray) -> float:
    """max_i ||b_i*|| — the standard 'quality' measure of a lattice basis,
    central to Finding 2 (forward-security norm experiment)."""
    Bstar, _mu = gram_schmidt(B)
    return max(float(np.linalg.norm(b)) for b in Bstar)


def matrix_col_norm(M: np.ndarray) -> float:
    """max column Euclidean norm — used to report ||R|| / ||R^-1|| for H1."""
    M = M.astype(float)
    return float(np.max(np.linalg.norm(M, axis=0)))


# --------------------------------------------------------------------------
# LLL reduction (own implementation; CLAUDE.md §9 step 1)
# --------------------------------------------------------------------------

def lll_reduce(B: np.ndarray, delta: float = 0.75, max_steps: int = 200_000) -> np.ndarray:
    """Classic (floating-point Gram-Schmidt) LLL reduction of the columns of
    integer matrix B. Returns a reduced integer basis of the same lattice
    (same column space / determinant up to sign), shape unchanged.

    This is a textbook, unoptimized LLL: correct and readable rather than
    asymptotically fast, which is the trade-off CLAUDE.md asks for at these
    (tiny) parameter sizes.
    """
    m, k = B.shape
    # dtype=object -> arbitrary-precision Python ints; intermediate HNF-style
    # vectors can have entries far larger than int64 range before reduction.
    basis = [B[:, i].astype(object).copy() for i in range(k)]

    # Bstar[i] / normsq[i] depend only on basis[0..i], so a size-reduction of
    # basis[kk] against basis[j<kk] never invalidates Bstar[j<kk]: only row kk
    # needs recomputing. This turns the naive O(k) full-Gram-Schmidt-per-step
    # LLL into an O(k) *row* recompute per step, which is what makes m~70
    # dimensions run in seconds rather than minutes.
    Bstar: list[np.ndarray] = [None] * k       # type: ignore[list-item]
    normsq: list[float] = [0.0] * k
    mu = [[0.0] * k for _ in range(k)]

    def recompute(i: int) -> None:
        bi_full_f = basis[i].astype(float)  # convert once, not once per j
        bi = bi_full_f.copy()
        for j in range(i):
            num = float(np.dot(bi_full_f, Bstar[j]))
            mu[i][j] = num / normsq[j] if normsq[j] > 0 else 0.0
            bi -= mu[i][j] * Bstar[j]
        Bstar[i] = bi
        normsq[i] = float(np.dot(bi, bi))

    recompute(0)
    recompute(1) if k > 1 else None
    kk = 1
    steps = 0
    while kk < k and steps < max_steps:
        steps += 1
        for j in range(kk - 1, -1, -1):
            r = round(mu[kk][j])
            if r != 0:
                basis[kk] = basis[kk] - r * basis[j]
                recompute(kk)
        rhs = (delta - mu[kk][kk - 1] ** 2) * normsq[kk - 1]
        if normsq[kk] >= rhs:
            kk += 1
            if kk < k:
                recompute(kk)
        else:
            basis[kk], basis[kk - 1] = basis[kk - 1], basis[kk]
            recompute(kk - 1)
            recompute(kk)
            kk = max(kk - 1, 1)
    return np.array([[int(x) for x in col] for col in basis], dtype=np.int64).T


# --------------------------------------------------------------------------
# Rank over GF(q) — used to test linear independence when re-randomizing
# a basis (NewBasisDel's RandBasis step)
# --------------------------------------------------------------------------

def real_rank(M: np.ndarray) -> int:
    """Integer/rational linear independence rank of M's columns, via a
    numerically-tolerant SVD. Note this is *not* the same question as
    `rank_mod_q`: a basis of L_perp_q(A) has determinant +/- q^n, so it is
    always rank-deficient mod q by construction — independence of lattice
    basis vectors must be tested over Z/Q, not over F_q.
    """
    if M.shape[1] == 0:
        return 0
    return int(np.linalg.matrix_rank(M.astype(float)))


def rank_mod_q(M: np.ndarray, q: int) -> int:
    if M.shape[1] == 0:
        return 0
    A = (M.copy() % q).astype(np.int64)
    rows, cols = A.shape
    row = 0
    for col in range(cols):
        if row == rows:
            break
        piv = None
        for r in range(row, rows):
            if A[r, col] % q != 0:
                piv = r
                break
        if piv is None:
            continue
        if piv != row:
            A[[row, piv]] = A[[piv, row]]
        inv = pow(int(A[row, col]), q - 2, q)
        A[row] = (A[row] * inv) % q
        for r in range(rows):
            if r != row and A[r, col] % q != 0:
                A[r] = (A[r] - A[r, col] * A[row]) % q
        row += 1
    return row


# --------------------------------------------------------------------------
# Discrete Gaussian sampling (Klein / GPV algorithm)
# --------------------------------------------------------------------------

def discrete_gaussian_1d(center: float, sigma: float, rng: random.Random, tail: float = 8.0) -> int:
    """Sample z ~ D_{Z, sigma, center} by rejection sampling."""
    lo = int(np.floor(center - tail * sigma))
    hi = int(np.ceil(center + tail * sigma))
    if hi <= lo:
        hi = lo + 1
    while True:
        z = rng.randint(lo, hi)
        p = np.exp(-((z - center) ** 2) / (2 * sigma * sigma))
        if rng.random() < p:
            return z


def klein_sample(
    basis: np.ndarray, center: np.ndarray, sigma: float, rng: random.Random,
    Bstar: list[np.ndarray] | None = None,
) -> np.ndarray:
    """Klein/GPV discrete-Gaussian sampler over the lattice spanned by
    `basis` (columns), centered at `center`. Returns an integer vector in
    the lattice, close to `center`, sampled from (approximately) the
    discrete Gaussian of width `sigma`.

    `Bstar` (the basis's Gram-Schmidt vectors) may be precomputed and passed
    in when sampling many times against the same basis — recomputing it is
    the dominant cost of this function.
    """
    m, k = basis.shape
    if Bstar is None:
        Bstar, _mu = gram_schmidt(basis)
    c = center.astype(float).copy()
    z = [0] * k
    for i in range(k - 1, -1, -1):
        bi_star = Bstar[i]
        denom = float(np.dot(bi_star, bi_star))
        ci = float(np.dot(c, bi_star)) / denom if denom > 0 else 0.0
        norm_bi_star = float(np.linalg.norm(bi_star))
        sigma_i = max(sigma / norm_bi_star, 1e-6) if norm_bi_star > 0 else sigma
        zi = discrete_gaussian_1d(ci, sigma_i, rng)
        z[i] = zi
        c = c - zi * basis[:, i].astype(float)
    v = np.zeros(m, dtype=np.int64)
    for i in range(k):
        v += z[i] * basis[:, i]
    return v
