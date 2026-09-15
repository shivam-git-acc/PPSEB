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
# Overflow-safe integer arrays
# --------------------------------------------------------------------------

# A basis produced by *low-norm* delegation (H1's I+N) stays comfortably
# inside int64 for any J we'd realistically demo. But Finding 2 deliberately
# also runs a "naive uniform-invertible" H1 for comparison (CLAUDE.md §4:
# "run it under BOTH H1 instantiations"), and THAT one has no norm bound at
# all: its Gram-Schmidt norm was observed to grow ~600x per period, so by
# ~7-8 chained periods entries exceed int64's ~9.2e18 range. numpy int64
# overflow wraps silently (no exception) rather than raising, which then
# corrupts the exact "A.T = 0 (mod q)" identity these functions depend on —
# that silent corruption, not a logic bug in the delegation math, is what
# produced a spurious "NewBasisDel produced an invalid basis" failure at
# J=8 with the naive variant. Fix: any matrix that isn't already reduced mod
# q (a lattice basis's entries aren't — they must be actual short-ish
# integers, not residues) is kept in `object` dtype (arbitrary-precision
# Python ints) end to end, only downcast to int64 when it's provably safe.
INT64_SAFE_BOUND = 2**62  # comfortable margin below int64's ~9.2e18 max


def to_safe_int_array(M: np.ndarray) -> np.ndarray:
    """Return M as int64 if every entry fits comfortably in int64, else as
    `object` (arbitrary-precision Python ints, no overflow risk)."""
    obj = M.astype(object)
    max_abs = 0
    it = obj.flat
    for x in it:
        ax = x if x >= 0 else -x
        if ax > max_abs:
            max_abs = ax
        if max_abs > INT64_SAFE_BOUND:
            return obj
    return obj.astype(np.int64)


def safe_matmul(A: np.ndarray, B: np.ndarray) -> np.ndarray:
    """A @ B, done in `object` (arbitrary-precision) arithmetic.

    This is intentionally NOT conditional on A/B already being object-dtype.
    An earlier version only promoted when an operand was already object,
    reasoning that "if both fit in int64, the product does too" — that's
    wrong: int64 matmul's internal accumulation can overflow even when every
    individual entry of A and B fits comfortably in int64 (e.g. summing ~70
    products of two ~1e17 values overflows int64's ~9.2e18 range, even
    though 1e17 alone does not). That silent wraparound is exactly what
    produced a spurious "NewBasisDel produced an invalid basis" failure for
    Finding 2's naive-uniform H1 comparison at J~6-8. Always promoting is the
    only way to be sure; it costs some speed, never correctness.
    """
    return A.astype(object) @ B.astype(object)


def mat_mod_mixed(A: np.ndarray, B: np.ndarray, q: int) -> np.ndarray:
    """(A @ B) % q — see `safe_matmul`."""
    return safe_matmul(A, B) % q


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
    result = np.array([[int(x) for x in col] for col in basis], dtype=object).T
    return to_safe_int_array(result)


_FPYLLL_AVAILABLE: bool | None = None  # cached probe result


def fpylll_available() -> bool:
    global _FPYLLL_AVAILABLE
    if _FPYLLL_AVAILABLE is None:
        try:
            import fpylll  # noqa: F401
            _FPYLLL_AVAILABLE = True
        except ImportError:
            _FPYLLL_AVAILABLE = False
    return _FPYLLL_AVAILABLE


def strong_reduce(B: np.ndarray, block_size: int = 10, delta: float = 0.99) -> tuple[np.ndarray, str]:
    """A stronger reduction than the default LLL(delta=0.75) — for a
    LEGITIMATE key holder's own basis (PATCH 03 Lever 2), never for an
    attacker's recovered candidate; keep the two uses separate in code and
    in the trace, since applying this to the legit side is not "helping the
    attacker" — an honest key holder is entitled to use the best basis they
    can compute.

    Prefers fpylll's BKZ (a strictly stronger reduction than LLL) if the
    package is importable; falls back to our own LLL at a delta much closer
    to 1 (0.99 vs the default 0.75) — a strictly better Lovasz condition,
    though still polynomial-time LLL, not true BKZ. Returns
    (reduced_basis, method_used) so callers can report which path ran.
    """
    if fpylll_available():
        from fpylll import BKZ, IntegerMatrix
        m, k = B.shape
        M = IntegerMatrix(k, m)
        for col in range(k):
            for row in range(m):
                M[col, row] = int(B[row, col])
        BKZ.reduction(M, BKZ.Param(block_size=block_size))
        out = np.array([[M[col, row] for col in range(k)] for row in range(m)], dtype=object)
        return to_safe_int_array(out), "fpylll_bkz"
    return lll_reduce(B, delta=delta), "lll_delta_0.99_fallback"


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


class ExactIndependenceTracker:
    """Incrementally tracks linear independence of integer vectors over Q,
    via exact Gaussian elimination modulo one large random prime P — not
    over Q with `fractions.Fraction`, and not via floating-point.

    Why not float: `real_rank`'s SVD (and an earlier float Gram-Schmidt used
    here) both lose precision once vector entries span a huge dynamic range
    — exactly what happens after several chained NewBasisDel calls under a
    non-low-norm R (Finding 2's naive-uniform H1 comparison; entries exceed
    1e17 by period 6-8). That precision loss wrongly rejected genuinely-
    independent candidates, so a from-scratch greedy build came up short of
    a full-rank set even though a valid one (S's own columns) was sitting
    right there in the candidate pool.

    Why not exact fractions.Fraction: correct, but numerator/denominator
    size compounds across eliminations, and for m~72 with huge inputs this
    was ~2x slower than the whole rest of NewBasisDel combined.

    Reducing mod a single large (61-bit) random prime is the standard
    practical middle ground: arithmetic is exact (Python's big-int mod, no
    precision loss) and bounded-size (everything stays < P), and it gives
    the TRUE rank over Q unless P happens to divide a relevant sub-
    determinant of the input — vanishingly unlikely for a randomly chosen
    61-bit P. (Even in that astronomical-odds case, the caller still
    verifies the final delegated basis satisfies A.T=0 mod q explicitly, so
    this is a performance/engineering choice, not a soundness gap.)
    """

    def __init__(self, dim: int, rng: random.Random | None = None) -> None:
        self.dim = dim
        rng = rng or random
        self.P = _large_prime(rng)
        self._pivot_cols: list[int] = []
        self._rows: list[list[int]] = []  # reduced-row-echelon rows, mod P

    def try_add(self, v: np.ndarray) -> bool:
        """Reduce v (mod P) against the current echelon rows. If it's
        independent of them, add it (in reduced form) and return True."""
        P = self.P
        row = [int(x) % P for x in v]
        for pivot_col, erow in zip(self._pivot_cols, self._rows):
            if row[pivot_col] != 0:
                factor = row[pivot_col]
                row = [(r - factor * e) % P for r, e in zip(row, erow)]
        for idx, val in enumerate(row):
            if val != 0:
                inv = pow(val, P - 2, P)
                row = [(r * inv) % P for r in row]
                self._pivot_cols.append(idx)
                self._rows.append(row)
                return True
        return False

    @property
    def count(self) -> int:
        return len(self._rows)


# Four verified 61-bit primes (sympy.isprime-checked) to pick from at random
# per NewBasisDel call, so an unlucky choice for one basis doesn't repeat
# for another.
_LARGE_PRIMES = (
    2**61 - 1,       # Mersenne prime
    2305843009213693967,
    2305843009213693973,
    2305843009213694009,
)


def _large_prime(rng: random.Random) -> int:
    return rng.choice(_LARGE_PRIMES)


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
    """Sample z ~ D_{Z, sigma, center} by rejection sampling over a uniform
    proposal on [center - tail*sigma, center + tail*sigma].

    Acceptance is computed *relative to the nearest integer's density*
    (rho(z)/rho(z_best), which is always <= 1 and exactly 1 at z_best) rather
    than the raw density rho(z). With small sigma (frequent here: some
    Gram-Schmidt vectors of the re-randomized bases run into the hundreds,
    so sigma/||b_i*|| can be << 1), the raw density underflows to exactly
    0.0 for *every* integer in range, including the best one — an unbiased
    but naive rejection sampler then rejects forever. Normalizing by the
    peak density guarantees the best candidate always accepts.
    """
    lo = int(np.floor(center - tail * sigma))
    hi = int(np.ceil(center + tail * sigma))
    if hi <= lo:
        hi = lo + 1
    z_best = min(max(round(center), lo), hi)
    best_sq_dist = (z_best - center) ** 2
    two_sigma_sq = 2 * sigma * sigma
    while True:
        z = rng.randint(lo, hi)
        d = (z - center) ** 2 - best_sq_dist  # >= 0, so p <= 1 (=1 at z_best)
        p = np.exp(-d / two_sigma_sq)
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
        # Clamp both ends: too-small sigma_i just means "round to nearest"
        # (handled by discrete_gaussian_1d's own floor), but a too-small
        # norm_bi_star (a near-degenerate Gram-Schmidt vector, e.g. from an
        # almost-dependent basis candidate slipping through) would blow
        # sigma_i up to where the rejection-sampling range is astronomically
        # wide and effectively never terminates — cap it defensively.
        sigma_i = sigma / norm_bi_star if norm_bi_star > 0 else sigma
        sigma_i = min(max(sigma_i, 1e-6), sigma * 1000)
        zi = discrete_gaussian_1d(ci, sigma_i, rng)
        z[i] = zi
        c = c - zi * basis[:, i].astype(float)
    # dtype=object: z_i * basis[:,i] can overflow int64 when `basis` itself
    # isn't norm-bounded (e.g. Finding 2's naive-uniform H1 comparison) —
    # see the note above `to_safe_int_array`. Downcast at the end if safe.
    v = np.zeros(m, dtype=object)
    basis_obj = basis.astype(object)
    for i in range(k):
        v += int(z[i]) * basis_obj[:, i]
    return to_safe_int_array(v)
