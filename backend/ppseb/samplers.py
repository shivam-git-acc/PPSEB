"""SampleGaussian, SamplePre, NewBasisDel — the trapdoor-sampling primitives
(CLAUDE.md §3.9) that KeyExt, Trapdoor and TrapGen's demo build on.

Every sampler reports the Gram-Schmidt norm of what it produced, because
Finding 2 (forward-security norm experiment) is entirely a question about
how these norms grow across a chain of NewBasisDel calls.
"""

from __future__ import annotations

import random

import numpy as np

from .linalg import (
    ExactIndependenceTracker,
    find_full_rank_partition,
    gram_schmidt,
    gram_schmidt_norm,
    klein_sample,
    lll_reduce,
    mat_inv_mod,
    mat_mod_mixed,
    particular_solution,
    to_safe_int_array,
)
from .trace import Trace


def sample_gaussian(
    basis: np.ndarray, center: np.ndarray, sigma: float, rng: random.Random,
    trace: Trace | None = None, algo: str = "SampleGaussian",
) -> np.ndarray:
    """Discrete Gaussian sample over the lattice spanned by `basis`, centered
    at `center`, width `sigma`. Thin, traced wrapper over Klein's algorithm."""
    v = klein_sample(basis, center, sigma, rng)
    if trace is not None:
        trace.norm(
            "Sampled a discrete Gaussian lattice point",
            detail=f"Klein/GPV sampler, sigma={sigma}, centered at the given vector.",
            data={"sample_norm": float(np.linalg.norm(v.astype(float)))},
            algo=algo,
        )
    return v


def sample_pre(
    A: np.ndarray, T_A: np.ndarray, v: np.ndarray, sigma: float, q: int,
    rng: random.Random, trace: Trace | None = None,
) -> np.ndarray:
    """SamplePre(A, T_A, v, sigma): a short w with A @ w = v (mod q), using
    trapdoor T_A. Standard GPV technique: find *any* solution t0 (via a
    pseudo-inverse over an invertible sub-block of A), then correct it by a
    discrete-Gaussian lattice point centered at -t0 — the result, t0+perturb,
    is a short vector because the perturbation cancels most of t0.
    """
    partition = find_full_rank_partition(A, q)
    t0 = particular_solution(A, v, q, partition)
    perturb = klein_sample(T_A, -t0.astype(float), sigma, rng)
    w = to_safe_int_array(t0.astype(object) + perturb.astype(object))
    ok = bool(np.all(mat_mod_mixed(A, w, q) == v % q))
    if trace is not None:
        trace.compute(
            "SamplePre: found a particular solution t0",
            detail="A pseudo-inverse over an invertible n x n block of A gives t0 with A.t0 = v (mod q), but t0 is not short.",
            data={"t0_norm": float(np.linalg.norm(t0.astype(float)))},
            algo="SamplePre",
        )
        trace.norm(
            "SamplePre: Gaussian-corrected t0 into a short preimage",
            detail="Sampled a lattice point near -t0 using trapdoor T_A (Klein's algorithm); w = t0 + that sample.",
            data={
                "w_norm": float(np.linalg.norm(w.astype(float))),
                "sigma": sigma,
            },
            algo="SamplePre",
        )
        trace.decision(
            "Verified A . w = v (mod q)",
            verdict="valid preimage" if ok else "INVALID",
            evidence={"matches_target": ok, "w_norm": float(np.linalg.norm(w.astype(float)))},
            algo="SamplePre",
        )
    if not ok:
        raise RuntimeError("SamplePre: A.w != v (mod q); this should never happen")
    return w


def new_basis_del(
    A: np.ndarray, R: np.ndarray, T_A: np.ndarray, sigma: float, q: int,
    rng: random.Random, trace: Trace | None = None, resample_factor: int = 2,
    R_inv: np.ndarray | None = None,
) -> np.ndarray:
    """NewBasisDel(A, R, T_A, sigma): a short basis of L_perp_q(A . R^-1),
    derived from T_A, without simply handing out R @ T_A verbatim (which
    would leak T_A's structure through R).

    Faithful-but-simplified ABB approach (CLAUDE.md §3.9 explicitly allows
    this trade-off at small parameters):
      1. S = R @ T_A is *some* basis of the target lattice (exact integer
         identity: (A R^-1)(R T_A) = A T_A = 0 mod q).
      2. Re-randomize: draw fresh discrete-Gaussian lattice points against S,
         greedily swap them in for the shortest independent generating set
         (a simplified RandBasis), so the output basis's shape doesn't just
         mirror T_A scaled by R.
      3. LLL-polish the result into the final short basis T'.
    """
    m = A.shape[1]
    if R_inv is None:
        R_inv = mat_inv_mod(R, q)  # generic fallback (slow for m~70; callers
                                    # that know R = H1(...) should pass the
                                    # fast H1_inverse(R) % q instead)
    # R_inv is always mod-q reduced (bounded in [0, q)) by every caller, but
    # its dtype may still be `object` if it came from H1_inverse's exact
    # (possibly huge, pre-reduction) computation — normalize to int64 now
    # that the values themselves are small, so the matmul below isn't a
    # mixed-dtype one.
    R_inv = np.array([[int(x) for x in row] for row in R_inv], dtype=np.int64)
    A_R = (A @ R_inv) % q

    S = (R.astype(object) @ T_A.astype(object))
    S_safe = to_safe_int_array(S)
    s_ok = bool(np.all(mat_mod_mixed(A_R, S_safe, q) == 0))
    s_norm = gram_schmidt_norm(S_safe)

    if trace is not None:
        trace.compute(
            "NewBasisDel: transformed the basis (S = R . T_A)",
            detail="Exact identity: (A.R^-1) . (R.T_A) = A.T_A = 0 (mod q), so S is a valid basis of L_perp_q(A.R^-1) — but it directly mirrors T_A scaled by R.",
            data={"S_valid": s_ok, "S_gram_schmidt_norm": s_norm},
            algo="NewBasisDel",
        )

    Bstar_S, _mu = gram_schmidt(S_safe)
    zero_center = np.zeros(m)
    candidates: list[np.ndarray] = [S_safe[:, i] for i in range(m)]
    candidates += [
        klein_sample(S_safe, zero_center, sigma, rng, Bstar=Bstar_S)
        for _ in range(resample_factor * m)
    ]
    candidates.sort(key=lambda v: float(np.dot(v.astype(float), v.astype(float))))

    # Greedily keep the shortest candidates that are linearly independent
    # (over Q — a basis of L_perp_q(A) always has det +/- q^n, so rank *mod q*
    # is the wrong test here; see linalg.real_rank). Independence is tested
    # via exact modular Gaussian elimination over one large random prime
    # (see ExactIndependenceTracker) rather than a floating-point
    # Gram-Schmidt: S's own columns are guaranteed independent by
    # construction (S = R.T_A for invertible R, full-rank T_A), but a
    # float-based test can lose enough precision on huge, wildly-scaled
    # entries (Finding 2's naive-uniform H1 comparison; entries exceed 1e17
    # by period ~7) to wrongly reject some of them — leaving the greedy
    # build short of m vectors even though a valid set was in the pool all
    # along.
    tracker = ExactIndependenceTracker(m, rng)
    chosen: list[np.ndarray] = []
    for v in candidates:
        if tracker.try_add(v):
            chosen.append(v)
        if len(chosen) == m:
            break
    if len(chosen) < m:
        # Should not happen (S alone is already full rank); fail loudly.
        raise RuntimeError("NewBasisDel: re-randomization failed to reach full rank")

    T_raw = to_safe_int_array(np.array([np.asarray(v, dtype=object) for v in chosen], dtype=object).T)
    T_new = lll_reduce(T_raw)
    ok = bool(np.all(mat_mod_mixed(A_R, T_new, q) == 0))
    new_norm = gram_schmidt_norm(T_new)

    if trace is not None:
        trace.norm(
            "NewBasisDel: re-randomized and LLL-polished the delegated basis",
            detail=f"Drew {resample_factor * m} fresh Gaussian lattice points against S, "
                   "greedily kept the shortest linearly-independent set, then LLL-reduced it.",
            data={
                "S_gram_schmidt_norm": s_norm,
                "T_new_gram_schmidt_norm": new_norm,
            },
            algo="NewBasisDel",
        )
        trace.decision(
            "Verified (A.R^-1) . T_new = 0 (mod q)",
            verdict="valid delegated basis" if ok else "INVALID",
            evidence={"all_columns_zero_mod_q": ok, "gram_schmidt_norm": new_norm},
            algo="NewBasisDel",
        )

    if not ok:
        raise RuntimeError("NewBasisDel: (A.R^-1).T_new != 0 (mod q); this should never happen")
    return T_new
