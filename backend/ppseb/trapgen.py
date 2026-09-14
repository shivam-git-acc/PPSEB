"""TrapGen: sample a (pk, trapdoor) pair (A, T) with A in Z_q^{n x m}
approximately uniform, and T a short basis of L_perp_q(A) = {x : Ax=0 mod q}.

CLAUDE.md §3.2 explicitly sanctions a "pragmatic, correct-enough" construction
rather than a full gadget trapdoor (Micciancio-Peikert 2012) or Ajtai's
original sampler, in the interest of a readable, auditable implementation at
tiny parameters: build A random, compute an exact basis of the mod-q kernel
lattice via an HNF-style block construction (`linalg.kernel_basis_mod_q`),
then LLL-reduce it.
"""

from __future__ import annotations

import numpy as np

from .linalg import find_full_rank_partition, gram_schmidt_norm, kernel_basis_mod_q, lll_reduce
from .params import Params
from .trace import Trace


def trapgen(params: Params, rng: np.random.Generator, trace: Trace | None = None) -> tuple[np.ndarray, np.ndarray]:
    """Returns (A, T): A is n x m over Z_q, T is an m x m short basis of
    L_perp_q(A). If `trace` is given, appends explanatory events to it."""
    n, m, q = params.n, params.m, params.q

    partition = None
    A = None
    for attempt in range(1, 51):
        candidate = rng.integers(0, q, size=(n, m))
        try:
            partition = find_full_rank_partition(candidate, q)
            A = candidate
            break
        except ValueError:
            continue
    if A is None:
        raise RuntimeError(f"TrapGen: could not sample a full-row-rank A mod q={q} in 50 tries")

    if trace is not None:
        trace.matrix(
            "Sampled A (public key)", A, name="A",
            detail=f"A uniform in Z_q^{{{n}x{m}}}; needed {attempt} draw(s) to get full row rank mod q={q}.",
            algo="TrapGen",
        )

    T_raw = kernel_basis_mod_q(A, q, partition)
    raw_norm = gram_schmidt_norm(T_raw)
    if trace is not None:
        trace.compute(
            "Built raw kernel basis of L_perp_q(A)",
            detail=(
                "Partitioned A's columns into an invertible n x n block A1 and the rest A2. "
                "Basis = [q*e_j for A1-columns] U [(-A1^-1 A2[:,k], e_k) for A2-columns]; "
                "this is a genuine basis (determinant = q^n), but its vectors are long (entries ~ q)."
            ),
            data={"gram_schmidt_norm_raw": raw_norm, "expected_det": q ** n},
            algo="TrapGen",
        )

    T = lll_reduce(T_raw)
    reduced_norm = gram_schmidt_norm(T)
    ok = bool(np.all((A @ T) % q == 0))

    if trace is not None:
        trace.norm(
            "LLL-reduced the kernel basis",
            detail="Shortens the raw basis into a usable trapdoor without changing the lattice it spans.",
            data={
                "gram_schmidt_norm_raw": raw_norm,
                "gram_schmidt_norm_reduced": reduced_norm,
                "shrink_factor": (raw_norm / reduced_norm) if reduced_norm else None,
            },
            algo="TrapGen",
        )
        trace.decision(
            "Verified A . T = 0 (mod q)",
            verdict="valid trapdoor" if ok else "INVALID",
            evidence={"all_columns_zero_mod_q": ok, "gram_schmidt_norm": reduced_norm},
            algo="TrapGen",
        )

    if not ok:
        raise RuntimeError("TrapGen: A . T != 0 (mod q); this should never happen")

    return A, T
