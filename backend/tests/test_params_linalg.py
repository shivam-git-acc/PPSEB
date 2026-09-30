import numpy as np
import pytest

from ppseb.params import Params, default_params, derived_m, is_prime
from ppseb.linalg import (
    find_full_rank_partition,
    kernel_basis_mod_q,
    lll_reduce,
    gram_schmidt_norm,
    particular_solution,
    rank_mod_q,
)


def test_is_prime():
    assert is_prime(257)
    assert not is_prime(256)
    assert not is_prime(1)


def test_default_params_valid():
    p = default_params()
    assert p.validate() == []
    assert p.m == derived_m(p.n, p.q)


def test_params_rejects_nonprime_q():
    p = Params(n=4, q=256, sigma=4.0, l=10, m=derived_m(4, 256))
    problems = p.validate()
    assert any("prime" in msg for msg in problems)


def test_params_rejects_small_m():
    p = Params(n=4, q=257, sigma=4.0, l=10, m=4)
    problems = p.validate()
    assert any("too small" in msg for msg in problems)


def _random_full_rank_A(n, m, q, seed=0):
    rng = np.random.default_rng(seed)
    for _ in range(50):
        A = rng.integers(0, q, size=(n, m))
        try:
            find_full_rank_partition(A, q)
            return A
        except ValueError:
            continue
    raise RuntimeError("could not find full rank A")


def test_kernel_basis_and_particular_solution():
    p = default_params()
    A = _random_full_rank_A(p.n, p.m, p.q)
    partition = find_full_rank_partition(A, p.q)
    T = kernel_basis_mod_q(A, p.q, partition)
    assert T.shape == (p.m, p.m)
    assert np.all((A @ T) % p.q == 0)
    # determinant of the kernel basis must be +/- q^n
    det = round(np.linalg.det(T.astype(float)))
    assert abs(det) == p.q ** p.n

    v = np.random.default_rng(1).integers(0, p.q, size=p.n)
    t0 = particular_solution(A, v, p.q, partition)
    assert np.all((A @ t0) % p.q == v % p.q)


def test_lll_reduces_norm():
    p = default_params()
    A = _random_full_rank_A(p.n, p.m, p.q)
    T = kernel_basis_mod_q(A, p.q)
    raw_norm = gram_schmidt_norm(T)
    T_reduced = lll_reduce(T)
    assert np.all((A @ T_reduced) % p.q == 0)
    reduced_norm = gram_schmidt_norm(T_reduced)
    assert reduced_norm <= raw_norm


def test_rank_mod_q():
    q = 257
    I = np.eye(5, dtype=np.int64)
    assert rank_mod_q(I, q) == 5
    Z = np.zeros((5, 5), dtype=np.int64)
    assert rank_mod_q(Z, q) == 0


# --- the sublattice repair (audit, 2026-09-30) ---------------------------

def test_q_ary_generators_span_a_sublattice_without_qI():
    """The defect this repairs, stated as a test: vectors can all LIE in a
    q-ary lattice without GENERATING it.

    Here the sparse generating set is built by scaling part of a real basis,
    which keeps every column in the lattice (integer combinations of basis
    vectors) while multiplying the index by q^6. The live attack reaches the
    same place by a different route -- its R-product inverse is taken mod q, so
    the integer matrix it multiplies the stolen basis by has a large
    determinant (measured index ~q^28 at n=4, m=72). Either way membership
    cannot detect it and the index can.
    """
    import numpy as np
    from ppseb.linalg import (kernel_basis_mod_q, mat_mod_mixed, q_ary_basis_from_generators,
                              q_ary_index_log, safe_matmul)

    q, n, m = 257, 4, 24
    rng = np.random.default_rng(7)
    A = rng.integers(0, q, size=(n, m)).astype(np.int64)
    basis = kernel_basis_mod_q(A, q)
    assert q_ary_index_log(basis, q, n) == pytest.approx(0.0, abs=1e-6)

    # Scale the columns that are already q*e_j: the index gains a factor q^n
    # while the generators still span ker(A) over Z_q, which is the repair's
    # stated precondition and the situation the live attack is in.
    T = np.eye(m, dtype=np.int64)
    for j in range(n):
        T[j, j] = q
    generators = safe_matmul(basis, T)

    # Every column is in the lattice -- membership cannot catch this.
    assert np.all(mat_mod_mixed(A, generators, q) == 0)
    # But they do not generate it.
    assert q_ary_index_log(generators, q, n) == pytest.approx(float(n), abs=1e-6)

    repaired = q_ary_basis_from_generators(generators, q)
    assert np.all(mat_mod_mixed(A, repaired, q) == 0)
    assert q_ary_index_log(repaired, q, n) == pytest.approx(0.0, abs=1e-6)


def test_q_ary_basis_from_generators_matches_the_public_lattice():
    """The repaired basis spans the SAME lattice as the public kernel basis --
    which is the point: those q*e_j vectors are free to anyone with pk."""
    import numpy as np
    from ppseb.linalg import (gram_schmidt_norm, kernel_basis_mod_q, lll_reduce,
                              q_ary_basis_from_generators, q_ary_index_log)

    q, n, m = 257, 4, 24
    rng = np.random.default_rng(11)
    A = rng.integers(0, q, size=(n, m)).astype(np.int64)
    pub = kernel_basis_mod_q(A, q)
    repaired = q_ary_basis_from_generators(pub, q)
    assert q_ary_index_log(repaired, q, n) == pytest.approx(0.0, abs=1e-6)
    # Same lattice, so reduction reaches a comparable quality from either.
    assert gram_schmidt_norm(lll_reduce(repaired)) == pytest.approx(
        gram_schmidt_norm(lll_reduce(pub)), rel=0.5)
