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
