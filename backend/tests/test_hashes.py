import numpy as np

from ppseb.params import default_params
from ppseb.hashes import H1, H1_inverse, H2, H2_inverse
from ppseb.linalg import mat_inv_mod


def test_h1_invertible_and_low_norm():
    p = default_params()
    rng = np.random.default_rng(3)
    pk = rng.integers(0, p.q, size=(p.n, p.m))
    R = H1(pk, 1, p)
    assert R.shape == (p.m, p.m)
    # unit upper triangular -> det exactly 1
    assert round(np.linalg.det(R.astype(float))) == 1
    max_entry = np.max(np.abs(R - np.eye(p.m, dtype=np.int64)))
    assert max_entry <= 1  # low norm: strictly {-1,0,1} off-diagonal


def test_h1_inverse_correct():
    p = default_params()
    rng = np.random.default_rng(4)
    pk = rng.integers(0, p.q, size=(p.n, p.m))
    R = H1(pk, 2, p)
    Rinv = H1_inverse(R)
    prod = R.astype(object) @ Rinv.astype(object)
    assert np.all(prod == np.eye(p.m, dtype=object))
    # mod-q reduction of the exact inverse should match sympy's mod-q inverse
    Rinv_mod = mat_inv_mod(R, p.q)
    assert np.all((Rinv % p.q) == Rinv_mod)


def test_h1_deterministic_in_pk_and_j():
    p = default_params()
    rng = np.random.default_rng(5)
    pk = rng.integers(0, p.q, size=(p.n, p.m))
    R1 = H1(pk, 7, p)
    R2 = H1(pk, 7, p)
    R3 = H1(pk, 8, p)
    assert np.all(R1 == R2)
    assert not np.all(R1 == R3)


def test_h2_frd_difference_invertible():
    p = default_params()
    for w, wp in [("diabetes", "hypertension"), ("asthma", "flu"), ("a", "b")]:
        b1 = H2(w, 1, p)
        b2 = H2(wp, 1, p)
        diff = (b1 - b2) % p.q
        # invertible mod q iff sympy can invert it without raising
        inv = H2_inverse(diff, p.q)
        prod = (diff @ inv) % p.q
        assert np.all(prod == np.eye(p.m, dtype=np.int64))


def test_h2_deterministic_and_sensitive_to_period():
    p = default_params()
    b1 = H2("diabetes", 1, p)
    b2 = H2("diabetes", 1, p)
    b3 = H2("diabetes", 2, p)
    assert np.all(b1 == b2)
    assert not np.all(b1 == b3)
