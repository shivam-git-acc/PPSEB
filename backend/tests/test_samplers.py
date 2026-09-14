import random

import numpy as np

from ppseb.params import default_params
from ppseb.trapgen import trapgen
from ppseb.hashes import H1
from ppseb.samplers import sample_pre, new_basis_del
from ppseb.trace import Trace


def test_sample_pre_finds_short_preimage():
    p = default_params()
    rng = np.random.default_rng(10)
    A, T = trapgen(p, rng)
    v = rng.integers(0, p.q, size=p.n)
    pyrand = random.Random(10)
    trace = Trace()
    w = sample_pre(A, T, v, p.sigma, p.q, pyrand, trace)
    assert np.all((A @ w) % p.q == v % p.q)
    assert any(e["type"] == "decision" for e in trace.events)


def test_new_basis_del_produces_valid_short_basis():
    p = default_params()
    rng = np.random.default_rng(11)
    A, T = trapgen(p, rng)
    R = H1(rng.integers(0, p.q, size=(p.n, p.m)), 1, p)
    pyrand = random.Random(11)
    trace = Trace()
    T_new = new_basis_del(A, R, T, p.sigma, p.q, pyrand, trace)
    from ppseb.linalg import mat_inv_mod
    A_R = (A @ mat_inv_mod(R, p.q)) % p.q
    assert np.all((A_R @ T_new) % p.q == 0)
    assert any(e["type"] == "decision" for e in trace.events)
