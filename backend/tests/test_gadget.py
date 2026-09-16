"""PATCH 10 §6 — MP12 gadget trapdoor and the honest-correctness gate.

MP12 is NOT the production TrapGen on master: the patch's gate fails at n=8
and the wiring regresses the default KeyExt/KGA path (see branch
patch-10-mp12-wiring). These tests exercise the MP12 primitives directly.

Deviations from the patch's test list, each because the literal test could
not fail:
- `test_honest_word_approval_100` (PATCH 09 honest self-approval): honest vs
  honest is ratio 1.0 by definition. Replaced by the absolute check §4 #3 asks
  for -- honest period AND word basis under the usability threshold.
- `test_any_n_runs`: MP12 itself works for any n, but H2 (unchanged by PATCH
  10) still needs every prime factor of n to divide q-1. So n=6 still fails at
  q=257; the test pins down exactly where, instead of asserting a false pass.
"""

import math
import random

import numpy as np
import pytest

from ppseb.gadget import (
    binary_decompose, gadget_basis_k, gadget_matrix, gadget_sample, gadget_vector,
    mp12_parameters, mp12_sample_pre, mp12_trapgen,
)
from ppseb.hashes import H1, H1_inverse, H2
from ppseb.linalg import centered_mod_q, gram_schmidt_norm, strong_reduce
from ppseb.params import Params
from ppseb.samplers import new_basis_del
from ppseb.scheme import decrypt_record, encrypt_record, peks_encrypt, trapdoor, verify
from attacks.end_to_end import END_TO_END_L, TARGET_MARGIN_STD, _basis_chain_norms
from attacks.forward_sec import sigma_for_params, usability_threshold

Q = 257


def _params(n):
    return Params(n=n, q=Q, sigma=4.0, l=10, m=0)


def test_gadget_basis_is_a_short_basis_of_gadget_kernel():
    S_k = gadget_basis_k(Q)
    assert np.all((gadget_vector(Q) @ S_k) % Q == 0)
    assert round(abs(np.linalg.det(S_k))) == Q
    assert gram_schmidt_norm(S_k.astype(float)) <= math.sqrt(5) + 1e-9


def test_binary_decompose_inverts_gadget():
    rng = np.random.default_rng(0)
    v = rng.integers(0, Q, size=6)
    assert np.all((gadget_matrix(6, Q) @ binary_decompose(v, Q)) % Q == v)


@pytest.mark.parametrize("n", [4, 6, 8])
def test_gadget_relation(n):
    """A [R; I] = G (mod q), and S_A is a short basis of L_perp_q(A) -- for any n."""
    p = _params(n)
    A, R, S_A = mp12_trapgen(p, np.random.default_rng(n))
    nk = R.shape[1]
    assert np.all((A @ np.vstack([R, np.eye(nk, dtype=np.int64)])) % Q == gadget_matrix(n, Q) % Q)
    assert np.all((A @ S_A) % Q == 0)


def test_mp12_basis_determinant():
    p = _params(4)
    _A, _R, S_A = mp12_trapgen(p, np.random.default_rng(3))
    from sympy import Matrix
    assert abs(int(Matrix(S_A.tolist()).det())) == Q ** p.n


def test_gadget_sample_solves_gadget_equation():
    rng = random.Random(1)
    v = np.random.default_rng(1).integers(0, Q, size=4)
    z = gadget_sample(v, Q, alpha=9.0, rng=rng)
    assert np.all((gadget_matrix(4, Q) @ z) % Q == v)


@pytest.mark.parametrize("n", [4, 8])
def test_samplepre_correct_and_short(n):
    p = _params(n)
    np_rng = np.random.default_rng(10 + n)
    A, R, _S_A = mp12_trapgen(p, np_rng)
    bound = mp12_parameters(p, R)["preimage_norm_bound"]
    pyr = random.Random(n)
    for _ in range(5):
        u = np_rng.integers(0, Q, size=n)
        x = mp12_sample_pre(A, R, u, p, pyr)
        assert np.all((A @ x) % Q == u)
        assert np.linalg.norm(x.astype(float)) <= bound


def test_any_n_limited_by_h2_not_trapgen():
    """MP12 runs at n=6; the remaining power-of-2 limit is H2's twisted binomial."""
    p = _params(6)
    mp12_trapgen(p, np.random.default_rng(6))  # does not raise
    with pytest.raises(RuntimeError, match="irreducible"):
        H2("flu", 0, p)


def _honest_chain(n, J, seed):
    """The honest doctor's chain as the end-to-end experiment builds it, with an
    MP12 root: sigma from the raw root norm, BKZ-strengthened key, calibrated noise.
    Passes at n=4; the same check fails at n=8 (word basis 1.2-2.3x over)."""
    p = _params(n)
    rng, pyrng = np.random.default_rng(seed), random.Random(seed)
    pk, _R, sk = mp12_trapgen(p, rng)
    p.sigma = sigma_for_params(sk, p)
    sk, _ = strong_reduce(sk)
    mu = rng.integers(0, Q, size=n).astype(np.int64)
    u = rng.integers(0, Q, size=n).astype(np.int64)
    p.l = END_TO_END_L
    calib = trapdoor(pk, sk, "__calib__", 0, mu, p, pyrng)
    p.ciphertext_noise_sigma = TARGET_MARGIN_STD / float(np.linalg.norm(calib.astype(float)))
    threshold = usability_threshold(p)["threshold"]

    kws = ("flu", "asthma", "diabetes", "gout")
    periods = []
    for j in range(J):
        cts = [peks_encrypt(pk, w, j, mu, p, rng, pyrng) for w in kws]
        msg = f"record at period {j}".encode()
        cm = encrypt_record(pk, msg, u, p, rng, pyrng)
        trap = trapdoor(pk, sk, kws[0], j, mu, p, pyrng)
        matches = [verify(c["CT1"], c["CT2"], trap, p)[0] for c in cts]
        norms = _basis_chain_norms(pk, sk, kws[0], j, mu, p, pyrng)
        periods.append({
            "period": j, "matches": matches,
            "decrypt_ok": decrypt_record(pk, sk, cm, u, p, pyrng) == msg,
            "period_gs": norms["period_gs"], "word_gs": norms["word_gs"], "threshold": threshold,
        })
        R = H1(pk, j + 1, p)
        R_inv = np.array([[int(x) for x in row] for row in (H1_inverse(R) % Q)], dtype=np.int64)
        sk, _ = strong_reduce(new_basis_del(pk, R, sk, p.sigma, Q, pyrng, R_inv=R_inv))
        pk = (pk @ R_inv) % Q
    return periods


@pytest.fixture(scope="module")
def honest_chain_n4():
    return _honest_chain(4, 6, seed=11)


def test_end_to_end_search_correct(honest_chain_n4):
    """Matching keyword verifies, non-matching don't, and the record decrypts -- every period."""
    for rec in honest_chain_n4:
        assert rec["matches"][0], f"period {rec['period']}: honest search missed its own keyword"
        assert not any(rec["matches"][1:]), f"period {rec['period']}: non-matching keyword verified"
        assert rec["decrypt_ok"], f"period {rec['period']}: honest decryption failed"


def test_honest_usable_all_periods(honest_chain_n4):
    """PATCH 10 §4 #3, the regression test for the whole bug: the honest period
    AND word basis are both under the usability threshold at every period."""
    for rec in honest_chain_n4:
        assert rec["period_gs"] < rec["threshold"], rec
        assert rec["word_gs"] < rec["threshold"], rec
