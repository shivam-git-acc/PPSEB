import random

import numpy as np

from ppseb.params import default_params
from ppseb.linalg import centered_mod_q, safe_matmul
from ppseb.hashes import H1, H1_inverse
from ppseb.trapgen import trapgen
from attacks.forward_sec import forward_sec_experiment


def test_forward_sec_experiment_well_formed():
    p = default_params()
    result = forward_sec_experiment(J=3, params=p, seed=2, h1_variant="low_norm")
    assert result["J"] == 3
    assert len(result["rows"]) == 3
    for row in result["rows"]:
        assert row["membership_ok"] is True  # the algebraic identity always holds
        assert row["verdict"] in ("BROKEN (trivial)", "BROKEN (after LLL reduction)", "survives both")
    # verdict must be DERIVED from the numbers, not hard-coded:
    for row in result["rows"]:
        if row["verdict"] == "BROKEN (trivial)":
            assert row["candidate_trivial_gram_schmidt_norm"] < row["usability_threshold"]
        elif row["verdict"] == "BROKEN (after LLL reduction)":
            assert row["candidate_trivial_gram_schmidt_norm"] >= row["usability_threshold"]
            assert row["candidate_after_lll_gram_schmidt_norm"] < row["usability_threshold"]
        elif row["verdict"] == "survives both":
            assert row["candidate_after_lll_gram_schmidt_norm"] >= row["usability_threshold"]
        # LLL re-reduction should never make the candidate WORSE:
        assert row["candidate_after_lll_gram_schmidt_norm"] <= row["candidate_trivial_gram_schmidt_norm"]


def test_forward_sec_naive_uniform_variant_runs():
    p = default_params()
    result = forward_sec_experiment(J=2, params=p, seed=3, h1_variant="naive_uniform")
    assert len(result["rows"]) == 2
    for row in result["rows"]:
        assert row["membership_ok"] is True


def test_forward_sec_naive_uniform_survives_larger_J():
    """Regression test: at J>=~7 the naive-uniform H1 comparison's basis
    entries exceed int64 range (silent overflow used to corrupt the mod-q
    identity) and, separately, used to exceed float64's precision in the
    re-randomization independence test (wrongly rejecting valid candidates).
    Both bugs manifested as a spurious RuntimeError from new_basis_del.
    """
    p = default_params()
    result = forward_sec_experiment(J=10, params=p, seed=1, h1_variant="naive_uniform")
    assert len(result["rows"]) == 10
    for row in result["rows"]:
        assert row["membership_ok"] is True
        assert row["candidate_after_lll_gram_schmidt_norm"] > 0


def test_r_inverse_over_z_matches_incremental_mod_q():
    """Audit: R_j = H1(...) = I + N has det = 1 exactly over Z, so it has a
    genuine integer inverse (H1_inverse, via back-substitution). Chaining
    the MOD-Q REDUCTIONS of those exact inverses one step at a time must
    agree exactly with multiplying the EXACT (unreduced, over-Z) inverses
    together first and reducing the product mod q only once at the end —
    mod-q reduction is a ring homomorphism, so it cannot matter when you
    apply it. This test pins that equivalence down explicitly.
    """
    p = default_params()
    q, m = p.q, p.m
    rng = np.random.default_rng(11)
    pk, _sk = trapgen(p, rng)

    J = 5
    R_invs_exact = []   # object dtype, unreduced (over Z)
    R_invs_modq = []    # int64, reduced mod q at each step
    pk_k = pk
    for j in range(1, J + 1):
        R = H1(pk_k, j, p)
        inv_exact = H1_inverse(R)
        R_invs_exact.append(inv_exact)
        inv_modq = np.array([[int(x) for x in row] for row in (inv_exact % q)], dtype=np.int64)
        R_invs_modq.append(inv_modq)
        pk_k = (pk_k @ inv_modq) % q

    # Method A: reduce mod q at every step of the accumulation (what the
    # experiment actually does).
    suf_a = np.eye(m, dtype=np.int64)
    for k in range(J - 1, -1, -1):
        suf_a = (R_invs_modq[k] @ suf_a) % q

    # Method B: multiply the exact (over-Z) inverses together first, reduce
    # only once at the very end.
    suf_b = np.eye(m, dtype=object)
    for k in range(J - 1, -1, -1):
        suf_b = safe_matmul(R_invs_exact[k], suf_b)
    suf_b_modq = (suf_b.astype(object)) % q

    diff = (suf_a.astype(object) - suf_b_modq) % q
    assert np.all(diff == 0), "R^-1 over Z (reduced once) must match incremental mod-q reduction"

    # And centering should agree too (sanity: centering is representative-
    # choice only, not a separate computation).
    assert np.array_equal(
        centered_mod_q(suf_a, q),
        centered_mod_q(np.array([[int(x) for x in row] for row in suf_b_modq], dtype=np.int64), q),
    )
