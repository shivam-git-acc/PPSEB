import inspect
import random

import numpy as np

from ppseb.params import Params, default_params
from ppseb.linalg import centered_mod_q, gram_schmidt_norm, lll_reduce, safe_matmul, strong_reduce
from ppseb.hashes import H1, H1_inverse
from ppseb.trapgen import trapgen
from attacks.forward_sec import (
    forward_sec_experiment, usability_threshold, _verdict_for_period, _recover_candidate,
    scaling_sweep, sigma_for_params,
)


def test_threshold_matches_formula():
    """PATCH 02 §A.6: usability_threshold(default) must equal min(sampling,
    decode) exactly, and the LITERAL textbook comparison values it reports
    (C=1, decode noise=sigma) must match the patch's own hand-derivation
    (~1.9) so that number can't silently drift even though we deliberately
    use different (documented) constants for the actual threshold."""
    p = default_params()
    info = usability_threshold(p)
    assert abs(info["threshold"] - min(info["sampling_cap"], info["decode_cap"])) < 1e-9
    assert abs(info["threshold_C1_sigma_naive"] - 1.9) < 0.1


def test_threshold_single_source():
    """The threshold value used by the per-row chart payload, the verdict
    logic, and the returned threshold_info must be byte-identical — there
    must be exactly one source of truth (PATCH 02 §A.2/§A.6)."""
    p = default_params()
    result = forward_sec_experiment(J=3, params=p, seed=4, h1_variant="low_norm")
    thr = result["threshold_info"]["threshold"]
    assert result["summary"]["threshold"] == thr
    for row in result["rows"]:
        assert row["usability_threshold"] == thr


def test_verdict_uses_threshold():
    """A candidate just under threshold is broken; just over, it survives —
    exercised directly against the verdict function (PATCH 02 §A.6)."""
    p = default_params()
    thr = usability_threshold(p)["threshold"]
    broken = _verdict_for_period(legit_usable=True, in_lattice=True, trivial_gs=thr * 5, lll_gs=thr * 0.99, threshold=thr)
    assert broken == "BROKEN (after LLL reduction)"
    survives = _verdict_for_period(legit_usable=True, in_lattice=True, trivial_gs=thr * 5, lll_gs=thr * 1.01, threshold=thr)
    assert survives == "survives (trivial + LLL) at these params"


def test_scaling_sweep_runs():
    """PATCH 02 §B.5 (updated by PATCH 03 Lever 1: sigma is now dimension-
    aware, not the base params' fixed sigma): the sweep returns one row per
    n with well-formed fields, and the SAME threshold FORMULA (not a second
    copy) is used at every n, evaluated at that row's own (dynamic) sigma."""
    p = default_params()
    result = scaling_sweep(J=3, base_params=p, n_values=(4, 6), seed=1, time_budget_s=120)
    measured = [r for r in result["rows"] if "error" not in r and not r.get("skipped")]
    assert len(measured) == 2
    for row in measured:
        p_n = Params(n=row["n"], q=p.q, sigma=row["sigma"], l=p.l, usability_C=p.usability_C, m=0)
        assert row["threshold"] == usability_threshold(p_n)["threshold"]
        assert row["num_broken"] == len(row["broken"])
        assert "runtime_s" in row
    assert result["trend"] in ("shrinking", "flat_or_growing", "mixed", "inconclusive", "never_broken")


def test_threshold_explicit():
    """usability_threshold must return both caps and name the binding one,
    never just an unexplained q/4 (PATCH 01 §2)."""
    p = default_params()
    info = usability_threshold(p)
    assert info["binding_bound"] in ("sampling", "decode")
    assert info["threshold"] == min(info["sampling_cap"], info["decode_cap"])
    assert info["threshold"] > 0


def test_lownorm_chain_stays_usable():
    """With low_norm H1, the legitimate chain's own basis should stay
    usable for every period at these demo parameters — correctness holds
    (PATCH 01 §1)."""
    p = default_params()
    result = forward_sec_experiment(J=5, params=p, seed=1, h1_variant="low_norm")
    assert result["correctness_lost_at"] is None
    for row in result["rows"]:
        assert row["legit_usable"] is True


def test_naive_uniform_correctness_collapse():
    """With naive_uniform H1, the legitimate chain should lose usability
    within a handful of periods — KeyExt itself diverges (PATCH 01 §1)."""
    p = default_params()
    result = forward_sec_experiment(J=5, params=p, seed=5, h1_variant="naive_uniform")
    assert result["correctness_lost_at"] is not None
    assert result["correctness_lost_at"] <= 4
    assert result["headline"].startswith("Correctness collapse")
    # every row from correctness_lost_at onward must be gated as such:
    for row in result["rows"]:
        if row["period"] >= result["correctness_lost_at"]:
            assert row["verdict"] == "correctness lost (legit basis unusable)"


def test_verdict_gated_on_legit():
    """A row with legit_usable=False must report 'correctness lost',
    regardless of how short the candidate norms are."""
    verdict = _verdict_for_period(
        legit_usable=False, in_lattice=True, trivial_gs=0.01, lll_gs=0.01, threshold=100.0,
    )
    assert verdict == "correctness lost (legit basis unusable)"

    verdict_bug = _verdict_for_period(
        legit_usable=True, in_lattice=False, trivial_gs=0.01, lll_gs=0.01, threshold=100.0,
    )
    assert verdict_bug.startswith("candidate not in lattice")


def test_lll_stays_in_lattice():
    """Every LLL-reduced candidate must still satisfy pk_i . cand = 0 (mod q)."""
    p = default_params()
    result = forward_sec_experiment(J=3, params=p, seed=2, h1_variant="low_norm")
    for row in result["rows"]:
        assert row["membership_ok"] is True


def test_balanced_norm_smaller():
    """Guards against the earlier inflation artifact: for a random integer
    matrix, the balanced (-q/2, q/2] representative's Gram-Schmidt norm must
    never exceed the raw [0, q) representative's."""
    q = 257
    rng = np.random.default_rng(0)
    raw = rng.integers(0, q, size=(20, 20))
    balanced = centered_mod_q(raw, q)
    assert gram_schmidt_norm(balanced) <= gram_schmidt_norm(raw)


def test_forward_sec_experiment_well_formed():
    p = default_params()
    result = forward_sec_experiment(J=3, params=p, seed=2, h1_variant="low_norm")
    assert result["J"] == 3
    assert len(result["rows"]) == 3
    for row in result["rows"]:
        assert row["verdict"] in (
            "BROKEN (trivial transform)", "BROKEN (after LLL reduction)",
            "survives (trivial + LLL) at these params", "correctness lost (legit basis unusable)",
        )
        # LLL re-reduction should never make the candidate WORSE:
        assert row["candidate_after_lll_gram_schmidt_norm"] <= row["candidate_trivial_gram_schmidt_norm"]


def test_forward_sec_naive_uniform_variant_runs():
    p = default_params()
    result = forward_sec_experiment(J=2, params=p, seed=3, h1_variant="naive_uniform")
    assert len(result["rows"]) == 2


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


def test_sigma_scaling_keeps_legit_usable():
    """PATCH 03 §5: with dimension-aware sigma (+ strengthened reduction),
    the legitimate chain stays usable — correctness_lost_at is None — at
    every tested n, resolving the scaling-sweep confound."""
    p = default_params()
    result = scaling_sweep(J=3, base_params=p, n_values=(4, 6), seed=1, time_budget_s=120)
    measured = [r for r in result["rows"] if "error" not in r and not r.get("skipped")]
    assert len(measured) == 2
    for row in measured:
        assert row["correctness_lost_at"] is None
    assert result["confound_resolved"] is True
    assert result["confound_note"] is None


def test_legit_reduction_helps():
    """strong_reduce must never leave a basis LONGER than plain LLL(0.75)
    produced it, on the same starting basis."""
    p = default_params()
    rng = np.random.default_rng(2)
    _pk, sk = trapgen(p, rng)  # trapgen already LLL(delta=0.75)-reduces internally
    plain_norm = gram_schmidt_norm(sk)
    strong, method = strong_reduce(sk)
    assert method in ("fpylll_bkz", "lll_delta_0.99_fallback")
    assert gram_schmidt_norm(strong) <= plain_norm + 1e-9


def test_attacker_and_legit_reductions_separate():
    """The attacker's recovery (_recover_candidate) must never call
    strong_reduce — the legit-basis strengthening (PATCH 03 Lever 2) and the
    attacker's own LLL are structurally separate code paths, not shared
    state that could accidentally let one leak into the other."""
    source = inspect.getsource(_recover_candidate)
    assert "strong_reduce" not in source
    assert "lll_reduce" in source


def test_sweep_reports_legit_gs_per_n():
    """Sweep rows must carry sigma and legit-basis norms (PATCH 03 §3), and
    a period gated out by correctness_lost_at must never appear in `broken`
    — a contaminated 0 (nothing left to break) can never silently read as
    'unbroken'."""
    p = default_params()
    result = scaling_sweep(J=3, base_params=p, n_values=(4,), seed=1, time_budget_s=60)
    row = result["rows"][0]
    assert "sigma" in row and row["sigma"] > 0
    assert "root_legit_gs" in row and "max_legit_gs" in row
    if row["correctness_lost_at"] is not None:
        broken_periods = {b["period"] for b in row["broken"]}
        assert all(period < row["correctness_lost_at"] for period in broken_periods)
