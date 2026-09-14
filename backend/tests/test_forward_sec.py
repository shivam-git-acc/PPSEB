from ppseb.params import default_params
from attacks.forward_sec import forward_sec_experiment


def test_forward_sec_experiment_well_formed():
    p = default_params()
    result = forward_sec_experiment(J=3, params=p, seed=2, h1_variant="low_norm")
    assert result["J"] == 3
    assert len(result["rows"]) == 3
    for row in result["rows"]:
        assert row["membership_ok"] is True  # the algebraic identity always holds
        assert row["verdict"] in ("BROKEN", "BROKEN (weak)", "survives trivial attack")
    # verdict must be DERIVED from the numbers, not hard-coded:
    for row in result["rows"]:
        if row["verdict"] == "BROKEN":
            assert row["candidate_gram_schmidt_norm"] <= 3.0 * row["legit_gram_schmidt_norm"]
        elif row["verdict"] == "survives trivial attack":
            assert row["candidate_gram_schmidt_norm"] >= row["usability_threshold"]


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
        assert row["candidate_gram_schmidt_norm"] > 0
