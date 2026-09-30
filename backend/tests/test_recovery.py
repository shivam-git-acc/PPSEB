"""PATCH 19 §7 — recovery is decided by the realized trapdoor, not the basis bound.

The claim under test is mechanistic, so the tests assert the mechanism: a
positive decode margin is exactly when Verify accepts, the realized trapdoor
norm predicts recovery better than the basis Gram-Schmidt norm does, and
widening only the attacker's sampling sigma walks the recovery rate down.
"""

import random

import numpy as np
import pytest

from attacks import recovery as rc
from attacks.end_to_end import build_frozen_history
from ppseb.linalg import kernel_basis_mod_q, strong_reduce
from ppseb.params import Params, default_params
from ppseb.scheme import trapdoor, verify


@pytest.fixture(scope="module")
def run():
    """Reduced size for test runtime; the shape of every claim is the same."""
    return rc.run_recovery_analysis(records_per_period=6, samples=10, repeats=1,
                                    sigma_scales=(1.0, 2.0, 4.0), seed=1900)


def test_records_metrics_trapnorm_margin(run):
    """Every attempt carries the two variables that decide the outcome, and the
    old proxy alongside for comparison."""
    assert run["n_attempts"] > 0
    for a in run["attempts_sample"]:
        if a.get("error"):
            continue
        assert isinstance(a["trap_norm"], float) and a["trap_norm"] > 0
        assert isinstance(a["margin"], float)
        assert isinstance(a["basis_gs"], float)
        assert isinstance(a["recovered"], bool)


def test_recovery_is_rate(run):
    """A period reports a FRACTION over many trapdoor draws, not one coin flip."""
    cells = [c for c in run["cells"] if c.get("recovery_rate") is not None]
    assert cells, run["cells"]
    for c in cells:
        assert c["samples"] == run["config"]["samples"] >= 2
        assert 0.0 <= c["recovery_rate"] <= 1.0
        assert c["recovery_rate"] == pytest.approx(c["recovered"] / c["measured"])
    # Not every cell may be fractional, but a rate must be capable of being one:
    # the sigma sweep is where the intermediate values are guaranteed.
    rates = [r["recovery_rate"] for r in run["sigma_sweep"]]
    assert any(0.0 < r < 1.0 for r in rates), rates


def test_margin_agrees_with_verify():
    """decode_margin > 0 is exactly when scheme.verify accepts -- the function
    it claims to explain. Checked directly, over a range of trapdoor widths so
    both sides of the threshold occur."""
    base = default_params()
    p = Params(n=4, q=257, sigma=base.sigma, l=base.l, usability_C=base.usability_C, m=0)
    history, _pk, _stolen_sk, mu, _u = build_frozen_history(1, p, seed=1900, records_per_period=4,
                                                            honest_checks=True, max_seed_retries=0)
    # A basis of THIS period's lattice. build_frozen_history's third return is
    # the NEXT period's key (the stolen one), which belongs to a different
    # lattice and would fail NewBasisDel's own check. The public kernel basis
    # needs no secret and is all this test requires.
    basis, _method = strong_reduce(kernel_basis_mod_q(history[0].pk_ri, p.q), block_size=2)
    db = history[0]
    # Take a record and its own keyword directly: this test is about margin
    # agreeing with Verify on a given ciphertext, so it must not depend on the
    # honest search having succeeded for this particular build.
    target_id, kw, _M = db.records[0]
    ct1, ct2 = next((c1, c2) for (n_id, c1, c2) in db.CT if n_id == target_id)
    seen = set()
    for scale in (1.0, 2.0, 5.0, 10.0):
        wide = Params(n=p.n, q=p.q, sigma=p.sigma * scale, l=p.l, usability_C=p.usability_C, m=0)
        wide.ciphertext_noise_sigma = p.ciphertext_noise_sigma
        for k in range(4):
            trap = trapdoor(db.pk_ri, basis, kw, 0, mu, wide, random.Random(k))
            margin = rc.decode_margin(ct1, ct2, trap, wide)
            match = bool(verify(ct1, ct2, trap, wide)[0])
            assert (margin > 0) == match, (scale, k, margin, match)
            seen.add(match)
    assert seen == {True, False}, "the sweep must cross the threshold for this to mean anything"


def test_margin_separates(run):
    """The mechanistic claim: recovered and failed attempts separate at
    margin 0, exactly, with false accepts the only admitted exception."""
    hist = run["plot2_margin_histograms"]
    assert hist["target_match_matches_margin"], "a positive margin must be exactly when Verify accepts"
    attempts = [a for a in run["attempts_sample"] if a.get("margin") is not None]
    for a in attempts:
        if a["recovered"]:
            assert a["margin"] > 0, a
        elif not a.get("false_accept"):
            assert a["margin"] <= 0, a
    assert sum(1 for a in attempts if a["margin"] > 0) > 0
    assert sum(1 for a in attempts if a["margin"] <= 0) > 0, "need both sides to claim separation"


def test_trapnorm_predicts_better_than_gs(run):
    """The realized trapdoor norm out-predicts the basis bound on the same
    attempts -- which is the whole point of changing what gets displayed."""
    corr = run["correlations_all"]
    assert corr["n_attempts"] > 20
    assert corr["trap_norm"] is not None and corr["basis_gs"] is not None
    assert abs(corr["trap_norm"]) > abs(corr["basis_gs"]), corr
    assert corr["trap_norm_beats_basis_gs"] is True
    # The margin is downstream of the norm, so it should predict at least as well.
    assert abs(corr["margin"]) >= abs(corr["trap_norm"]) - 1e-9, corr


def test_basis_gs_does_not_cleanly_predict(run):
    """The falsifier, asserted rather than asserted-away: cells exist whose
    basis norms order the opposite way to their recovery rates."""
    cells = [c for c in run["cells"] if c.get("recovery_rate") is not None]
    inversions = [(a, b) for a in cells for b in cells
                  if a["basis_gs"] < b["basis_gs"] and a["recovery_rate"] < b["recovery_rate"]]
    assert inversions, ("no inversion in this run -- the falsifier claim would be unsupported here; "
                        f"cells: {[(c['basis_gs'], c['recovery_rate']) for c in cells]}")


def test_sigma_sweep_monotone(run):
    """Widening only the attacker's sampling sigma walks the rate down: a
    controlled law, not an anecdote."""
    rows = run["sigma_sweep"]
    assert len(rows) >= 3
    rates = [r["recovery_rate"] for r in rows]
    norms = [r["mean_trap_norm"] for r in rows]
    margins = [r["mean_margin"] for r in rows]
    assert all(a <= b for a, b in zip(norms, norms[1:])), norms       # sigma up  -> ||Trap|| up
    assert all(a >= b for a, b in zip(margins, margins[1:])), margins  # ... -> margin down
    assert all(a >= b - 1e-9 for a, b in zip(rates, rates[1:])), rates # ... -> recovery down
    assert run["sigma_sweep_monotone"] is True
    assert rates[0] > rates[-1], "the sweep must actually move the rate"


def test_statement_is_measured_not_asserted(run):
    """The auto-statement quotes this run's own numbers, and says so when the
    measurement does not show what was expected."""
    s = run["statement"]
    assert f"n={run['config']['n']}" in s and f"q={run['config']['q']}" in s
    assert str(run["n_attempts"]) in s
    assert "asymptotic security" in s, "the scope caveat must survive"
    corr = run["correlations_all"]
    assert f"r={corr['trap_norm']:+.2f}" in s
