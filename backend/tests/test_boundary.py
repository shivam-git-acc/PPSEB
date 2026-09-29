"""PATCH 14 §5 — security boundary.

Backend A (lattice-estimator) needs SageMath, which is absent here, so its path
is asserted to be correctly reported as unavailable rather than silently faked.
"""

import math

import pytest

from attacks import boundary as bd
from attacks import security_estimate as se
from ppseb.params import Params, derived_m


def _cell(n=4, q=257, outcome=bd.OUTCOME_BROKE, bits=20.0, **extra):
    return {"n": n, "q": q, "m": derived_m(n, q), "outcome": outcome, "bits": bits,
            "paper_demo": bd.is_paper_demo(n, q), "trapdoor_bytes": se.trapdoor_bytes(derived_m(n, q), q),
            "estimate": {"backend": "lindner-peikert-fit", "bits": bits}, **extra}


# --- the estimate --------------------------------------------------------

def test_security_estimate_backend():
    """bits + backend label + cheapest attack, from whichever backend exists."""
    n, q = 4, 257
    est = se.estimate_bits(n, q, derived_m(n, q), target_norm=2.9, sigma=4.0)
    assert est["backend"] == ("lattice-estimator" if se.lattice_estimator_available() else "lindner-peikert-fit")
    assert est["cheapest_attack"]
    assert est["bits"] is None or est["bits"] > 0
    assert "fit_valid" in est


def test_backend_a_absence_is_reported_not_faked():
    assert se.lattice_estimator_available() is False, "Sage present: the Backend A path needs exercising"


def test_lp_fit_monotone():
    """More security with larger n, and with larger n·log q."""
    def bits(n, q, tau=3.0):
        est = se.estimate_bits(n, q, derived_m(n, q), target_norm=tau, sigma=4.0)
        return est["bits"] if est["bits"] is not None else (est["bits_upper_bound"] or 0.0)

    assert bits(4, 257) < bits(8, 257) or bits(8, 257) == 0.0  # n=8 may fall below the fit range
    assert bits(4, 257) < bits(4, 1153) < bits(4, 4001)
    assert bits(16, 12289) > bits(4, 4001)


def test_delta0_fit_is_monotone_where_it_is_used():
    """The fit dips below beta~50 -- searching there returned beta=3 for every
    parameter set. Only the monotone region is used."""
    betas = list(range(se.MIN_TRUSTWORTHY_BETA, 400, 10))
    deltas = [se.delta0_from_beta(b) for b in betas]
    assert all(a > b for a, b in zip(deltas, deltas[1:]))
    assert se.beta_for_delta0(se.delta0_from_beta(200)) == pytest.approx(200, abs=1)


def test_target_easier_than_fit_range_is_flagged_not_guessed():
    est = se.estimate_bits(4, 257, 72, target_norm=50.0, sigma=4.0)
    assert est["below_fit_range"] and est["beta"] is None
    assert est["bits"] is None and est["bits_upper_bound"] == pytest.approx(0.292 * 50)
    assert est["fit_valid"] is False


def test_trapdoor_bytes_grows_with_q_and_n():
    assert se.trapdoor_bytes(derived_m(4, 257), 257) < se.trapdoor_bytes(derived_m(4, 4001), 4001)
    assert se.trapdoor_bytes(derived_m(4, 257), 257) < se.trapdoor_bytes(derived_m(8, 257), 257)


# --- outcomes / conclusion ----------------------------------------------

def test_timeout_not_secure():
    cell = _cell(outcome=bd.OUTCOME_TIMEOUT, bits=101.0, n=16, q=12289)
    text = bd.build_conclusion([cell])
    assert "UNMEASURED" in text and "not proven secure" in text
    assert "secure" not in text.replace("not proven secure", "")
    assert bd.OUTCOME_TIMEOUT not in bd.MEASURED_OUTCOMES


def test_paper_params_marked():
    assert bd.is_paper_demo(4, 257) and bd.is_paper_demo(8, 257)
    assert not bd.is_paper_demo(4, 1153) and not bd.is_paper_demo(16, 12289)
    text = bd.build_conclusion([_cell(4, 257, bd.OUTCOME_BROKE, 19.6)])
    assert "demonstration parameters" in text and "vacuous" in text


def test_control_and_correctness_gates_excluded_from_boundary():
    cells = [_cell(4, 257, bd.OUTCOME_BROKE, 19.6),
             _cell(8, 257, bd.OUTCOME_NA, 14.0),
             _cell(4, 1153, bd.OUTCOME_UNTRUSTED, 31.8)]
    text = bd.build_conclusion(cells)
    assert "honest scheme incorrect or H2 invalid" in text
    assert "untrusted" in text
    broke_sentence = next(s for s in text.split(". ") if "recovers a working trapdoor" in s)
    assert "(n=8, q=257" not in broke_sentence and "(n=4, q=1153" not in broke_sentence
    assert "(n=4, q=257" in broke_sentence


def test_break_region_uses_only_broken_cells():
    cells = [_cell(4, 257, bd.OUTCOME_BROKE, 19.6), _cell(16, 12289, bd.OUTCOME_TIMEOUT, 101.3)]
    text = bd.build_conclusion(cells)
    assert "up to ~20 bits" in text


# --- a real cell ---------------------------------------------------------

@pytest.fixture(scope="module")
def paper_cell():
    return bd.run_cell_with_timeout(4, 257, J=2, records_per_period=6, seed=1400,
                                    beta_ladder=(2, 10), attack_budget_s=120.0, timeout_s=900)


def test_pk_attack_point(paper_cell):
    """Every valid cell yields bits, broke, beta_used and a runtime."""
    c = paper_cell
    assert "error" not in c, c.get("error")
    assert c["outcome"] in (bd.OUTCOME_BROKE, bd.OUTCOME_FAILED, bd.OUTCOME_TIMEOUT, bd.OUTCOME_NA)
    assert c["bits"] is not None and c["runtime_s"] > 0
    if c["outcome"] in bd.MEASURED_OUTCOMES:
        assert c["beta_used"] in (2, 10)
        assert isinstance(c["broke"], bool)
        assert c["attempts"]


def test_paper_demo_cell_breaks_from_public_key_alone(paper_cell):
    """The measured core of the finding: no secret key is needed at q=257."""
    if paper_cell["outcome"] == bd.OUTCOME_NA:
        pytest.skip(f"honest gate failed this seed: {paper_cell['gate_failed_checks']}")
    assert paper_cell["paper_demo"]
    assert paper_cell["outcome"] == bd.OUTCOME_BROKE
    assert paper_cell["control"]["passed"] is False
