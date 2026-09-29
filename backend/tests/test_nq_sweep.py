"""PATCH 13 §3 — (n, q) sweep."""

import math
from pathlib import Path

import pytest

from attacks import nq_sweep as nq
from attacks.end_to_end import build_frozen_history
from ppseb.params import Params, default_params


def _period(a1=False, a2=False, control=False):
    checks = {k: True for k in nq.GATE_CHECKS}
    checks.update(word_gs=50.0, threshold=35.0, word_usable=False)
    return {"period": 0, "checks": checks, "gate_ok": True,
            "attack1": {"break": a1, "N0_star": 0 if a1 else None, "N0_legit": 0},
            "attack2": {"break": a2, "N0_star": 0 if a2 else None, "N0_legit": 0},
            "control": {"passed": control, "N0_star": None, "N0_legit": 0}}


def _cell(*periods, gate_ok=True, **extra):
    return {"n": 4, "q": 257, "m": 72, "repeats": [{"gate_ok": gate_ok, "periods": list(periods)}], **extra}


def test_m_derived_per_cell():
    """m follows q for the same n -- never a cached global."""
    ms = {q: Params(n=4, q=q, sigma=4.0, l=10, m=0).m for q in (257, 4001)}
    assert ms[257] == 2 * 4 * math.ceil(math.log2(257)) == 72
    assert ms[4001] == 2 * 4 * math.ceil(math.log2(4001)) == 96
    assert ms[257] != ms[4001]
    assert nq.m_checks(4, 4001, 96)["m_matches_formula"]


@pytest.mark.parametrize("n", nq.DEFAULT_N_VALUES)
@pytest.mark.parametrize("q", nq.DEFAULT_Q_VALUES)
def test_m_lower_bound(n, q):
    checks = nq.m_checks(n, q, Params(n=n, q=q, sigma=4.0, l=10, m=0).m)
    assert checks["m_matches_formula"] and checks["m_above_lower_bound"]


@pytest.mark.parametrize("n", nq.DEFAULT_N_VALUES)
@pytest.mark.parametrize("q", nq.DEFAULT_Q_VALUES)
def test_h2_valid_for_grid(n, q):
    assert nq.h2_valid(n, q) is None


def test_h2_invalid_at_4099_is_reported_not_crashed():
    """The patch's original q=4099 is 3 mod 4, so x^4 - c is never irreducible."""
    assert nq.h2_valid(4, 4099) is not None
    cell = nq.run_cell(4, 4099, J=2, repeats=1, records_per_period=4, seed_base=1)
    assert cell["verdict"] == nq.VERDICT_H2 and cell["m"] == 104


def test_correctness_gate_per_cell():
    """A cell whose honest chain fails any gated check is n/a, whatever the attacks did."""
    cell = _cell(_period(a1=True, a2=True), gate_ok=False)
    assert nq.cell_verdict(cell) == nq.VERDICT_HONEST
    cell["verdict"] = nq.cell_verdict(cell)
    text = nq.build_conclusion([cell], [4], [257])
    assert "correctness gate" in text and "public-key-only attack breaks" not in text


def test_pk_supersedes_stolen():
    assert nq.cell_verdict(_cell(_period(a1=True, a2=True))) == nq.VERDICT_PK
    assert nq.cell_verdict(_cell(_period(a1=False, a2=True))) == nq.VERDICT_STOLEN
    assert nq.cell_verdict(_cell(_period())) == nq.VERDICT_FAILED


def test_control_passing_makes_cell_untrusted_before_any_break():
    assert nq.cell_verdict(_cell(_period(a1=True, control=True))) == nq.VERDICT_UNTRUSTED


def test_cell_worker_is_a_plain_subprocess():
    """Not multiprocessing: spawn/forkserver hand the child the parent's __main__
    path, which killed every cell of a real grid run launched from stdin."""
    import inspect
    assert "subprocess.run" in inspect.getsource(nq.run_cell_with_timeout)
    module_src = Path(inspect.getfile(nq)).read_text()
    assert "import multiprocessing" not in module_src


def test_cell_runs_to_completion_in_its_own_process():
    """The regression the unit tests missed: a cell must come back with a real
    verdict, not a worker error."""
    cell = nq.run_cell_with_timeout(4, 257, J=2, repeats=1, records_per_period=4,
                                    seed_base=5, timeout_s=900)
    assert "error" not in cell, cell.get("error")
    assert not cell.get("timed_out")
    assert cell["verdict"] in (nq.VERDICT_PK, nq.VERDICT_STOLEN, nq.VERDICT_FAILED,
                               nq.VERDICT_HONEST, nq.VERDICT_UNTRUSTED)
    assert cell["repeats"][0]["periods"]


def test_timeout_is_untested_not_secure():
    cell = nq.run_cell_with_timeout(8, 257, 4, 2, 40, 1, timeout_s=1.0)
    assert cell["timed_out"] and cell["verdict"] == nq.VERDICT_TIMEOUT
    text = nq.build_conclusion([cell], [8], [257])
    assert "untested" in text and "Both attacks fail" not in text


def test_word_check_reported_but_not_gated():
    assert "word_usable" not in nq.GATE_CHECKS
    assert {"kernel_ok", "match_ok", "nonmatch_ok", "search_ok", "decrypt_ok"} <= set(nq.GATE_CHECKS)


@pytest.fixture(scope="module")
def small_history():
    base = default_params()
    p = Params(n=4, q=257, sigma=base.sigma, l=base.l, usability_C=base.usability_C, m=0)
    history, _pk, stolen_sk, mu, u_pke = build_frozen_history(
        2, p, seed=5, records_per_period=6, honest_checks=True, max_seed_retries=0)
    return p, history, stolen_sk, mu, u_pke


def test_honest_checks_recorded_per_period(small_history):
    _p, history, *_ = small_history
    for entry in history:
        checks = entry.legit_trap_demo["checks"]
        assert set(nq.GATE_CHECKS) <= set(checks)
        assert checks["kernel_ok"] is True


def test_control_reduced_garbage_fails(small_history):
    """A short, genuine trapdoor for an unrelated lattice must not find the doctor's record."""
    p, history, _sk, mu, _u = small_history
    for i in range(len(history)):
        ctrl = nq.negative_control_unrelated_key(history, i, p, mu, seed=5)
        assert ctrl["passed"] is False


def test_both_attacks_run_per_valid_cell(monkeypatch):
    """When the gate passes, every period gets Attack 1, Attack 2 and the control."""
    monkeypatch.setattr(nq, "GATE_CHECKS", ("kernel_ok",))
    rep = nq.run_repeat(4, 257, J=2, records_per_period=6, seed=5)
    assert rep["gate_ok"]
    for pe in rep["periods"]:
        assert {"attack1", "attack2", "control"} <= set(pe)
        assert set(pe["attack1"]) >= {"N0_star", "N0_legit", "break"}
