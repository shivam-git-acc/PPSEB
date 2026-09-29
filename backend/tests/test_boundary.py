"""PATCH 14 §5 / PATCH 15 §4 — security boundary, both attacks.

Backend A (lattice-estimator) needs SageMath, which is absent here, so its path
is asserted to be correctly reported as unavailable rather than silently faked.

The PATCH 15 tests pin the RELATIVE verdict: a forward-security break may be
declared only where the public key alone FAILED, so `pk_broke` always
supersedes `stolen_broke`, and a timeout is never allowed to read as secure.
"""

import json

import math

import pytest

from attacks import boundary as bd
from attacks import security_estimate as se
from ppseb.params import Params, derived_m


def _cell(n=4, q=257, outcome=bd.OUTCOME_BROKE, bits=20.0, **extra):
    cell = {"n": n, "q": q, "m": derived_m(n, q), "outcome": outcome, "bits": bits,
            "paper_demo": bd.is_paper_demo(n, q), "trapdoor_bytes": se.trapdoor_bytes(derived_m(n, q), q),
            "estimate": {"backend": "lindner-peikert-fit", "bits": bits},
            "control_ok": True, "pk_broke": outcome == bd.OUTCOME_BROKE, "stolen_broke": False,
            "pk_timed_out": outcome == bd.OUTCOME_TIMEOUT, "stolen_timed_out": False, **extra}
    cell["stolen_helps"] = bool(cell["stolen_broke"] and not cell["pk_broke"])
    cell["verdict"] = bd.cell_verdict(cell)
    return cell


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
    return bd.run_cell_with_timeout(4, 257, J=3, records_per_period=6, seed=1400,
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


def test_timed_out_cell_still_carries_a_plottable_estimate():
    """A killed cell returns no result of its own, but must still have bits --
    the unmeasured cells are half the plot."""
    cell = bd.run_cell_with_timeout(16, 12289, J=2, records_per_period=6, seed=1400,
                                    beta_ladder=(2,), attack_budget_s=5.0, timeout_s=20)
    assert cell["outcome"] == bd.OUTCOME_TIMEOUT and cell["timed_out"]
    assert cell["bits"] is not None and cell["bits"] > 0
    assert cell["estimate"]["target_provenance"].startswith("gaussian_heuristic")
    assert cell["trapdoor_bytes"] > 0


# --- PATCH 15 §4: both attacks, relative verdict, wide-grid persistence -----

def test_both_attacks_per_cell(paper_cell):
    """A valid cell carries a measured outcome for BOTH attacks on the same
    frozen period -- otherwise 'the stolen key adds nothing' is unsupported."""
    c = paper_cell
    if c["outcome"] in (bd.OUTCOME_NA, bd.OUTCOME_H2):
        pytest.skip(f"honest gate failed this seed: {c.get('gate_failed_checks')}")
    for field in ("pk_broke", "pk_timed_out", "stolen_broke", "stolen_timed_out"):
        assert isinstance(c[field], bool), field
    assert c["pk_outcome"] in (bd.OUTCOME_BROKE, bd.OUTCOME_FAILED, bd.OUTCOME_TIMEOUT)
    assert c["stolen_outcome"] in (bd.OUTCOME_BROKE, bd.OUTCOME_FAILED, bd.OUTCOME_TIMEOUT)
    assert c["pk_attempts"] and c["stolen_attempts"], "both ladders must have run"
    # Same frozen period, so the two attacks are comparable at all.
    assert {a["N0_legit"] for a in c["pk_attempts"]} == {a["N0_legit"] for a in c["stolen_attempts"]}
    assert c["target_period"] == bd.STOLEN_TARGET_PERIOD and c["periods_back"] == c["J"]
    assert c["verdict"] == bd.cell_verdict(c)


def test_stolen_reads_only_stolen_sk():
    """Attack 2's inputs are the stolen sk_r|J plus public data: PeriodDB has no
    secret field, and the candidate builder takes exactly one secret argument."""
    import dataclasses
    import inspect
    from attacks.end_to_end import PeriodDB

    assert not any("sk" in f.name for f in dataclasses.fields(PeriodDB))
    params = list(inspect.signature(bd._stolen_candidate).parameters)
    assert [x for x in params if "sk" in x] == ["stolen_sk"], params
    # And the public-key attack takes no secret at all.
    assert not any("sk" in x for x in inspect.signature(bd._pk_candidate).parameters)


def test_verdict_forward_break_requires_pk_fail():
    """The only cell type that demonstrates forward security failing."""
    cell = _cell(outcome=bd.OUTCOME_FAILED, pk_broke=False, stolen_broke=True)
    assert cell["verdict"] == bd.VERDICT_FORWARD
    assert cell["stolen_helps"] is True
    tally = bd.stolen_key_tally([cell])
    assert len(tally["stolen_helps"]) == 1 and not tally["both_broke"]
    assert "genuine forward-security break" in bd.build_conclusion([cell])


def test_pk_supersedes_stolen():
    """Where the public key already breaks, the theft is redundant -- never a
    forward-security break."""
    cell = _cell(outcome=bd.OUTCOME_BROKE, pk_broke=True, stolen_broke=True)
    assert cell["verdict"] == bd.VERDICT_PK
    assert cell["stolen_helps"] is False
    tally = bd.stolen_key_tally([cell])
    assert not tally["stolen_helps"] and len(tally["both_broke"]) == 1
    text = bd.build_conclusion([cell])
    assert "the theft was redundant" in text and "genuine forward-security break" not in text


def test_timeout_never_reads_as_secure_in_the_relative_verdict():
    """A budget-exhausted attack falls into 'unmeasured', not into the
    'secure vs both' bucket, for either attack."""
    for field in ("pk_timed_out", "stolen_timed_out"):
        flags = {"pk_timed_out": False, "stolen_timed_out": False, field: True}
        cell = _cell(outcome=bd.OUTCOME_TIMEOUT, pk_broke=False, stolen_broke=False, **flags)
        assert cell["verdict"] == bd.VERDICT_UNMEASURED
        assert "secure" not in cell["verdict"]
        assert not bd.stolen_key_tally([cell])["neither"], "a timeout is not a measured survival"


def test_control_per_cell():
    """A cell whose negative control passed is untrusted, counts for nothing,
    and is never reported as a survival."""
    cell = _cell(outcome=bd.OUTCOME_UNTRUSTED, control_ok=False, pk_broke=True, stolen_broke=True)
    assert cell["verdict"] == bd.VERDICT_UNTRUSTED
    tally = bd.stolen_key_tally([cell])
    assert tally["considered"] == 0 and len(tally["excluded"]) == 1
    assert "untrusted (negative control passed); excluded" in bd.build_conclusion([cell])


def test_wide_grid_shape_and_q_substitution():
    """n x q, with the impossible q=4099 column substituted and the swap stated."""
    assert bd.DEFAULT_GRID == tuple((n, q) for n in (4, 8, 16) for q in (257, 1153, 4001, 12289, 40961))
    assert bd.Q_SUBSTITUTIONS == {4099: 4001}
    for (n, q) in bd.DEFAULT_GRID:
        assert bd.h2_valid(n, q) is None, f"grid cell (n={n}, q={q}) is impossible for H2"
    assert bd.h2_valid(4, 4099) is not None, "q=4099 is why the substitution exists"
    assert "4099" in bd.Q_SUBSTITUTION_NOTE and "4001" in bd.Q_SUBSTITUTION_NOTE
    assert bd.Q_SUBSTITUTION_NOTE in bd.build_conclusion([_cell()])
    assert bd.repeats_for(4, 257) == 2 and bd.repeats_for(16, 40961) == 1


def test_resume_wide_grid(tmp_path, monkeypatch):
    """Resuming skips units already in the JSONL: no cell is run or counted
    twice, and a repeated unit key is de-duplicated on read."""
    monkeypatch.setattr(bd, "RESULTS_DIR", tmp_path)
    job_id = "resume_test"
    grid = [(4, 257), (8, 257)]
    job = bd.BoundaryJob(job_id, grid, J=3, records_per_period=4, seed=1400,
                         beta_ladder=(2,), attack_budget_s=10.0, timeout_s=60)
    units = list(job._units())
    assert len(units) == 4, "two fast cells at 2 repeats each"

    ran = []

    def fake_cell(n, q, *a, **kw):
        ran.append((n, q, kw.get("run_stolen")))
        return _cell(n, q)

    monkeypatch.setattr(bd, "run_cell_with_timeout", fake_cell)
    job.run()
    assert job.status == "done" and len(ran) == 4
    assert len(job.cells) == 2, "repeats merge into one cell per (n, q)"

    ran.clear()
    resumed = bd.BoundaryJob(job_id, grid, J=3, records_per_period=4, seed=1400,
                             beta_ladder=(2,), attack_budget_s=10.0, timeout_s=60)
    resumed.run()
    assert ran == [], "every unit was already done"
    assert len(resumed.records) == 4 and len(resumed.cells) == 2

    # A duplicated line (e.g. two writers) must not double-count.
    path, _meta = bd._paths(job_id)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines + [lines[0]]) + "\n")
    assert len(bd.load_records(job_id)) == 4


def test_wall_clock_cap_stops_without_claiming_security(tmp_path, monkeypatch):
    """The overall cap checkpoints and stops; the cells it never reached are
    absent, not reported as secure."""
    monkeypatch.setattr(bd, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(bd, "run_cell_with_timeout", lambda n, q, *a, **kw: _cell(n, q))
    job = bd.BoundaryJob("cap_test", [(4, 257), (8, 257), (16, 12289)], J=3, records_per_period=4,
                         seed=1400, beta_ladder=(2,), attack_budget_s=10.0, timeout_s=60,
                         max_hours=1e-9)
    job.run()
    assert job.status == "stopped (wall-clock cap)"
    assert "NOT run" in job.stopped_early and "not reported as secure" in job.stopped_early
    assert len(job.cells) < 3


def test_merge_repeats_prefers_a_measured_break():
    """One success across repeats is a break; a timeout in another repeat can
    neither erase it nor be upgraded into a survival."""
    broke = _cell(4, 257, bd.OUTCOME_BROKE, pk_broke=True, pk_beta=2, seed=1)
    timed = _cell(4, 257, bd.OUTCOME_TIMEOUT, pk_broke=False, pk_timed_out=True, seed=2)
    merged = bd.merge_repeats([timed, broke])
    assert merged["pk_broke"] and merged["pk_beta"] == 2
    assert merged["pk_timed_out"] is False
    assert merged["outcome"] == bd.OUTCOME_BROKE and merged["verdict"] == bd.VERDICT_PK
    assert merged["repeats"] == 2 and merged["repeat_seeds"] == [2, 1]

    both_timed = bd.merge_repeats([timed, dict(timed, seed=3)])
    assert both_timed["pk_timed_out"] and both_timed["verdict"] == bd.VERDICT_UNMEASURED


def test_snapshot_carries_the_stolen_key_tally(tmp_path, monkeypatch):
    """The Plot-2 caption's counts come from the job, computed from the cells."""
    monkeypatch.setattr(bd, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(bd, "run_cell_with_timeout",
                        lambda n, q, *a, **kw: _cell(n, q, bd.OUTCOME_FAILED, pk_broke=False,
                                                     stolen_broke=(n == 8)))
    job = bd.BoundaryJob("tally_test", [(4, 257), (8, 257)], J=3, records_per_period=4, seed=1400,
                         beta_ladder=(2,), attack_budget_s=10.0, timeout_s=60)
    job.run()
    snap = job.snapshot()
    assert snap["stolen_key_tally"]["considered"] == 2
    assert [c["n"] for c in snap["stolen_key_tally"]["stolen_helps"]] == [8]
    assert json.dumps(snap["stolen_key_tally"])  # JSON-serialisable for the UI
