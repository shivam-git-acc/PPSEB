"""PATCH 08 §8 — tests for the batch-sweep machinery.

These deliberately do NOT run the real crypto: the attack itself is covered
by tests/test_end_to_end.py, and a test suite for an overnight grid must not
itself take overnight. What's under test here is the part PATCH 08 actually
adds — persistence, resume/idempotency, per-cell error isolation, the trust
gate, and the aggregation that the overnight conclusion rests on.
"""

import json

import pytest

import sweep
from ppseb.params import default_params


@pytest.fixture(autouse=True)
def tmp_results_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(sweep, "RESULTS_DIR", tmp_path / "results")
    return tmp_path / "results"


def _cfg(**kw):
    base = dict(
        n_values=[4], J_values=[3], h1_variants=["low_norm"], reducers=["bkz"],
        records_per_period=8, repeats=3, seed_base=1, max_hours=1.0,
    )
    base.update(kw)
    return sweep.SweepConfig(**base)


def _ok_record(cfg, n, J, repeat, broke_periods=(), trusted=True, variant="low_norm", reducer="bkz"):
    seed = cfg.seed_for(n, J, variant, reducer, repeat)
    return {
        "key": sweep.unit_key(n, J, variant, reducer, repeat, seed),
        "n": n, "J": J, "variant": variant, "reducer": reducer,
        "repeat": repeat, "seed": seed, "status": "ok",
        "control_ok": trusted,
        "wordpred_disagreements": [] if trusted else [0],
        "any_l2_break": bool(broke_periods),
        "broken_periods_l2": list(broke_periods),
        "broken_periods_l3": [],
        "periods": [
            {"period": p, "periods_back": J - p, "gs_norm": 10.0 + p, "word_gs": 100.0 + p,
             "honest_word_gs": 50.0 + p, "threshold": 27.0,
             "level1_norm_ok": True, "level2_search_break": p in broke_periods,
             "level3_plaintext_break": False, "l2_matches_wordpred": True,
             "control_garbage_passed": False, "control_wrong_period_passed": False}
            for p in range(J)
        ],
        "trusted": trusted and True,
        "error": None,
    }


def _finalize(rec):
    rec["trusted"] = sweep.record_is_trusted(rec)
    return rec


# --- persistence / resume ------------------------------------------------

def test_results_persist():
    """Records are readable from the .jsonl after the job object is gone."""
    cfg = _cfg()
    job_id = "persist1"
    sweep.write_meta(job_id, {"job_id": job_id, "config": sweep.asdict(cfg), "total": 3, "status": "done"})
    for repeat in range(3):
        sweep.append_record(job_id, _finalize(_ok_record(cfg, 4, 3, repeat)))

    # Nothing in memory -- read purely from disk.
    records = sweep.load_records(job_id)
    assert len(records) == 3
    agg = sweep.aggregate(job_id)
    assert agg is not None
    assert agg["counts"]["units_done"] == 3


def test_checkpoint_resume(monkeypatch):
    """A job restarted after a partial run skips completed units and never
    double-counts them (idempotency keyed by unit_key)."""
    cfg = _cfg(repeats=4)
    job_id = "resume1"
    sweep.write_meta(job_id, {"job_id": job_id, "config": sweep.asdict(cfg), "total": 4, "status": "running"})

    # Two units already on disk from the "previous" (crashed) run.
    for repeat in (0, 1):
        sweep.append_record(job_id, _finalize(_ok_record(cfg, 4, 3, repeat)))

    executed = []

    def fake_run_unit(n, J, variant, reducer, repeat, seed, config, base_params):
        executed.append(repeat)
        return _finalize(_ok_record(config, n, J, repeat, variant=variant, reducer=reducer))

    monkeypatch.setattr(sweep, "run_unit", fake_run_unit)

    job = sweep.SweepJob(job_id, cfg, default_params())
    job._run()

    # Only the not-yet-done units ran ...
    assert sorted(executed) == [2, 3]
    # ... and the file holds exactly one record per unit, no duplicates.
    records = sweep.load_records(job_id)
    keys = [r["key"] for r in records]
    assert len(keys) == 4
    assert len(set(keys)) == 4
    assert sweep.load_meta(job_id)["status"] == "done"


def test_error_cell_continues(monkeypatch):
    """One throwing cell is recorded as an error and the job still finishes."""
    cfg = _cfg(repeats=3)
    job_id = "err1"

    real_end_to_end = sweep.end_to_end_experiment

    def exploding(*args, **kwargs):
        if kwargs.get("seed", 0) % 2 == 0:
            raise RuntimeError("injected failure")
        return {
            "rows": [], "control_ok": True, "wordpred_disagreements": [],
            "any_l2_break": False, "broken_periods_l2": [], "broken_periods_l3": [],
        }

    monkeypatch.setattr(sweep, "end_to_end_experiment", exploding)
    job = sweep.SweepJob(job_id, cfg, default_params())
    sweep.write_meta(job_id, {"job_id": job_id, "config": sweep.asdict(cfg), "total": 3, "status": "running"})
    job._run()

    records = sweep.load_records(job_id)
    assert len(records) == 3, "job must complete every unit despite a throwing cell"
    assert sweep.load_meta(job_id)["status"] == "done"
    errored = [r for r in records if r["status"] == "error"]
    assert errored, "the injected failure must be recorded, not swallowed"
    assert all("injected failure" in r["error"] for r in errored)
    assert all(r["trusted"] is False for r in errored)


# --- trust gate / aggregation -------------------------------------------

def test_break_rate_from_repeats():
    """break_rate = broken_trusted_repeats / trusted_repeats."""
    cfg = _cfg(repeats=3)
    records = [
        _finalize(_ok_record(cfg, 4, 3, 0, broke_periods=(2,))),
        _finalize(_ok_record(cfg, 4, 3, 1, broke_periods=(2,))),
        _finalize(_ok_record(cfg, 4, 3, 2)),
    ]
    cells = sweep.aggregate_cells(records, cfg)
    assert len(cells) == 1
    cell = cells[0]
    assert cell["trusted_repeats"] == 3
    assert cell["broken_trusted_repeats"] == 2
    assert cell["break_rate"] == pytest.approx(2 / 3)
    assert cell["outcome"] == "break"
    assert cell["broken_periods_l2"] == [2]


def test_untrusted_repeats_excluded_from_break_rate():
    """A repeat that failed a guardrail contributes to neither numerator nor
    denominator -- it is excluded, not counted as a survival."""
    cfg = _cfg(repeats=3)
    records = [
        _finalize(_ok_record(cfg, 4, 3, 0, broke_periods=(2,))),
        _finalize(_ok_record(cfg, 4, 3, 1)),
        _finalize(_ok_record(cfg, 4, 3, 2, broke_periods=(1,), trusted=False)),
    ]
    cells = sweep.aggregate_cells(records, cfg)
    cell = cells[0]
    assert cell["trusted_repeats"] == 2
    assert cell["break_rate"] == pytest.approx(1 / 2)
    assert cell["broken_periods_l2"] == [2], "the untrusted repeat's period must not appear"


def test_conclusion_trusted_only():
    """Untrusted / errored / skipped cells are excluded from the conclusion's
    counts and never silently become 'survives'."""
    cfg = _cfg(n_values=[4, 8], J_values=[3], repeats=3)
    records = []
    # n=4 -> a clean surviving cell.
    for r in range(3):
        records.append(_finalize(_ok_record(cfg, 4, 3, r)))
    # n=8 -> every repeat fails the guardrails => untrusted.
    for r in range(3):
        records.append(_finalize(_ok_record(cfg, 8, 3, r, broke_periods=(1,), trusted=False)))

    cells = sweep.aggregate_cells(records, cfg)
    by_n = {c["n"]: c for c in cells}
    assert by_n[4]["outcome"] == "survives"
    assert by_n[8]["outcome"] == "untrusted"

    text = sweep.build_conclusion(cells, cfg, records)
    assert "1 trusted cells" in text or "Of 1 trusted" in text
    assert "1 cells were untrusted" in text
    # The untrusted cell "broke" -- that must NOT be reported as a break.
    assert "n=8" not in text.split("untrusted")[0]


def test_skipped_never_survives():
    """A cell with no completed repeats (safety-stopped / never reached) is
    'skipped' -- it must never be counted as a survival."""
    cfg = _cfg(n_values=[4, 8], J_values=[3], repeats=3)
    records = [_finalize(_ok_record(cfg, 4, 3, r)) for r in range(3)]  # n=8 never ran
    cells = sweep.aggregate_cells(records, cfg)
    by_n = {c["n"]: c for c in cells}
    assert by_n[8]["outcome"] == "skipped"
    assert by_n[8]["outcome"] != "survives"
    assert by_n[8]["break_rate"] is None

    text = sweep.build_conclusion(cells, cfg, records)
    assert "1 errored or were skipped" in text


def test_partial_cell_is_not_survives():
    """A cell stopped mid-way (fewer than half its repeats trusted) is
    untrusted, not a survival on thin evidence."""
    cfg = _cfg(repeats=4)
    records = [_finalize(_ok_record(cfg, 4, 3, 0))]  # 1 of 4 repeats
    cells = sweep.aggregate_cells(records, cfg)
    assert cells[0]["outcome"] == "untrusted"


def test_record_is_trusted_gate():
    """The gate rejects each guardrail failure independently."""
    cfg = _cfg()
    ok = _ok_record(cfg, 4, 3, 0)
    assert sweep.record_is_trusted(ok)

    bad_control = dict(ok, control_ok=False)
    assert not sweep.record_is_trusted(bad_control)

    bad_wordpred = dict(ok, wordpred_disagreements=[2])
    assert not sweep.record_is_trusted(bad_wordpred)

    errored = dict(ok, status="error")
    assert not sweep.record_is_trusted(errored)


# --- plots / export ------------------------------------------------------

def test_plot_data_shape():
    """Plot A-D payloads are well-formed for an aggregated grid."""
    cfg = _cfg(n_values=[4, 8], J_values=[3, 4], repeats=2)
    records = []
    for n in (4, 8):
        for J in (3, 4):
            for r in range(2):
                records.append(_finalize(_ok_record(cfg, n, J, r, broke_periods=(1,) if n == 4 else ())))
    cells = sweep.aggregate_cells(records, cfg)
    plots = sweep.plot_payloads(records, cells, cfg)

    panels = plots["plot_a"]["panels"]
    assert len(panels) == 1
    assert panels[0]["n_values"] == [4, 8] and panels[0]["J_values"] == [3, 4]
    assert len(panels[0]["cells"]) == 4

    series = plots["plot_b"]["low_norm|bkz"]
    assert {s["n"] for s in series} == {4, 8}
    for s in series:
        for pt in s["points"]:
            assert pt["word_gs_mean"] is not None
            assert pt["threshold"] is not None
            assert pt["samples"] >= 1

    assert {row["n"] for row in plots["plot_c"]} == {4, 8}
    assert all("bkz" in row for row in plots["plot_c"])

    assert {row["n"] for row in plots["plot_d"]} == {4, 8}
    for row in plots["plot_d"]:
        assert row["broke"] + row["survives"] + row["untrusted"] + row["error"] == 2


def test_csv_export_has_one_row_per_period():
    cfg = _cfg(repeats=1)
    job_id = "csv1"
    sweep.write_meta(job_id, {"job_id": job_id, "config": sweep.asdict(cfg), "total": 1, "status": "done"})
    sweep.append_record(job_id, _finalize(_ok_record(cfg, 4, 3, 0)))
    csv = sweep.records_csv(job_id)
    lines = csv.strip().splitlines()
    assert lines[0].startswith("key,n,J,")
    assert len(lines) == 1 + 3  # header + one row per period (J=3)


# --- preflight -----------------------------------------------------------

def test_preflight_flags_impossible_dimensions():
    """The H2 constraint makes n=6/n=10 impossible at q=257; preflight must
    say so BEFORE the overnight run, not after."""
    cfg = _cfg(n_values=[4, 6, 8, 10], J_values=[3], repeats=1)
    pre = sweep.preflight(cfg, 257)
    assert pre["invalid_n"] == [6, 10]
    assert pre["valid_n"] == [4, 8]
    assert pre["doomed_units"] == 2
    assert pre["runnable_units"] == 2
    assert pre["warnings"], "an impossible grid must warn"


def test_preflight_clean_grid_has_no_warning():
    cfg = _cfg(n_values=[4, 8, 16], J_values=[3], repeats=1)
    pre = sweep.preflight(cfg, 257)
    assert pre["invalid_n"] == []
    assert pre["warnings"] == []
    assert pre["eta_seconds"] > 0


def test_h2_dimension_valid_matches_the_real_constraint():
    for n in (2, 4, 8, 16, 32):
        assert sweep.h2_dimension_valid(n, 257)
    for n in (3, 5, 6, 7, 9, 10, 12):
        assert not sweep.h2_dimension_valid(n, 257)


# --- gate bias, reproducibility, multi-process safety --------------------

def _wordpred_only_break(cfg, n, J, repeat):
    """A repeat that recovered N0 with every negative control holding, excluded
    ONLY because the word-basis predictor disagreed -- the exact case the live
    run exposed."""
    rec = _ok_record(cfg, n, J, repeat, broke_periods=(J - 1,))
    rec["control_ok"] = True
    rec["wordpred_disagreements"] = [J - 1]
    # Honest word basis over threshold although the honest search works.
    for p in rec["periods"]:
        p["honest_word_gs"] = 60.0
        p["threshold"] = 27.0
    return _finalize(rec)


def test_controls_only_gate_counts_wordpred_disagreement():
    cfg = _cfg()
    rec = _wordpred_only_break(cfg, 4, 3, 0)
    assert not sweep.record_is_trusted(rec, "strict")
    assert sweep.record_is_trusted(rec, "controls_only")
    with pytest.raises(ValueError):
        sweep.record_is_trusted(rec, "anything_else")


def test_controls_only_gate_still_rejects_failed_controls():
    cfg = _cfg()
    rec = _ok_record(cfg, 4, 3, 0, broke_periods=(2,), trusted=False)
    assert not sweep.record_is_trusted(rec, "controls_only")


def test_gate_diagnostics_measure_miscalibration():
    cfg = _cfg()
    records = [_wordpred_only_break(cfg, 4, 3, r) for r in range(3)]
    d = sweep.gate_diagnostics(records)
    assert d["honest_periods_measured"] == 9
    assert d["honest_word_usable"] == 0
    assert d["honest_word_usable_rate"] == 0.0
    assert d["predictor_miscalibrated"] is True
    assert len(d["breaks_excluded_by_wordpred_only"]) == 3


def test_strict_conclusion_never_claims_clean_negative_when_breaks_were_filtered():
    """The failure mode the live run exposed: under the strict gate, a run
    whose only breaks were removed by the miscalibrated word-basis check must
    NOT be reported as a consistent negative result."""
    cfg = _cfg(n_values=[4], J_values=[3, 4], repeats=3)
    records = [_finalize(_ok_record(cfg, 4, 3, r)) for r in range(3)]         # clean survives
    records += [_wordpred_only_break(cfg, 4, 4, r) for r in range(3)]        # filtered breaks

    cells = sweep.aggregate_cells(records, cfg, "strict")
    text = sweep.build_conclusion(cells, cfg, records, "strict")
    assert "consistent negative result" not in text
    assert "CAUTION" in text

    cells_c = sweep.aggregate_cells(records, cfg, "controls_only")
    by_j = {c["J"]: c for c in cells_c}
    assert by_j[4]["outcome"] == "break"
    assert by_j[4]["break_rate"] == pytest.approx(1.0)


def test_clean_negative_result_still_reported_when_nothing_was_filtered():
    cfg = _cfg(repeats=3)
    records = [_finalize(_ok_record(cfg, 4, 3, r)) for r in range(3)]
    cells = sweep.aggregate_cells(records, cfg, "strict")
    text = sweep.build_conclusion(cells, cfg, records, "strict")
    assert "consistent negative result" in text
    assert "CAUTION" not in text


def test_seeds_stable_across_processes():
    """Seeds (and hence idempotency keys) must not depend on per-process
    string-hash randomization, or resume after a restart double-counts."""
    import subprocess, sys
    code = (
        "import sys; sys.path.insert(0, '.');"
        "import sweep; c = sweep.SweepConfig(seed_base=7);"
        "print(c.seed_for(4, 3, 'low_norm', 'bkz', 1))"
    )
    outs = {
        subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env={"PYTHONHASHSEED": str(h), "PATH": ""}, cwd=str(sweep.Path(sweep.__file__).parent)).stdout.strip()
        for h in (1, 2, 3)
    }
    assert len(outs) == 1 and outs != {""}, outs


def test_load_records_dedupes_by_key():
    cfg = _cfg(repeats=1)
    job_id = "dup1"
    rec = _finalize(_ok_record(cfg, 4, 3, 0))
    sweep.append_record(job_id, rec)
    sweep.append_record(job_id, rec)
    assert len(sweep.load_records(job_id)) == 1


def test_lock_prevents_second_live_owner(monkeypatch):
    job_id = "lock1"
    sweep._lock_path(job_id).write_text("999999")
    monkeypatch.setattr(sweep, "_pid_alive", lambda pid: True)
    assert sweep.acquire_job_lock(job_id) is False

    monkeypatch.setattr(sweep, "_pid_alive", lambda pid: False)
    assert sweep.acquire_job_lock(job_id) is True  # stale lock is taken over


def test_resume_interrupted_jobs_on_startup(monkeypatch):
    """A job left 'running' by a dead process is resumed with the params it
    started with, and only its missing units run."""
    cfg = _cfg(repeats=3)
    job_id = "startup1"
    started_params = {"n": 4, "q": 257, "sigma": 9.5, "l": 10, "usability_C": 0.2}
    sweep.write_meta(job_id, {
        "job_id": job_id, "config": sweep.asdict(cfg), "total": 3,
        "status": "running", "base_params": started_params,
    })
    sweep.append_record(job_id, _finalize(_ok_record(cfg, 4, 3, 0)))

    seen = {"repeats": [], "sigma": set()}

    def fake_run_unit(n, J, variant, reducer, repeat, seed, config, base_params):
        seen["repeats"].append(repeat)
        seen["sigma"].add(base_params.sigma)
        return _finalize(_ok_record(config, n, J, repeat))

    monkeypatch.setattr(sweep, "run_unit", fake_run_unit)
    resumed = sweep.resume_interrupted_jobs(default_params())
    assert resumed == [job_id]
    sweep._JOBS[job_id].thread.join(timeout=10)

    assert sorted(seen["repeats"]) == [1, 2]
    assert seen["sigma"] == {9.5}, "resume must use the job's own params, not the caller's defaults"
    assert sweep.load_meta(job_id)["status"] == "done"
    assert len(sweep.load_records(job_id)) == 3


def test_stop_file_halts_job(monkeypatch):
    """Stop works across processes: the runner honours the on-disk stop file."""
    cfg = _cfg(repeats=5)
    job_id = "stop1"
    calls = []

    def fake_run_unit(n, J, variant, reducer, repeat, seed, config, base_params):
        calls.append(repeat)
        if len(calls) == 2:
            sweep._stop_path(job_id).write_text("stop")
        return _finalize(_ok_record(config, n, J, repeat))

    monkeypatch.setattr(sweep, "run_unit", fake_run_unit)
    sweep.write_meta(job_id, {"job_id": job_id, "config": sweep.asdict(cfg), "total": 5, "status": "running"})
    sweep.SweepJob(job_id, cfg, default_params())._run()

    meta = sweep.load_meta(job_id)
    assert meta["status"] == "stopped"
    assert len(sweep.load_records(job_id)) == 2
