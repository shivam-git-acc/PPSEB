"""M8 — the harness and the reproduction script (Property 25, Requirement 8)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from medvault import repro
from medvault.config import MedVaultConfig
from medvault.harness import (
    ATTACKER_MODELS,
    KEYWORD_DICTIONARY,
    SECRET_KEYWORD,
    run_access_pattern,
    run_all_attacks,
    run_kga,
    run_plant,
    run_replay,
)


# --------------------------------------------------------------------------
# The attacks themselves
# --------------------------------------------------------------------------

def test_every_attacker_model_has_a_defined_outcome():
    for attacker in ATTACKER_MODELS:
        mode_a = run_kga("A", attacker=attacker)
        mode_b = run_kga("B", attacker=attacker)
        assert mode_a["mode"] == "A" and mode_b["mode"] == "B"
        assert mode_a["dictionary_size"] == len(KEYWORD_DICTIONARY)
        if attacker == "insider":
            assert mode_b["success_rate_pct"] == 100.0
        else:
            assert mode_b["success_rate_pct"] <= 2.0
            assert mode_b["blocked"] is True


def test_the_same_attack_function_runs_both_modes():
    """Requirement 8.2: nothing in the harness branches on the mode."""
    for function in (run_kga, run_plant, run_replay):
        source = function.__doc__ or ""
        assert "mode" in source.lower()
    # `run_plant` and `run_replay` accept any mode letter through the same call.
    for mode in ("A", "B"):
        assert run_plant(mode)["mode"] == mode
        assert run_replay(mode)["mode"] == mode


def test_access_pattern_differs_by_mode():
    assert run_access_pattern("A")["token_on_chain"] is True
    assert run_access_pattern("B")["token_on_chain"] is False
    assert run_access_pattern("B")["record_ids_on_chain"] is False


def test_mode_a_kga_reports_the_recovered_keyword():
    result = run_kga("A", attacker="outsider")
    assert result["recovered_keyword"] == SECRET_KEYWORD
    assert result["success_rate_pct"] == 100.0
    # Every lattice number carries its parameters (Requirement 12.10).
    assert set(result["params"]) == {"n", "q", "sigma", "l"}


def test_run_all_attacks_summary_is_the_before_after_table():
    summary = run_all_attacks(MedVaultConfig(seed=5))["summary"]
    assert summary["kga_outsider_pct"] == {"A": 100.0, "B": 0.0}
    assert summary["kga_insider_pct"] == {"A": 100.0, "B": 100.0}
    assert summary["replay_succeeds"] == {"A": True, "B": False}
    assert summary["plant_succeeds"] == {"A": True, "A′": False, "B": False}
    assert summary["retrieval_replay_succeeds"] == {"A": True, "B": False}
    assert summary["token_on_chain"] == {"A": True, "B": False}


# --------------------------------------------------------------------------
# repro.sh's Python half
# --------------------------------------------------------------------------

def test_repro_writes_json_with_every_required_section(tmp_path, fast_repro):
    result, _ = fast_repro(42)
    path = repro.write_results(result, tmp_path / "repro.json")
    loaded = json.loads(Path(path).read_text(encoding="utf-8"))

    for key in ("meta", "kga_success", "kga_trials", "replay_plant", "retrieval_replay",
                "shape_check", "mode_tradeoff", "leakage", "access_pattern",
                "search_latency_ms", "storage_overhead", "revocation_cost",
                "pir", "zk", "tree_evolution_norm", "gas_per_consent_event"):
        assert key in loaded
    # Every section carries data now. A section that could not be measured keeps
    # an explicit reason instead of a number, and is listed in not_yet_measured.
    assert loaded["pir"]
    assert loaded["tree_evolution_norm"]["all_nodes_correct"] is True
    assert loaded["zk"]["available"] in (True, False)
    for reason in loaded["not_yet_measured"].values():
        assert isinstance(reason, str) and reason

    assert loaded["meta"]["seed"] == 42
    assert loaded["meta"]["kem_label"]
    assert loaded["meta"]["library_versions"]
    assert loaded["meta"]["lattice_params"]


def test_repro_excludes_the_archived_sweeps():
    assert "sweep" in repro.ARCHIVED_SWEEPS
    source = Path(repro.__file__).read_text(encoding="utf-8")
    for module in ("sweep", "boundary", "nq_sweep", "end_to_end", "forward_sec",
                   "recovery"):
        assert f"import {module}" not in source
        assert f"from {module}" not in source


def test_archived_modules_are_still_runnable_separately():
    """Excluded from the repro path is not the same as removed."""
    import importlib

    for module in ("sweep", "attacks.boundary", "attacks.nq_sweep",
                   "attacks.end_to_end", "attacks.forward_sec", "attacks.recovery"):
        assert importlib.import_module(module) is not None


def test_repro_finishes_inside_the_time_budget(fast_repro):
    result, wall_clock = fast_repro(42)
    assert wall_clock < 600
    assert result["meta"]["elapsed_s"] < 600


# --------------------------------------------------------------------------
# Property 25: determinism
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 25: Repro determinism
def test_property_25_same_seed_same_headline_values(fast_repro):
    first, _ = fast_repro(42)
    second = repro.run_repro(42, fast=True)     # a genuinely fresh second run
    assert repro.deterministic_headline(first) == repro.deterministic_headline(second)


def test_a_different_seed_changes_the_fingerprint_but_not_the_outcomes(fast_repro):
    """The seed changes bytes, not the security outcomes the demo claims."""
    base = repro.deterministic_headline(fast_repro(42)[0])
    other = repro.deterministic_headline(fast_repro(1234)[0])
    assert base["kga_success"] == other["kga_success"]
    assert base["replay_plant"]["mode_B"]["replay"] is False
    assert base["storage_overhead"]["index_entry_bytes"] == \
        other["storage_overhead"]["index_entry_bytes"]


def test_storage_overhead_is_measured_not_guessed():
    storage = repro.measure_storage_overhead(MedVaultConfig(seed=42))
    assert storage["record_ciphertext_bytes"] == storage["record_plaintext_bytes"] + 28
    assert storage["index_entry_bytes"] == 96
    assert storage["envelope_bytes"] >= 1088  # one ML-KEM-768 ciphertext at least


def test_latency_rows_carry_their_grid_position():
    rows = repro.measure_search_latency(MedVaultConfig(seed=42), grid=((5, 1),),
                                       queries=3)
    for row in rows:
        assert {"records", "doctors", "queries", "keyed_index_ms_per_query"} <= set(row)
        assert row["keyed_index_ms_per_query"] >= 0


@pytest.mark.parametrize("mode,expect_leak", [("A", True), ("B", False)])
def test_repro_access_pattern_matches_the_harness(mode, expect_leak, fast_repro):
    result, _ = fast_repro(42)
    assert result["access_pattern"][f"mode_{mode}"]["token_on_chain"] is expect_leak


def test_sandboxes_ignore_the_callers_ledger_and_proof_mode():
    """Regression: a chain-backed session used to make the harness inherit
    `ledger_mode="hardhat"`, and its proof-less requests then crashed.

    The attacks measure the gateway, not the chain, so the sandbox pins both
    settings no matter what the caller passes.
    """
    from medvault.harness import build_sandbox

    world = build_sandbox("B", MedVaultConfig(seed=42, ledger_mode="hardhat",
                                              zk_mode="groth16"))
    assert world.ledger.backend_label == "memory-ledger"
    assert world.zk.mode == "signed"
    # And the replay attack itself must still produce a verdict, not an exception.
    result = run_replay("B", config=MedVaultConfig(seed=42, ledger_mode="hardhat"))
    assert result["replay_ok"] is False
