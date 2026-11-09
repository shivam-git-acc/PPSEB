"""Access-pattern leakage before and after (deck finding 6; S3).

The attack code is the mid-sem lab's, unchanged (`attacks/ledger.py`); these
tests point it at logs the MedVault system produces and pin three results:
PPSEB's public log leaks, the hardened chain log does not, and the search node
still does (R11.10) — plus what cover queries can and cannot change.
"""

from __future__ import annotations

import inspect

import attacks.ledger as ledger
from medvault import leakage
from medvault.harness import run_access_pattern


def test_attack_code_is_the_lab_code_unchanged():
    assert leakage.tier1 is ledger.tier1
    assert leakage.tier2_label is ledger.tier2_label
    # Tier 2 still has no parameter through which the truth could arrive.
    assert list(inspect.signature(ledger.tier2_label).parameters) == [
        "tx_log", "prevalence", "record_ids"]


def test_matched_record_ids_reach_the_chain_only_where_ppseb_puts_them():
    for mode, expected in (("A", True), ("B", False), ("C", True)):
        result = run_access_pattern(mode)
        assert result["matched_record_ids"], "the search must have matched something"
        assert result["record_ids_on_chain"] is expected, mode


def test_ppseb_chain_leaks_and_hardened_chain_does_not():
    sweep = leakage.leakage_sweep(seeds=2, base_seed=2101)
    a_chain = sweep["summary"]["mode_A_chain"]
    assert a_chain["tier1_purity_min"] == 1.0          # Tier 1: certain
    assert a_chain["beats_baseline"] == "2/2"          # Tier 2: beats chance

    b_chain = sweep["summary"]["mode_B_chain"]
    assert b_chain["observed_groups_mean"] == 0         # nothing to group
    assert b_chain["records_with_any_match_mean"] == 0
    assert b_chain["beats_baseline"] == "0/2"


def test_search_node_still_sees_the_access_pattern():
    """Stated in R11.10; measured here so nobody reads mode B as leak-free."""
    sweep = leakage.leakage_sweep(seeds=2, base_seed=2101, modes=("B",))
    node = sweep["summary"]["mode_B_search_node"]
    assert node["tier1_purity_min"] == 1.0
    assert node["beats_baseline"] == "2/2"


def test_cover_schedule_adds_real_keywords_and_flattens_counts():
    import random
    real = ["diabetes"] * 8 + ["asthma"] * 2
    stream = leakage.cover_schedule(real, 1.0, random.Random(0))
    assert len(stream) == 20 and all(k in ledger.PREVALENCE for k in stream)
    counts = {k: stream.count(k) for k in ledger.PREVALENCE}
    assert counts["diabetes"] == 8 and max(counts.values()) - min(counts.values()) <= 7
    # Only the least-searched keywords received cover.
    assert counts["asthma"] >= 2


def test_cover_queries_lower_tier2_but_cannot_hide_tier1():
    rows = leakage.cover_query_curve(overheads=(0.0, 2.0), seeds=3, base_seed=2101)
    none, heavy = rows
    assert heavy["tier2_accuracy_mean"] < none["tier2_accuracy_mean"]
    # The honest limit: co-access grouping is untouched by frequency smoothing.
    assert none["tier1_purity_mean"] == heavy["tier1_purity_mean"] == 1.0
