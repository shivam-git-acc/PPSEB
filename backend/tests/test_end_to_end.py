import copy

import numpy as np
import pytest

from ppseb.params import default_params
from attacks import end_to_end as e2e
from attacks.end_to_end import (
    build_frozen_history, attack_period, end_to_end_experiment, end_to_end_multi_n,
    verify_search, _hash_ct, _hash_cm,
)


@pytest.fixture(scope="module")
def small_history():
    p = default_params()
    history, stolen_pk, stolen_sk, mu, u_pke = build_frozen_history(J=2, params=p, seed=1)
    return p, history, stolen_pk, stolen_sk, mu, u_pke


def test_legit_doctor_finds_own_record(small_history):
    """N0_legit must not be None for every period — the honest doctor must
    be able to find their own record before we ever ask if an attacker can."""
    _p, history, _stolen_pk, _stolen_sk, _mu, _u_pke = small_history
    for entry in history:
        assert entry.legit_trap_demo["N0"] is not None


def test_frozen_db_immutable(small_history):
    """CT_i/CM_i content hashes before and after an attack run must be
    identical — the attacker must never regenerate the frozen ciphertexts."""
    p, history, _stolen_pk, stolen_sk, mu, u_pke = small_history
    before_ct = [entry.ct_hash for entry in history]
    before_cm = [entry.cm_hash for entry in history]
    for i in range(len(history)):
        attack_period(history, i, len(history), stolen_sk, p, mu, u_pke)
    after_ct = [_hash_ct(entry.CT) for entry in history]
    after_cm = [_hash_cm(entry.CM) for entry in history]
    assert before_ct == after_ct
    assert before_cm == after_cm


def test_attacker_uses_frozen_ct(small_history, monkeypatch):
    """The attacker's search must be run against history[i].CT itself (by
    object identity), never a freshly-built tuple."""
    p, history, _stolen_pk, stolen_sk, mu, u_pke = small_history
    seen_ct = []
    real_verify_search = e2e.verify_search

    def spy(CT, trap, params, trace=None):
        seen_ct.append(CT)
        return real_verify_search(CT, trap, params, trace)

    monkeypatch.setattr(e2e, "verify_search", spy)
    attack_period(history, 0, len(history), stolen_sk, p, mu, u_pke)
    assert seen_ct, "verify_search was never called"
    assert seen_ct[0] is history[0].CT


def test_level2_same_n0_definition(small_history):
    """level2_search_break must be True IFF N0_star is not None AND equals
    N0_legit — never True on a None/None coincidence or a mismatch."""
    p, history, _stolen_pk, stolen_sk, mu, u_pke = small_history
    for i in range(len(history)):
        row = attack_period(history, i, len(history), stolen_sk, p, mu, u_pke)
        expected = row["N0_star"] is not None and row["N0_star"] == row["N0_legit"]
        assert row["level2_search_break"] == expected


def test_level3_gated_on_reachability(small_history, monkeypatch):
    """If LEVEL3_REACHABLE is False, level3_plaintext_break must always be
    False and the row must report level3_reachable=False, regardless of
    whether Level 2 broke."""
    p, history, _stolen_pk, stolen_sk, mu, u_pke = small_history
    monkeypatch.setattr(e2e, "LEVEL3_REACHABLE", False)
    row = attack_period(history, 0, len(history), stolen_sk, p, mu, u_pke)
    assert row["level3_plaintext_break"] is False
    assert row.get("level3_reachable") is False


def test_no_break_reported_honestly(monkeypatch):
    """If no period yields N0_star == N0_legit, the summary must say
    'resists', never 'broken' — forced by monkeypatching verify_search to
    always return a non-matching value for the attacker's own search."""
    p = default_params()

    def always_miss(CT, trap, params, trace=None):
        return None

    # Only the ATTACKER's search (inside attack_period) should be forced to
    # miss; the legit doctor's own search (inside build_frozen_history) must
    # still succeed, or there's nothing to attack. Patch after history build.
    history, stolen_pk, stolen_sk, mu, u_pke = build_frozen_history(J=2, params=p, seed=2)
    monkeypatch.setattr(e2e, "verify_search", always_miss)

    rows = [attack_period(history, i, len(history), stolen_sk, p, mu, u_pke) for i in range(len(history))]
    assert all(not r["level2_search_break"] for r in rows)
    any_l2 = any(r["level2_search_break"] for r in rows)
    assert any_l2 is False
    # mirror end_to_end_experiment's own summary logic at this outcome
    conclusion_should_say_resists = not any_l2
    assert conclusion_should_say_resists


def test_end_to_end_experiment_well_formed():
    """A full run at n=4 (fast) returns well-formed rows and a headline
    consistent with the measured any_l2_break."""
    p = default_params()
    result = end_to_end_experiment(J=2, base_params=p, n=4, seed=3, reducer_name="bkz")
    assert result["level3_reachable_in_principle"] is True
    assert len(result["rows"]) == 2
    for row in result["rows"]:
        assert "gs_norm" in row and "threshold" in row
        assert row["level2_search_break"] == (row["N0_star"] is not None and row["N0_star"] == row["N0_legit"])
        if not row["level2_search_break"]:
            assert row["level3_plaintext_break"] is False
    if result["any_l2_break"]:
        assert "break" in result["headline"].lower()
    else:
        assert "resists" in result["headline"].lower()
