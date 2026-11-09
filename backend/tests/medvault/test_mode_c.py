"""Index mode C: PAEKS-style keyword authentication over PPSEB (S2).

The deck's proposed fix for offline keyword guessing is PAEKS: the sender
authenticates the keyword, so guesses cannot be turned into test ciphertexts.
Mode C keeps PPSEB's scheme, its public Verify and its on-chain trapdoor, and
runs it on HMAC(K_pd, keyword). These tests pin what that buys and, just as
deliberately, what it does not.
"""

from __future__ import annotations

import inspect

import pytest

from medvault.harness import (
    KEYWORD_DICTIONARY,
    kga_matrix,
    run_access_pattern,
    run_kga,
    run_plant,
    run_replay,
    run_retrieval_replay,
)
from medvault.search import ModeCIndex, paeks_keyword
from tests.medvault.helpers import make_sandbox


@pytest.fixture(scope="module")
def world():
    return make_sandbox("C", keywords=("diabetes", "blood"))


def test_mode_c_finds_the_right_record_and_only_that(world):
    assert isinstance(world.index, ModeCIndex)
    assert world.search("doctor_a", "diabetes")[0]["record_ids"] == ["rec-1"]
    assert world.search("doctor_a", " Diabetes ")[0]["record_ids"] == ["rec-1"]
    assert world.search("doctor_a", "asthma")[0]["record_ids"] == []


def test_mode_c_reuses_ppseb_unchanged():
    """The scheme is PPSEB's own; only the keyword fed to it changes."""
    source = inspect.getsource(ModeCIndex)
    assert "peks_encrypt(" in source and "paeks_keyword(" in source
    import ppseb.scheme as scheme
    assert "paeks" not in inspect.getsource(scheme)


def test_keyword_transform_is_keyed():
    k1, k2 = b"\x01" * 32, b"\x02" * 32
    assert paeks_keyword(k1, "diabetes") == paeks_keyword(k1, "  DIABETES")
    assert paeks_keyword(k1, "diabetes") != paeks_keyword(k2, "diabetes")
    assert "diabetes" not in paeks_keyword(k1, "diabetes")


def test_trapdoor_is_public_on_chain_yet_keyless_guessing_fails():
    """The tension the deck names: Verify and the trapdoor stay public."""
    assert run_access_pattern("C")["token_on_chain"] is True
    for attacker in ("outsider", "keyless_server"):
        result = run_kga("C", attacker=attacker)
        assert result["success"] is False and result["recovered_keyword"] is None
        assert result["blocked"] is True


def test_the_key_holding_insider_still_succeeds():
    insider = run_kga("C", attacker="insider")
    assert insider["success"] is True and insider["blocked"] is False


def test_mode_c_kga_as_a_rate():
    matrix = kga_matrix(rates=True, seeds=1, modes=("C",))
    n = len(KEYWORD_DICTIONARY)
    for attacker in ("outsider", "keyless_server"):
        cell = matrix["mode_C"][attacker]
        assert cell["trials"] == n and cell["successes"] == 0
        assert cell["wrong_keyword_matches"] == 0
    insider = matrix["mode_C"]["insider"]
    assert insider["wrong_keyword_matches"] == 0
    # Insider misses are toy-parameter correctness failures, as in mode A.
    assert insider["successes"] + insider["own_ciphertext_failures"] == n
    assert insider["success_rate_given_working_search_pct"] == 100.0


def test_mode_c_does_not_fix_replay_or_forgery():
    """Stated openly: mode C authenticates keywords, not requests or ciphertexts."""
    assert run_replay("C")["replay_ok"] is True
    assert run_retrieval_replay("C")["replay_ok"] is True
    assert run_plant("C")["appears_in_search"] is True


def test_revocation_works_through_the_keys():
    """Mode C has no gates, so a revoked doctor's request is still accepted;
    it matches nothing because the old epoch's entries and key are gone."""
    world = make_sandbox("C", doctors=("doctor_a", "doctor_b"))
    old = world.doctors["doctor_a"].build_request(world.index, "diabetes", nonce=50,
                                                  timestamp=world.ledger.now())
    assert world.submit_request(old)[0]["record_ids"] == ["rec-1"]

    world.revoke_doctor("doctor_a")
    after, _ = world.submit_request(old)
    assert after["ok"] is True and after["record_ids"] == []
    assert world.search("doctor_b", "diabetes")[0]["record_ids"] == ["rec-1"]
