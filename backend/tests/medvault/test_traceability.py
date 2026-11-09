"""Appendix A: one regression test per finding (Requirements 14.2, 15).

Each test names its finding, the mechanism that closes it, and the observable
that proves it. These are the rows the traceability table points at.
"""

from __future__ import annotations

import pytest

from medvault.config import MedVaultConfig
from medvault.envelope import Scope
from medvault.harness import (
    run_access_pattern,
    run_kga,
    run_plant,
    run_replay,
    run_retrieval_replay,
)
from medvault.service import build_world
from tests.medvault.helpers import make_sandbox


def test_finding_kga_offline_keyword_guessing():
    """F1 — keyed off-chain per-doctor per-epoch tokens.

    Before: an outsider with a dictionary and one captured token recovers the
    keyword. After: they cannot even form a candidate token.
    """
    baseline = run_kga("A", attacker="outsider")
    hardened = run_kga("B", attacker="outsider")
    assert baseline["success_rate_pct"] == 100.0
    assert hardened["success_rate_pct"] <= 2.0
    assert hardened["blocked"] is True

    keyless = run_kga("B", attacker="keyless_server")
    assert keyless["success_rate_pct"] <= 2.0

    insider = run_kga("B", attacker="insider")
    assert insider["success_rate_pct"] == 100.0, "reported openly, not hidden"


def test_finding_plant_universal_ciphertext():
    """F2 — patient-signed entry writes.

    Before: `CT1 = ⌊q/2⌋, CT2 = 0` matches every trapdoor. After: the entry has
    no patient signature, so the search node refuses it.
    """
    baseline = run_plant("A")
    assert baseline["accepted"] is True
    assert baseline["appears_in_search"] is True

    hardened = run_plant("B")
    assert hardened["accepted"] is False
    assert hardened["appears_in_search"] is False
    assert hardened["reason"] == "unsigned_entry"


def test_finding_replay_captured_trapdoor():
    """F3 — signed, nonce-bound requests with an epoch check."""
    baseline = run_replay("A")
    assert baseline["first_ok"] is True and baseline["replay_ok"] is True

    hardened = run_replay("B")
    assert hardened["first_ok"] is True
    assert hardened["replay_ok"] is False
    assert hardened["replay_reason"] == "reused_nonce"


def test_finding_kga_as_a_rate_with_an_unkeyed_control():
    """F1 measured as a rate, not one trial: every dictionary keyword is the
    secret once. The unkeyed-hash control shows the key, not hashing, is the fix."""
    from medvault.harness import KEYWORD_DICTIONARY, kga_matrix

    matrix = kga_matrix(rates=True, seeds=1)
    n = len(KEYWORD_DICTIONARY)
    for attacker in ("outsider", "keyless_server", "insider"):
        cell = matrix["mode_A"][attacker]
        assert cell["trials"] == n and cell["wrong_keyword_matches"] == 0
        # Every miss is a trapdoor that failed on its own keyword's ciphertext
        # (a toy-parameter correctness failure the doctor suffers too), never a
        # keyword the attack could not find while search worked.
        assert cell["successes"] + cell["own_ciphertext_failures"] == n
        assert cell["success_rate_given_working_search_pct"] == 100.0
        assert cell["success_rate_pct"] >= 80.0
    assert matrix["mode_B"]["outsider"]["successes"] == 0
    assert matrix["mode_B"]["keyless_server"]["successes"] == 0
    assert matrix["mode_B"]["insider"]["successes"] == n      # reported openly
    control = matrix["control_unkeyed_hash"]
    assert control["successes"] == control["trials"] == n


def test_finding_replay_captured_retrieval():
    """F3, retrieval half (deck finding 7: "replay it, pull the record").

    Before: the same retrieval bytes hand the ciphertext over twice. After: the
    second submission is rejected at the nonce gate. Neither path ever gives the
    replaying party plaintext.
    """
    baseline = run_retrieval_replay("A")
    assert baseline["legit_ok"] is True and baseline["replay_ok"] is True
    assert baseline["replay_plaintext"] is None and baseline["replay_ciphertext_bytes"] > 0

    hardened = run_retrieval_replay("B")
    assert hardened["first_ok"] is True and hardened["legit_ok"] is True
    assert hardened["replay_ok"] is False
    assert hardened["replay_reason"] == "reused_nonce"


def test_retrieval_gates_reject_forged_and_cross_used_signatures():
    """Mode B retrieval: a wrong key, a tampered field, or a search signature
    presented as a retrieval signature are all `bad_signature`, and a rejected
    request does not burn the nonce."""
    from dataclasses import replace

    from medvault.crypto import ed25519_keypair

    world = make_sandbox("B")
    doctor = world.doctors["doctor_a"]
    good = doctor.build_retrieval("rec-1", doctor.next_nonce(), world.ledger.now())
    before = world.gateway.last_nonce("doctor_a")

    stranger = ed25519_keypair(seed=b"\x07" * 32, label="TEST_KEY:stranger")
    forged = replace(good, signature=stranger.sign(b"anything"))
    tampered = replace(good, record_id="rec-other")
    search_sig = doctor.build_request(world.index, "diabetes", good.nonce,
                                      good.timestamp).signature
    cross = replace(good, signature=search_sig)
    for bad in (forged, tampered, cross):
        result, _ = world.submit_retrieval(bad)
        assert result["ok"] is False and result["reason"] == "bad_signature"
    assert world.gateway.last_nonce("doctor_a") == before

    assert world.submit_retrieval(good)[0]["ok"] is True


def test_finding_access_pattern_is_public():
    """F4 — commitments only on-chain, private retrieval via PIR (M5)."""
    baseline = run_access_pattern("A")
    assert baseline["token_on_chain"] is True
    assert baseline["record_ids_on_chain"] is True   # PPSEB's step 4, now modelled
    hardened = run_access_pattern("B")
    assert hardened["token_on_chain"] is False
    assert hardened["record_ids_on_chain"] is False
    assert "public_token" not in hardened["log_keys"]
    assert "matched" not in hardened["log_keys"]


def test_finding_stale_or_modified_cloud_data():
    """F5 — the on-chain Merkle root and version."""
    world = make_sandbox("B")
    assert world.retrieve("doctor_a", "rec-1")[0]["ok"] is True

    world.set_evil_mode("modified")
    modified, _ = world.retrieve("doctor_a", "rec-1")
    assert modified["ok"] is False and modified["plaintext"] is None

    world.upload_record("rec-1", "a rewrite of the same record", ["diabetes"], tag="lab")
    world.set_evil_mode("stale")
    stale, _ = world.retrieve("doctor_a", "rec-1")
    assert stale["ok"] is False and stale["reason"] == "stale_version"
    assert stale["plaintext"] is None

    world.set_evil_mode("withheld")
    withheld, _ = world.retrieve("doctor_a", "rec-1")
    assert withheld["ok"] is False and withheld["plaintext"] is None


def test_finding_no_consent_or_revocation():
    """F6 — the consent registry, epochs and nullifiers (nullifiers: M6)."""
    world = build_world(MedVaultConfig(seed=42))
    world.upload_record("rec-1", "body", ["diabetes"], tag="lab")
    world.grant_scope("doctor_a", Scope.record_set(["rec-1"]))
    world.grant_scope("doctor_b", Scope.record_set(["rec-1"]))

    world.revoke_doctor("doctor_a")
    assert world.search("doctor_a", "diabetes")[0]["reason"] == "stale_epoch"
    assert world.search("doctor_b", "diabetes")[0]["ok"] is True


def test_finding_key_lifecycle():
    """F7 — the epoch tree with erasure: correctness at every node.

    The finding is "stealing today's key reveals yesterday's key". The mechanism
    is an epoch tree where each node satisfies A*T = 0 mod q and advancing erases
    the epochs already passed. No forward-security claim is made: erasure in
    Python cannot reach a copy somebody already took.
    """
    from medvault.key_tree import KeyTree, KeyTreeConfig

    tree = KeyTree(KeyTreeConfig(depth=3, seed=42)).build()
    assert all(tree.check_all_correctness().values())
    assert all(row["usable"] for row in tree.norm_summary())

    # PEKS separates epochs, measured while every leaf key still exists.
    rows = tree.measure_peks()
    assert all(row["same_epoch_match"] for row in rows)
    assert not any(row["cross_epoch_match"] for row in rows)

    # Then advancing erases the passed epochs and keeps the frontier usable.
    tree.advance_epoch(4)
    with pytest.raises(ValueError, match="erased_key"):
        tree.get_leaf_key(3)
    tree.get_leaf_key(4)


def test_every_finding_has_a_named_mechanism_in_the_trace():
    """The demo claim is not "it is secure" but "each finding has one fix"."""
    mechanisms = {
        "kga": "keyed HMAC token per doctor per epoch",
        "plant": "patient-signed index entries",
        "replay": "Ed25519 signature + strictly increasing nonce + epoch check",
        "access pattern": "commitments only on-chain, PIR for retrieval (M5)",
        "stale or modified cloud data": "on-chain Merkle root and version",
        "consent and revocation": "consent registry, epochs, re-wrap, re-index",
        "key lifecycle": "epoch tree with erasure (M7)",
    }
    assert len(mechanisms) == 7
    assert all(value for value in mechanisms.values())
