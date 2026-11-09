"""M3 — KGA-resistant search and one-time authorisation (Properties 8-15)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from medvault.config import MedVaultConfig
from medvault.crypto import ed25519_keypair
from medvault.envelope import Scope
from medvault.gateway import GATE_POLICY, Gateway
from medvault.search import (
    IndexEntry,
    ModeAIndex,
    ModeBIndex,
    SearchNode,
    build_mode,
    compute_commitment,
    compute_token,
    entry_signing_message,
    normalize_keyword,
    search_signing_message,
    sign_search_request,
    verify_search_signature,
)
from medvault.service import build_world
from tests.medvault.helpers import make_sandbox

SETTINGS = settings(max_examples=100, deadline=None)

KEY = b"\x2a" * 32


# --------------------------------------------------------------------------
# Property 8: normalisation and token determinism
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 8: Token normalization idempotence and determinism
@SETTINGS
@given(text=st.text(min_size=0, max_size=40))
def test_property_8_normalisation_is_idempotent(text):
    once = normalize_keyword(text)
    assert normalize_keyword(once) == once
    assert len(compute_token(KEY, text)) == 32


# Feature: medvault-pq, Property 8: case and whitespace are irrelevant
@SETTINGS
@given(word=st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126),
                    min_size=0, max_size=20))
def test_property_8_case_and_whitespace_do_not_change_the_token(word):
    """'Diabetes', ' diabetes ', 'DIABETES' must map to one token.

    Restricted to printable ASCII on purpose. Unicode case folding is not a
    round trip ('ß'.upper() is 'SS', whose lowercase is 'ss'), so asserting
    case-insensitivity over arbitrary code points would be asserting something
    false. The keyword dictionary is ASCII, and that is the stated scope.
    """
    decorated = f"  {word.upper()}  "
    assert compute_token(KEY, decorated) == compute_token(KEY, word)
    assert compute_token(KEY, word) == compute_token(KEY, word)


def test_tokens_are_keyed_and_commitments_hide_the_token():
    keyword = "diabetes"
    first, second = compute_token(KEY, keyword), compute_token(b"\x2b" * 32, keyword)
    assert first != second, "the key must change the token"

    commitment = compute_commitment(first, nonce=1, epoch=0)
    assert first not in commitment
    assert len(commitment) == 32
    assert commitment != compute_commitment(first, nonce=2, epoch=0)


# --------------------------------------------------------------------------
# Property 9: index partitioning by doctor and epoch
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 9: Index partitioning by doctor and epoch
@SETTINGS
@given(doctor=st.sampled_from(["doctor_a", "doctor_b"]),
       epoch=st.integers(min_value=0, max_value=5),
       offset=st.integers(min_value=1, max_value=5),
       keyword=st.text(alphabet="abcdefgh ", min_size=1, max_size=12))
def test_property_9_index_partitioning(doctor, epoch, offset, keyword):
    signing = ed25519_keypair(seed=b"\x31" * 32, label="TEST_KEY:patient")
    index = ModeBIndex()
    node = SearchNode(require_patient_signature=True)
    node.trust_patient("patient", signing.public_key())
    entries = index.build([("rec-1", keyword)], index_key=KEY, epoch=epoch,
                          doctor_id=doctor, signing_key=signing)
    accepted, rejected = node.add_entries(entries, signing.public_key(), "patient")
    assert accepted and not rejected

    token = index.compute_token(KEY, keyword)
    assert node.search(token, doctor, epoch, index) == ["rec-1"]

    other_doctor = "doctor_b" if doctor == "doctor_a" else "doctor_a"
    assert node.search(token, other_doctor, epoch, index) == []
    assert node.search(token, doctor, epoch + offset, index) == []


# --------------------------------------------------------------------------
# Property 10: Ed25519 request signatures
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 10: Ed25519 signature verification round trip
@SETTINGS
@given(token=st.binary(min_size=32, max_size=32),
       nonce=st.integers(min_value=0, max_value=2**32),
       epoch=st.integers(min_value=0, max_value=4096),
       timestamp=st.integers(min_value=0, max_value=2**40))
def test_property_10_signature_round_trip_and_mutation(token, nonce, epoch, timestamp):
    signing = ed25519_keypair(seed=b"\x41" * 32, label="TEST_KEY:doctor")
    other = ed25519_keypair(seed=b"\x42" * 32, label="TEST_KEY:other")

    signature = sign_search_request(signing, token, nonce, epoch, timestamp)
    assert verify_search_signature(signing.public_key(), signature,
                                   token, nonce, epoch, timestamp)
    assert not verify_search_signature(other.public_key(), signature,
                                       token, nonce, epoch, timestamp)

    mutated_token = bytes([token[0] ^ 1]) + token[1:]
    assert not verify_search_signature(signing.public_key(), signature,
                                       mutated_token, nonce, epoch, timestamp)
    assert not verify_search_signature(signing.public_key(), signature,
                                       token, nonce + 1, epoch, timestamp)
    assert not verify_search_signature(signing.public_key(), signature,
                                       token, nonce, epoch + 1, timestamp)
    assert not verify_search_signature(signing.public_key(), signature,
                                       token, nonce, epoch, timestamp + 1)


def test_signing_message_covers_every_field():
    message = search_signing_message(b"t" * 32, 1, 2, 3)
    assert len(message) == 32 + 8 + 4 + 8
    assert len(entry_signing_message(b"t" * 32, "rec-1", 2, "doctor_a")) > 32


# --------------------------------------------------------------------------
# Property 11: nonce is strictly increasing, and only advances on acceptance
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 11: Nonce strictly increasing enforcement
@SETTINGS
@given(nonces=st.lists(st.integers(min_value=0, max_value=12), min_size=1, max_size=8))
def test_property_11_nonce_enforcement(nonces):
    world = make_sandbox("B")
    agent = world.doctors["doctor_a"]
    last_accepted = 0
    for nonce in nonces:
        request = agent.build_request(world.index, "diabetes", nonce=nonce,
                                      timestamp=world.ledger.now())
        result, _ = world.submit_request(request)
        should_accept = nonce > last_accepted
        assert result["ok"] is should_accept, f"nonce {nonce} after {last_accepted}"
        if should_accept:
            last_accepted = nonce
        else:
            assert result["reason"] == "reused_nonce"


def test_a_rejected_request_does_not_burn_the_nonce(world_with_record):
    """A rejection must not advance the accepted-nonce watermark."""
    agent = world_with_record.doctors["doctor_a"]
    epoch = agent.capability.epoch

    stale = agent.build_request(world_with_record.index, "diabetes", nonce=5,
                                timestamp=world_with_record.ledger.now())
    stale.epoch = epoch + 99
    stale.signature = sign_search_request(agent.signing_key, stale.token, stale.nonce,
                                          stale.epoch, stale.timestamp)
    assert world_with_record.submit_request(stale)[0]["reason"] == "stale_epoch"

    good = agent.build_request(world_with_record.index, "diabetes", nonce=5,
                               timestamp=world_with_record.ledger.now())
    assert world_with_record.submit_request(good)[0]["ok"] is True


# --------------------------------------------------------------------------
# Property 12: accept if and only if every gate passes
# --------------------------------------------------------------------------

def test_property_12_gate_sequence_rejects_each_failure(world_with_record):
    world = world_with_record
    agent = world.doctors["doctor_a"]
    epoch = agent.capability.epoch

    def submit(**overrides):
        request = agent.build_request(world.index, "diabetes",
                                      nonce=world.gateway.last_nonce("doctor_a") + 1,
                                      timestamp=world.ledger.now())
        for field, value in overrides.items():
            setattr(request, field, value)
        return world.submit_request(request)[0]

    # A valid request is accepted.
    assert submit()["reason"] == "accepted"

    # Bad signature: sign a different token than the one sent.
    request = agent.build_request(world.index, "diabetes", nonce=99,
                                  timestamp=world.ledger.now())
    request.signature = sign_search_request(agent.signing_key, b"\x00" * 32, 99,
                                            request.epoch, request.timestamp)
    assert world.submit_request(request)[0]["reason"] == "bad_signature"

    # Stale epoch, correctly signed for that epoch.
    request = agent.build_request(world.index, "diabetes", nonce=99,
                                  timestamp=world.ledger.now())
    request.epoch = epoch + 1
    request.signature = sign_search_request(agent.signing_key, request.token, 99,
                                            request.epoch, request.timestamp)
    assert world.submit_request(request)[0]["reason"] == "stale_epoch"

    # Out of scope: a scope hash nobody granted.
    request = agent.build_request(world.index, "diabetes", nonce=99,
                                  timestamp=world.ledger.now())
    request.scope_hash = b"\xee" * 32
    request.signature = sign_search_request(agent.signing_key, request.token, 99,
                                            request.epoch, request.timestamp)
    assert world.submit_request(request)[0]["reason"] == "out_of_scope"


def test_gate_policy_is_explicit():
    assert GATE_POLICY["A"] == ()
    assert set(GATE_POLICY["B"]) == {"signature", "epoch", "nonce", "scope"}


# --------------------------------------------------------------------------
# Property 13: only patient-signed entries are stored
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 13: Patient-signed entry enforcement
@SETTINGS
@given(keyword=st.text(alphabet="abcdefgh", min_size=1, max_size=8),
       signed=st.booleans(), foreign=st.booleans())
def test_property_13_patient_signed_entries(keyword, signed, foreign):
    patient = ed25519_keypair(seed=b"\x51" * 32, label="TEST_KEY:patient")
    other_patient = ed25519_keypair(seed=b"\x52" * 32, label="TEST_KEY:other")
    signer = other_patient if foreign else patient

    index = ModeBIndex()
    node = SearchNode(require_patient_signature=True)
    node.trust_patient("patient", patient.public_key())
    token = index.compute_token(KEY, keyword)
    signature = (signer.sign(entry_signing_message(token, "rec-1", 0, "doctor_a"))
                 if signed else b"")
    entry = IndexEntry(token, "rec-1", 0, "doctor_a", signature)

    accepted, reason = node.add_entry(entry, patient.public_key(), "patient")
    if signed and not foreign:
        assert accepted and reason == "accepted"
    elif not signed:
        assert not accepted and reason == "unsigned_entry"
    else:
        assert not accepted and reason in ("bad_entry_signature", "foreign_entry")


def test_foreign_patient_cannot_write_into_an_owned_index():
    patient = ed25519_keypair(seed=b"\x61" * 32, label="TEST_KEY:patient")
    intruder = ed25519_keypair(seed=b"\x62" * 32, label="TEST_KEY:intruder")
    index = ModeBIndex()
    node = SearchNode(require_patient_signature=True)
    node.trust_patient("patient", patient.public_key())

    first = index.build([("rec-1", "diabetes")], index_key=KEY, epoch=0,
                        doctor_id="doctor_a", signing_key=patient)
    assert node.add_entries(first, patient.public_key(), "patient")[0]

    token = index.compute_token(KEY, "asthma")
    forged = IndexEntry(token, "rec-2", 0, "doctor_a",
                        intruder.sign(entry_signing_message(token, "rec-2", 0, "doctor_a")))
    accepted, reason = node.add_entry(forged, patient.public_key(), "intruder")
    assert not accepted
    assert reason == "bad_entry_signature"


def test_mode_a_search_node_is_permissive_by_design(mode_a_world):
    """The baseline node does not require signatures — that is Finding 2."""
    assert mode_a_world.node.require_patient_signature is False
    entry = mode_a_world.index.universal_plant(0, "doctor_a")
    accepted, _ = mode_a_world.node.add_entry(entry, None, "attacker")
    assert accepted


# --------------------------------------------------------------------------
# Properties 14-15: KGA fails without the key
# --------------------------------------------------------------------------

def test_property_14_outsider_kga_fails_in_keyed_mode():
    from medvault.harness import run_kga

    result = run_kga("B", attacker="outsider")
    assert result["success"] is False
    assert result["success_rate_pct"] <= 2.0
    assert result["recovered_keyword"] is None


def test_property_15_keyless_server_kga_fails():
    from medvault.harness import run_kga

    result = run_kga("B", attacker="keyless_server")
    assert result["success"] is False
    assert result["success_rate_pct"] <= 2.0


def test_insider_kga_succeeds_and_is_reported_openly():
    from medvault.harness import run_kga

    result = run_kga("B", attacker="insider")
    assert result["success"] is True
    assert result["success_rate_pct"] == 100.0


def test_mode_a_kga_succeeds():
    from medvault.harness import run_kga

    result = run_kga("A", attacker="outsider")
    assert result["success"] is True
    assert result["recovered_keyword"] == "hypertension"


# --------------------------------------------------------------------------
# The rest of M3
# --------------------------------------------------------------------------

def test_replay_and_plant_differ_by_mode():
    from medvault.harness import run_plant, run_replay

    assert run_replay("A")["replay_ok"] is True
    assert run_replay("B")["replay_ok"] is False
    assert run_replay("B")["replay_reason"] == "reused_nonce"

    assert run_plant("A")["appears_in_search"] is True
    assert run_plant("B")["appears_in_search"] is False
    assert run_plant("B")["reason"] == "unsigned_entry"


def test_mode_selection_and_unknown_modes():
    assert build_mode("B").mode_name() == "B"
    # Mode C was a stub until Phase 6 (S2); it now builds the PAEKS-style index.
    assert build_mode("C").mode_name() == "C"
    with pytest.raises(ValueError):
        build_mode("Z")


def test_mode_a_index_rejects_missing_keys():
    index = ModeAIndex()
    with pytest.raises(RuntimeError):
        index.build([("rec-1", "kw")], index_key=None, epoch=0, doctor_id="doctor_a")


def test_search_returns_sorted_unique_record_ids(world_with_record):
    world_with_record.upload_record("rec-003", "another lab", ["diabetes"], tag="lab")
    result, _ = world_with_record.search("doctor_b", "diabetes")
    assert result["ok"] is True
    assert result["record_ids"] == sorted(set(result["record_ids"]))


def test_commitment_only_on_chain_in_mode_b(world_with_record):
    world_with_record.search("doctor_a", "diabetes")
    log = world_with_record.ledger.chain_log()
    token_hex = world_with_record.doctors["doctor_a"].last_request.token.hex()
    assert all(token_hex not in str(entry) for entry in log)
    assert any("commitment" in entry for entry in log)


def test_search_node_snapshot_has_no_tokens(world_with_record):
    snapshot = world_with_record.node.snapshot_for_audit()
    serialised = str(snapshot)
    request = world_with_record.doctors["doctor_a"].last_request
    if request is not None:
        assert request.token.hex() not in serialised


def test_retrieval_requires_scope(world_with_record):
    """Doctor A's tag scope does not cover the cardiology record."""
    result, _ = world_with_record.retrieve("doctor_a", "rec-002")
    assert result["ok"] is False
    assert result["reason"] == "out_of_scope"


def test_unknown_doctor_cannot_search(config):
    world = build_world(config)
    result, _ = world.search("doctor_z", "diabetes")
    assert result["ok"] is False
    assert result["reason"] == "no_capability"


def test_gateway_requires_a_key_resolver_for_signatures():
    world = build_world(MedVaultConfig(seed=7))
    gateway = Gateway(ledger=world.ledger, search_node=world.node, index=world.index,
                      mode="B", key_resolver=None)
    agent = world.doctors["doctor_a"]
    world.upload_record("rec-1", "body", ["diabetes"], tag="lab")
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    request = agent.build_request(world.index, "diabetes", nonce=1,
                                  timestamp=world.ledger.now())
    result = gateway.handle_search(request)
    assert result.ok is False and result.reason == "bad_signature"
