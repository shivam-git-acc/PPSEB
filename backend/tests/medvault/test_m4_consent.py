"""M4 — consent, revocation and audit (Property 16, Requirements 4 and 11)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from medvault.config import MedVaultConfig
from medvault.consent import (
    MAX_BREAK_GLASS_SECONDS,
    MAX_GRANT_SECONDS,
    MIN_GRANT_SECONDS,
    ConsentError,
    MemoryConsentLedger,
    justification_hash,
)
from medvault.envelope import Scope
from medvault.search import compute_token
from medvault.service import build_world
from tests.medvault.helpers import make_sandbox

SETTINGS = settings(max_examples=100, deadline=None)


def register(ledger: MemoryConsentLedger, doctor_id: str = "doctor_a") -> None:
    ledger.register_doctor(doctor_id, b"\x01" * 32, b"\x02" * 32)


# --------------------------------------------------------------------------
# Property 16: the audit log is chronological and complete
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 16: Audit log chronological order
@SETTINGS
@given(operations=st.lists(
    st.tuples(st.sampled_from(["grant", "revoke"]),
              st.sampled_from(["doctor_a", "doctor_b", "doctor_c"])),
    min_size=1, max_size=8))
def test_property_16_audit_log_is_chronological(operations):
    ledger = MemoryConsentLedger()
    for doctor in ("doctor_a", "doctor_b", "doctor_c"):
        register(ledger, doctor)

    expect_grant_events = 0
    expect_revoke_events = 0
    for kind, doctor in operations:
        if kind == "grant":
            ledger.grant("patient", doctor, Scope.record_set(["rec-1"]), 3600)
            expect_grant_events += 1
        else:
            grant = ledger.get_grant("patient", doctor)
            if grant is None or grant.revoked:
                continue
            ledger.revoke("patient", doctor)
            expect_revoke_events += 1

    log = ledger.audit_log()
    # Event ids are strictly increasing, which is what "chronological" means for
    # an append-only log.
    assert [event.event_id for event in log] == list(range(1, len(log) + 1))
    assert [event.timestamp for event in log] == sorted(event.timestamp for event in log)

    grants = [e for e in log if e.event_type == "grant"]
    revokes = [e for e in log if e.event_type == "revoke"]
    assert len(grants) == expect_grant_events
    assert len(revokes) == expect_revoke_events
    # Every revocation is followed by the epoch change it caused.
    for event in revokes:
        later = [e for e in log if e.event_id > event.event_id
                 and e.event_type == "epoch_change" and e.doctor_id == event.doctor_id]
        assert later, "a revocation must be followed by an epoch_change event"


def test_registration_grant_and_revocation_are_all_logged():
    ledger = MemoryConsentLedger()
    register(ledger)
    ledger.grant("patient", "doctor_a", Scope.record_tag("lab"), 3600)
    ledger.revoke("patient", "doctor_a")
    kinds = [event.event_type for event in ledger.audit_log()]
    assert kinds == ["doctor_registered", "grant", "revoke", "epoch_change"]


# --------------------------------------------------------------------------
# Expiry bounds (Requirement 4.2)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("expiry", [MIN_GRANT_SECONDS, 86_400, MAX_GRANT_SECONDS])
def test_expiry_inside_the_range_is_accepted(expiry):
    ledger = MemoryConsentLedger()
    register(ledger)
    grant = ledger.grant("patient", "doctor_a", Scope.record_set(["rec-1"]), expiry)
    assert grant.expiry_seconds == expiry


@pytest.mark.parametrize("expiry", [MIN_GRANT_SECONDS - 1, 0, -5, MAX_GRANT_SECONDS + 1])
def test_expiry_outside_the_range_is_rejected(expiry):
    ledger = MemoryConsentLedger()
    register(ledger)
    with pytest.raises(ConsentError) as excinfo:
        ledger.grant("patient", "doctor_a", Scope.record_set(["rec-1"]), expiry)
    assert excinfo.value.reason == "expiry_out_of_range"


def test_an_expired_grant_stops_working():
    ledger = MemoryConsentLedger()
    register(ledger)
    ledger.grant("patient", "doctor_a", Scope.record_set(["rec-1"]), MIN_GRANT_SECONDS)
    scope_hash = Scope.record_set(["rec-1"]).scope_hash()
    assert ledger.has_valid_grant("doctor_a", scope_hash, 0)
    ledger.advance_clock(MIN_GRANT_SECONDS + 1)
    assert not ledger.has_valid_grant("doctor_a", scope_hash, 0)
    assert ledger.active_doctors("patient") == []


# --------------------------------------------------------------------------
# Break-glass (Requirement 4.12, P1)
# --------------------------------------------------------------------------

def test_break_glass_accepts_the_boundary_and_requires_a_justification():
    ledger = MemoryConsentLedger()
    register(ledger)
    grant = ledger.emergency_grant("patient", "doctor_a", Scope.record_set(["rec-1"]),
                                   justification_hash("cardiac arrest"), MAX_BREAK_GLASS_SECONDS)
    assert grant.is_break_glass
    assert grant.expiry_seconds == MAX_BREAK_GLASS_SECONDS

    with pytest.raises(ConsentError) as excinfo:
        ledger.emergency_grant("patient", "doctor_b", Scope.record_set(["rec-1"]),
                               justification_hash("x"), MAX_BREAK_GLASS_SECONDS + 1)
    assert excinfo.value.reason == "expiry_out_of_range"

    with pytest.raises(ConsentError) as excinfo:
        ledger.emergency_grant("patient", "doctor_c", Scope.record_set(["rec-1"]),
                               b"", 600)
    assert excinfo.value.reason == "missing_justification"


# --------------------------------------------------------------------------
# Revocation semantics
# --------------------------------------------------------------------------

def test_revocation_increments_the_epoch_and_emits_events():
    ledger = MemoryConsentLedger()
    register(ledger)
    ledger.grant("patient", "doctor_a", Scope.record_set(["rec-1"]), 3600)
    assert ledger.current_epoch("patient") == 0
    new_epoch, _timestamp = ledger.revoke("patient", "doctor_a")
    assert new_epoch == 1
    assert ledger.current_epoch("patient") == 1


def test_revoking_twice_is_refused():
    ledger = MemoryConsentLedger()
    register(ledger)
    ledger.grant("patient", "doctor_a", Scope.record_set(["rec-1"]), 3600)
    ledger.revoke("patient", "doctor_a")
    with pytest.raises(ConsentError) as excinfo:
        ledger.revoke("patient", "doctor_a")
    assert excinfo.value.reason == "already_revoked"


def test_grant_to_an_unregistered_doctor_is_still_recorded_but_checkable():
    """The registry does not gate on registration; the gateway gates on the grant."""
    ledger = MemoryConsentLedger()
    ledger.grant("patient", "doctor_x", Scope.record_set(["rec-1"]), 3600)
    assert ledger.get_grant("patient", "doctor_x") is not None


def test_reissue_grant_moves_a_surviving_grant_to_the_new_epoch():
    ledger = MemoryConsentLedger()
    register(ledger, "doctor_a")
    register(ledger, "doctor_b")
    ledger.grant("patient", "doctor_a", Scope.record_set(["rec-1"]), 3600)
    ledger.grant("patient", "doctor_b", Scope.record_set(["rec-1"]), 3600)
    new_epoch, _ = ledger.revoke("patient", "doctor_a")
    scope_hash = Scope.record_set(["rec-1"]).scope_hash()

    assert not ledger.has_valid_grant("doctor_b", scope_hash, new_epoch)
    ledger.reissue_grant("patient", "doctor_b", new_epoch)
    assert ledger.has_valid_grant("doctor_b", scope_hash, new_epoch)


# --------------------------------------------------------------------------
# The demo scenario: revoke A, B keeps working (Requirements 4.13, 4.14, 11.5)
# --------------------------------------------------------------------------

def test_revoked_doctor_is_rejected_and_the_other_still_works(world_with_record):
    world = world_with_record
    assert world.search("doctor_a", "diabetes")[0]["ok"]
    assert world.search("doctor_b", "diabetes")[0]["ok"]

    revoke, _ = world.revoke_doctor("doctor_a")
    assert revoke["remaining_doctors"] == ["doctor_b"]

    # A holds the old capability: the epoch gate rejects it.
    stale, _ = world.search("doctor_a", "diabetes")
    assert stale["ok"] is False
    assert stale["reason"] == "stale_epoch"

    # A's old token is useless even to the raw index: the revoked doctor's
    # index epochs were erased as part of the rotation.
    stale_token = compute_token(world.doctors["doctor_a"].capability.index_key, "diabetes")
    assert world.node.search(stale_token, "doctor_a", 0, world.index) == []

    # And a retrieval with the stale capability is refused.
    retrieval, _ = world.retrieve("doctor_a", "rec-001")
    assert retrieval["ok"] is False
    assert retrieval["reason"] == "stale_epoch"

    # B was re-granted at the new epoch and still works.
    fresh, _ = world.search("doctor_b", "diabetes")
    assert fresh["ok"] is True
    assert fresh["record_ids"] == ["rec-001"]
    assert world.retrieve("doctor_b", "rec-001")[0]["ok"] is True


def test_revocation_cost_is_measured(world_with_record):
    revoke, _ = world_with_record.revoke_doctor("doctor_a")
    cost = revoke["cost"]
    for key in ("time_ms", "transactions", "re_key_ops", "re_wrap_ops", "re_index_ops"):
        assert key in cost
    assert cost["time_ms"] > 0
    assert cost["transactions"] == 1
    assert cost["re_key_ops"] >= 1
    assert cost["re_wrap_ops"] >= 1
    assert cost["re_index_ops"] >= 1


def test_revocation_erases_the_revoked_doctors_index(world_with_record):
    before = world_with_record.node.entries("doctor_a", 0)
    assert before
    revoke, _ = world_with_record.revoke_doctor("doctor_a")
    assert revoke["cost"]["dropped_entries"] == len(before)
    assert world_with_record.node.entries("doctor_a", 0) == []


def test_revocation_cannot_recall_what_the_doctor_already_downloaded(world_with_record):
    """The documented limit (Requirement 4.16), asserted rather than implied."""
    assert world_with_record.retrieve("doctor_a", "rec-001")[0]["ok"] is True
    held_dek = world_with_record.doctors["doctor_a"].capability.deks["rec-001"]
    world_with_record.revoke_doctor("doctor_a")
    # The capability the doctor already holds still opens the blob they fetched.
    assert world_with_record.store.decrypt(
        held_dek, world_with_record.store.head("patient_alice", "rec-001")) == b"blood test: diabetes type 2"


# --------------------------------------------------------------------------
# Auditor view
# --------------------------------------------------------------------------

def test_auditor_view_shows_the_sequence_without_secrets(world_with_record):
    world_with_record.search("doctor_a", "diabetes")
    world_with_record.revoke_doctor("doctor_a")
    view = world_with_record.ledger.audit_view()
    kinds = [event["type"] for event in view]
    # A, B, and B's re-issue at the new epoch: three grant events, in order.
    assert kinds.count("grant") == 3
    assert "revoke" in kinds and "epoch_change" in kinds and "search_commitment" in kinds

    serialised = str(view)
    doctor = world_with_record.doctors["doctor_a"]
    assert doctor.capability.index_key.hex() not in serialised
    assert doctor.kem_secret.hex() not in serialised
    assert world_with_record.patient_signing.private_bytes.hex() not in serialised


def test_doctor_registration_is_bound_to_the_key_hashes():
    ledger = MemoryConsentLedger()
    ledger.register_doctor("doctor_a", b"\x01" * 32, b"\x02" * 32)
    ledger.register_doctor("doctor_a", b"\x01" * 32, b"\x02" * 32)  # idempotent
    with pytest.raises(ConsentError):
        ledger.register_doctor("doctor_a", b"\x09" * 32, b"\x02" * 32)


def test_three_doctors_get_three_different_scopes(world):
    world.upload_record("rec-lab", "lab result", ["diabetes"], tag="lab")
    world.upload_record("rec-img", "mri scan", ["radiology"], tag="radiology")
    world.upload_record("rec-rx", "prescription", ["pharmacy"], tag="pharmacy")
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    world.grant_scope("doctor_b", Scope.record_tag("radiology"))
    world.grant_scope("doctor_c", Scope.record_set(["rec-rx"]))

    assert world.retrieve("doctor_a", "rec-lab")[0]["ok"] is True
    assert world.retrieve("doctor_a", "rec-img")[0]["reason"] == "out_of_scope"
    assert world.retrieve("doctor_b", "rec-img")[0]["ok"] is True
    assert world.retrieve("doctor_c", "rec-rx")[0]["ok"] is True
    assert world.retrieve("doctor_c", "rec-lab")[0]["reason"] == "out_of_scope"


def test_envelopes_are_one_per_doctor_and_open_only_for_them(world):
    world.upload_record("rec-1", "body", ["diabetes"], tag="lab")
    for doctor in ("doctor_a", "doctor_b", "doctor_c"):
        world.grant_scope(doctor, Scope.record_tag("lab"))

    for doctor in ("doctor_a", "doctor_b", "doctor_c"):
        envelope = world.doctors[doctor].envelope
        assert world.open_envelope_as(doctor, envelope, doctor)["ok"] is True
        for other in ("doctor_a", "doctor_b", "doctor_c"):
            if other == doctor:
                continue
            assert world.open_envelope_as(doctor, envelope, other)["ok"] is False


def test_record_commit_requires_an_increasing_version():
    ledger = MemoryConsentLedger()
    ledger.put_record("patient", b"\x01" * 32, 1)
    ledger.put_record("patient", b"\x02" * 32, 2)
    with pytest.raises(ConsentError) as excinfo:
        ledger.put_record("patient", b"\x03" * 32, 2)
    assert excinfo.value.reason == "version_not_increasing"


def test_backend_label_is_stated():
    ledger = MemoryConsentLedger()
    assert ledger.backend_label == "memory-ledger"


def test_world_config_is_deterministic_for_the_same_seed():
    first = make_sandbox("B", seed=11)
    second = make_sandbox("B", seed=11)
    assert first.root == second.root
    assert (first.store.get_all_content_hashes("patient_alice")
            == second.store.get_all_content_hashes("patient_alice"))
    assert first.doctors["doctor_a"].capability.index_key == \
        second.doctors["doctor_a"].capability.index_key
