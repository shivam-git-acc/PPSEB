"""M2 — ML-KEM capability wrapping (Properties 5-7, Requirement 2)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from medvault.crypto import sha256
from medvault.envelope import (
    Capability,
    Scope,
    tamper,
    unwrap_capability,
    wrap_capability,
)
from medvault.kem import (
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    ML_KEM_768_SECRET_KEY_BYTES,
    get_kem_wrapper,
)

SETTINGS = settings(max_examples=100, deadline=None)

scopes = st.one_of(
    st.builds(lambda ids: Scope.record_set(sorted(ids)),
              st.lists(st.sampled_from(["rec-1", "rec-2", "rec-3"]), unique=True)),
    st.builds(Scope.record_tag, st.sampled_from(["lab", "cardio", "oncology"])),
)


def capability_strategy():
    return st.builds(
        Capability,
        doctor_id=st.sampled_from(["doctor_a", "doctor_b"]),
        patient_id=st.just("patient_alice"),
        epoch=st.integers(min_value=0, max_value=8),
        scope=scopes,
        index_key=st.binary(min_size=32, max_size=32),
        deks=st.dictionaries(st.sampled_from(["rec-1", "rec-2"]),
                             st.binary(min_size=32, max_size=32), max_size=2),
        zk_secret=st.binary(min_size=32, max_size=32),
    )


# --------------------------------------------------------------------------
# The wrapper itself
# --------------------------------------------------------------------------

def test_kem_wrapper_is_labelled():
    """A fallback must announce itself (Requirement 2.6, 16.x)."""
    label = get_kem_wrapper().label()
    assert label in ("liboqs-ml-kem-768", "pure-python-ml-kem-768-NON-HARDENED")
    if label.startswith("pure-python"):
        assert "NON-HARDENED" in label


def test_pure_python_ml_kem_768_round_trip_and_sizes(pure_kem):
    public_key, secret_key = pure_kem.keygen(seed=b"\x07" * 32)
    assert len(public_key) == ML_KEM_768_PUBLIC_KEY_BYTES
    assert len(secret_key) == ML_KEM_768_SECRET_KEY_BYTES

    ciphertext, shared = pure_kem.encaps(public_key, seed=b"\x09" * 32)
    assert len(ciphertext) == ML_KEM_768_CIPHERTEXT_BYTES
    assert pure_kem.decaps(secret_key, ciphertext) == shared


def test_pure_python_ml_kem_is_deterministic(pure_kem):
    first = pure_kem.keygen(seed=b"\x01" * 32)
    second = pure_kem.keygen(seed=b"\x01" * 32)
    assert first == second


def test_pure_python_ml_kem_wrong_key_does_not_raise(pure_kem):
    """ML-KEM implicit rejection: a wrong key gives a wrong secret, not an error."""
    public_key, _ = pure_kem.keygen(seed=b"\x02" * 32)
    _, other_secret = pure_kem.keygen(seed=b"\x03" * 32)
    ciphertext, shared = pure_kem.encaps(public_key, seed=b"\x04" * 32)
    assert pure_kem.decaps(other_secret, ciphertext) != shared


def test_pure_python_ml_kem_tampered_ciphertext_gives_a_different_secret(pure_kem):
    public_key, secret_key = pure_kem.keygen(seed=b"\x05" * 32)
    ciphertext, shared = pure_kem.encaps(public_key, seed=b"\x06" * 32)
    broken = bytearray(ciphertext)
    broken[100] ^= 0x01
    assert pure_kem.decaps(secret_key, bytes(broken)) != shared


# --------------------------------------------------------------------------
# Property 5: envelope round trip
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 5: Envelope wrap/unwrap round trip
@SETTINGS
@given(capability=capability_strategy(), kem_seed=st.binary(min_size=32, max_size=32))
def test_property_5_envelope_round_trip(capability, kem_seed, pure_kem):
    public_key, secret_key = pure_kem.keygen(seed=kem_seed)
    envelope = wrap_capability(public_key, capability, kem=pure_kem)
    result = unwrap_capability(secret_key, envelope, kem=pure_kem)
    assert result.ok, result.reason
    recovered = result.capability
    assert recovered.index_key == capability.index_key
    assert recovered.deks == capability.deks
    assert recovered.zk_secret == capability.zk_secret
    assert recovered.epoch == capability.epoch
    assert recovered.scope == capability.scope
    assert recovered.doctor_id == capability.doctor_id


# --------------------------------------------------------------------------
# Property 6: the wrong key opens nothing
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 6: Wrong ML-KEM key fails to open envelope
@SETTINGS
@given(capability=capability_strategy(), seed_a=st.binary(min_size=32, max_size=32),
       seed_b=st.binary(min_size=32, max_size=32))
def test_property_6_wrong_key_produces_no_capability(capability, seed_a, seed_b,
                                                     pure_kem):
    if seed_a == seed_b:
        seed_b = bytes(b ^ 0xFF for b in seed_b)
    public_key, _ = pure_kem.keygen(seed=seed_a)
    _, wrong_secret = pure_kem.keygen(seed=seed_b)
    envelope = wrap_capability(public_key, capability, kem=pure_kem)
    result = unwrap_capability(wrong_secret, envelope, kem=pure_kem)
    assert result.ok is False
    assert result.capability is None
    assert result.reason == "wrong_key_or_tampered"


# --------------------------------------------------------------------------
# Property 7: any modified byte fails authentication
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 7: Tampered envelope fails authentication
@SETTINGS
@given(capability=capability_strategy(), position=st.integers(min_value=0, max_value=400))
def test_property_7_tampered_envelope_produces_no_capability(capability, position,
                                                             pure_kem):
    public_key, secret_key = pure_kem.keygen(seed=b"\x11" * 32)
    envelope = wrap_capability(public_key, capability, kem=pure_kem)
    broken = tamper(envelope, position=position)
    result = unwrap_capability(secret_key, broken, kem=pure_kem)
    assert result.ok is False
    assert result.capability is None


def test_envelope_metadata_is_authenticated(world_with_record):
    """The mirrored epoch is only a hint; the payload's copy must agree."""
    envelope = world_with_record.doctors["doctor_a"].envelope
    forged = type(envelope)(
        kem_ciphertext=envelope.kem_ciphertext,
        sealed_payload=envelope.sealed_payload,
        epoch=envelope.epoch + 1,
        scope_hash=envelope.scope_hash,
        kem_label=envelope.kem_label,
        recipient_key_hash=envelope.recipient_key_hash,
    )
    result = unwrap_capability(world_with_record.doctors["doctor_a"].kem_secret,
                               forged, kem=world_with_record.kem)
    assert result.ok is False


def test_only_the_addressed_doctor_opens_the_envelope(world_with_record):
    envelope = world_with_record.doctors["doctor_a"].envelope
    intruder = world_with_record.open_envelope_as("doctor_a", envelope, "doctor_b")
    assert intruder["ok"] is False
    assert intruder["capability"] is None

    owner = world_with_record.open_envelope_as("doctor_a", envelope, "doctor_a")
    assert owner["ok"] is True
    assert owner["capability"]["doctor_id"] == "doctor_a"


def test_envelope_reports_its_kem_label(world_with_record):
    envelope = world_with_record.doctors["doctor_a"].envelope
    assert envelope.kem_label == get_kem_wrapper().label()


def test_scope_hash_is_stable_for_the_same_scope():
    first = Scope.record_set(["rec-2", "rec-1"])
    second = Scope.record_set(["rec-1", "rec-2"])
    assert first.scope_hash() == second.scope_hash()
    assert sha256(first.canonical_bytes()) == first.scope_hash()


def test_scope_kind_is_validated():
    with pytest.raises(ValueError):
        Scope("nonsense")
    with pytest.raises(ValueError):
        Scope("record_set", ("rec-1",), "lab")
