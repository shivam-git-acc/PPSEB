"""M1 — encrypted records and integrity (Properties 1-4, Requirement 1)."""

from __future__ import annotations

import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from medvault.blob_store import BlobStore
from medvault.crypto import aes_gcm_decrypt, aes_gcm_encrypt, new_dek, sha256
from medvault.envelope import Scope
from medvault.merkle import MerkleTree, MerkleProofStep

SETTINGS = settings(max_examples=100, deadline=None)


# --------------------------------------------------------------------------
# Property 1: AES-GCM round trip, fresh DEK every time
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 1: AES-GCM record encryption round trip
@SETTINGS
@given(plaintext=st.binary(min_size=0, max_size=2048))
def test_property_1_aes_gcm_round_trip(plaintext):
    first, second = new_dek(), new_dek()
    assert first != second, "each record must get a distinct DEK"
    assert aes_gcm_decrypt(first, aes_gcm_encrypt(first, plaintext)) == plaintext


def test_aes_gcm_rejects_a_modified_ciphertext():
    key = new_dek()
    sealed = bytearray(aes_gcm_encrypt(key, b"patient record"))
    sealed[-1] ^= 0x01
    with pytest.raises(Exception):
        aes_gcm_decrypt(key, bytes(sealed))


def test_aes_gcm_rejects_a_wrong_key():
    sealed = aes_gcm_encrypt(new_dek(), b"patient record")
    with pytest.raises(Exception):
        aes_gcm_decrypt(new_dek(), sealed)


# --------------------------------------------------------------------------
# Property 2: content addressing
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 2: Content-addressed storage correctness
@SETTINGS
@given(payload=st.binary(min_size=0, max_size=512))
def test_property_2_content_addressed_storage(payload):
    store = BlobStore()
    put = store.store("rec-1", payload, patient_id="p1")
    blob = store.head("p1", "rec-1")
    assert blob is not None
    assert put.content_hash == sha256(b"rec-1", blob.ciphertext).hex()
    fetched = store.get("p1", "rec-1")
    assert fetched.ok and fetched.blob.ciphertext == blob.ciphertext
    assert store.decrypt(put.dek, fetched.blob) == payload


def test_store_versions_increase_and_keep_history(config):
    store = BlobStore()
    first = store.store("rec-1", b"v1", patient_id="p1")
    second = store.store("rec-1", b"v2", patient_id="p1")
    assert (first.version, second.version) == (1, 2)
    assert store.head("p1", "rec-1").version == 2
    store.set_evil_mode("stale")
    stale = store.get("p1", "rec-1", expected_version=2)
    assert stale.blob.version == 1


# --------------------------------------------------------------------------
# Property 3: Merkle inclusion
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 3: Merkle tree inclusion round trip
@SETTINGS
@given(count=st.integers(min_value=1, max_value=24),
       payloads=st.lists(st.binary(min_size=32, max_size=32), min_size=1, max_size=24))
def test_property_3_merkle_inclusion(count, payloads):
    leaves = payloads[:count]
    root, proofs = MerkleTree.build(leaves)
    for leaf, proof in zip(leaves, proofs):
        assert MerkleTree.verify(leaf, proof, root)

    # A leaf that is not in the tree never verifies.
    outsider = sha256(b"not-a-leaf")
    assert not MerkleTree.verify(outsider, proofs[0], root)

    # A modified sibling never verifies.
    if proofs[0]:
        broken = list(proofs[0])
        broken[0] = MerkleProofStep(sha256(b"sibling"), broken[0].direction)
        assert not MerkleTree.verify(leaves[0], broken, root)

    # The root is deterministic for the same leaf set.
    assert MerkleTree.build(leaves)[0] == root


def test_empty_tree_root_is_not_vacuously_valid():
    root, proofs = MerkleTree.build([])
    assert root == b"\x00" * 32
    assert proofs == []


# --------------------------------------------------------------------------
# Property 4: fail closed on tampering
# --------------------------------------------------------------------------

# Feature: medvault-pq, Property 4: Fail-closed on tampering
@SETTINGS
@given(payload=st.binary(min_size=17, max_size=256))
def test_property_4_every_single_byte_change_is_detected(payload):
    """Any served byte change must break the content hash — for every position."""
    from medvault.config import MedVaultConfig
    from medvault.service import build_world

    world = build_world(MedVaultConfig(seed=42))
    world.upload_record("rec-1", payload.hex(), ["kw"])
    world.grant_scope("doctor_a", Scope.record_set(["rec-1"]))

    # Baseline: honest retrieval works, so a later failure means detection.
    assert world.retrieve("doctor_a", "rec-1")[0]["ok"]

    world.set_evil_mode("modified")
    result, trace = world.retrieve("doctor_a", "rec-1")
    assert result["ok"] is False
    assert result["plaintext"] is None
    assert result["reason"] == "content_hash_mismatch"
    assert any(e["type"] == "decision" and e["data"].get("verdict") == "FAIL_CLOSED"
               for e in trace)


def test_stale_version_fails_closed(world_with_record):
    world_with_record.upload_record("rec-001", "updated blood test", ["diabetes"], tag="lab")
    world_with_record.set_evil_mode("stale")
    result, _ = world_with_record.retrieve("doctor_b", "rec-001")
    assert result["ok"] is False
    assert result["reason"] == "stale_version"
    assert result["plaintext"] is None


def test_withheld_blob_fails_closed(world_with_record):
    world_with_record.set_evil_mode("withheld")
    result, _ = world_with_record.retrieve("doctor_a", "rec-001")
    assert result["ok"] is False
    assert result["reason"] == "withheld"
    assert result["plaintext"] is None


def test_honest_mode_is_the_control(world_with_record):
    world_with_record.set_evil_mode("honest")
    result, _ = world_with_record.retrieve("doctor_a", "rec-001")
    assert result["ok"] is True
    assert "diabetes" in result["plaintext"]


def test_merkle_root_and_version_are_committed(world_with_record):
    root, version = world_with_record.ledger.record_root(world_with_record.patient_id)
    assert root == world_with_record.root
    assert version == world_with_record.store.latest_version(world_with_record.patient_id)


def test_tampered_merkle_proof_fails_closed(world_with_record):
    """A proof that does not reach the on-chain root must not decrypt."""
    bundle = world_with_record._proofs["rec-001"]
    if bundle.proof:
        step = bundle.proof[0]
        world_with_record._proofs["rec-001"] = type(bundle)(
            bundle.record_id, bundle.content_hash, bundle.version,
            (MerkleProofStep(os.urandom(32), step.direction),) + bundle.proof[1:],
            bundle.root,
        )
    else:  # single-leaf tree: break the committed hash instead
        world_with_record._proofs["rec-001"] = type(bundle)(
            bundle.record_id, "00" * 32, bundle.version, bundle.proof, bundle.root)
    result, _ = world_with_record.retrieve("doctor_a", "rec-001")
    assert result["ok"] is False
    assert result["reason"] in ("merkle_proof_failed", "content_hash_mismatch")
