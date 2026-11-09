"""R6 / Properties 20-22: zero-knowledge authorisation (M6).

Two layers. The Poseidon and consent-tree tests need no toolchain and always run.
The Groth16 tests need the built circuit (`node circuits/build.js`) and skip with
that instruction otherwise — the signed fallback is tested separately and is
never counted as a zero-knowledge result.
"""

from __future__ import annotations

import copy
import json

import pytest
from hypothesis import given, settings, strategies as st

from medvault.config import MedVaultConfig
from medvault.envelope import Scope
from medvault.search import sign_search_request
from medvault.service import build_world
from medvault.zk import FIELD, ConsentTree, ZKAuthorisation, ZKError, field_id, poseidon

requires_groth16 = pytest.mark.skipif(
    not ZKAuthorisation.available(),
    reason="Groth16 prover unavailable: run `npm --prefix circuits ci` (the build itself is committed)",
)


# --------------------------------------------------------------------------
# Poseidon and the consent tree (no toolchain needed)
# --------------------------------------------------------------------------

def test_poseidon_matches_circomlibjs_reference_vectors():
    """Values produced by circomlibjs `buildPoseidon()`; a mismatch here means
    Python leaves would never match the circuit's leaves."""
    assert poseidon(1, 2) == int(
        "7853200120776062878684798364095072458815029376092732009249414926327459813530")
    assert poseidon(1, 2, 3) == int(
        "6542985608222806190361240322586112750744169038454362455181422643027100751666")


def test_poseidon_rejects_unsupported_arity():
    with pytest.raises(ZKError):
        poseidon(1)
    with pytest.raises(ZKError):
        poseidon(1, 2, 3, 4)


def _walk(leaf: int, elements: list[int], bits: list[int]) -> int:
    node = leaf
    for sibling, bit in zip(elements, bits):
        node = poseidon(sibling, node) if bit else poseidon(node, sibling)
    return node


@settings(max_examples=25, deadline=None, derandomize=True)
@given(count=st.integers(1, 16), secret=st.integers(1, FIELD - 1))
def test_property_20_every_live_leaf_has_a_path_to_the_root(count, secret):
    grants = [(f"d{i}", secret + i, 7, 0) for i in range(count)]
    tree = ConsentTree(grants)
    for doctor, s, scope, epoch in grants:
        elements, bits = tree.path(doctor)
        assert _walk(poseidon(s, scope, epoch), elements, bits) == tree.root


def test_revoked_leaf_is_absent_and_root_changes():
    before = ConsentTree([("a", 11, 7, 0), ("b", 12, 7, 0)])
    after = ConsentTree([("b", 12, 7, 1)])
    assert before.root != after.root
    assert "a" not in after.positions


def test_tree_capacity_is_enforced():
    with pytest.raises(ZKError):
        ConsentTree([(f"d{i}", i, 1, 0) for i in range(17)])


def test_field_id_is_reduced():
    assert 0 <= field_id(b"\xff" * 32) < FIELD


# --------------------------------------------------------------------------
# Signed fallback (labelled, never a ZK claim)
# --------------------------------------------------------------------------

def _world(zk_mode: str):
    world = build_world(MedVaultConfig(zk_mode=zk_mode))
    world.upload_record("r1", "hba1c 7.2", ["diabetes"], tag="lab")
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    world.grant_scope("doctor_b", Scope.record_tag("lab"))
    return world


def _resend(world, request, *, proof=None):
    """Re-sign a captured request with a fresh nonce, optionally swapping the proof.

    This isolates the proof gate: signature, epoch, nonce and scope all pass, so
    any rejection has to come from the proof or its nullifier.
    """
    agent = world.doctors[request.doctor_id]
    again = copy.copy(request)
    again.nonce = agent.next_nonce()
    again.signature = sign_search_request(agent.signing_key, again.token, again.nonce,
                                          again.epoch, again.timestamp)
    if proof is not None:
        again.zk_proof = proof
    return world.submit_request(again)[0]


def test_signed_fallback_is_labelled_not_zero_knowledge():
    world = _world("signed")
    assert "not zero knowledge" in world.zk.label
    assert "proof" in world.gateway.gate_policy()["gates"]
    assert world.search("doctor_a", "diabetes")[0]["ok"]


def test_signed_fallback_rejects_forged_and_missing_statements():
    world = _world("signed")
    world.search("doctor_a", "diabetes")
    request = world.doctors["doctor_a"].last_request
    forged = {"kind": "signed", "signature": "00" * 64}
    assert _resend(world, request, proof=forged)["reason"] == "bad_proof"
    assert _resend(world, request, proof={"kind": "signed"})["reason"] == "bad_proof"
    # Doctor B's statement does not authorise doctor A.
    world.search("doctor_b", "diabetes")
    other = world.doctors["doctor_b"].last_request.zk_proof
    assert _resend(world, request, proof=other)["reason"] == "bad_proof"


# --------------------------------------------------------------------------
# Real Groth16 (Properties 21-22)
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def groth16_world():
    if not ZKAuthorisation.available():
        pytest.skip("Groth16 prover unavailable: run `npm --prefix circuits ci` (the build itself is committed)")
    world = _world("groth16")
    first, _ = world.search("doctor_a", "diabetes")
    return world, first


@requires_groth16
def test_property_21_valid_proof_is_accepted(groth16_world):
    world, first = groth16_world
    assert first["ok"] and first["record_ids"] == ["r1"]
    assert world.ledger.nullifier_count() >= 1
    assert "Groth16" in world.zk.label and "DEV" in world.zk.label


@requires_groth16
def test_property_22_reused_nullifier_is_rejected(groth16_world):
    world, _ = groth16_world
    request = world.doctors["doctor_a"].last_request
    assert _resend(world, request)["reason"] == "bad_proof"


@requires_groth16
def test_tampered_public_input_is_rejected(groth16_world):
    world, _ = groth16_world
    request = world.doctors["doctor_a"].last_request
    tampered = copy.deepcopy(request.zk_proof)
    tampered["public_inputs"][1] = str((int(tampered["public_inputs"][1]) + 1) % FIELD)
    assert _resend(world, request, proof=tampered)["reason"] == "bad_proof"
    assert world.zk.verify_proof(tampered["proof"], tampered["public_inputs"]) is False


@requires_groth16
def test_malformed_proof_fails_closed_without_raising(groth16_world):
    world, _ = groth16_world
    request = world.doctors["doctor_a"].last_request
    for junk in ({"kind": "groth16", "proof": {}, "public_inputs": []},
                 {"kind": "groth16", "proof": {"pi_a": ["x"]}, "public_inputs": ["1"] * 4},
                 {"kind": "groth16"}, None):
        assert _resend(world, request, proof=junk or {})["reason"] == "bad_proof"


@requires_groth16
def test_proof_against_an_old_consent_root_is_rejected(groth16_world):
    world, _ = groth16_world
    agent = world.doctors["doctor_b"]
    nonce = agent.nonce_counter + 1
    stale = world.proof_for("doctor_b", nonce)           # proven against root R1
    world.grant_scope("doctor_c", Scope.record_tag("lab"))  # root moves to R2
    agent.proof_factory, saved = (lambda _n: stale), agent.proof_factory
    try:
        result, _ = world.search("doctor_b", "diabetes")
    finally:
        agent.proof_factory = saved
    assert result["reason"] == "bad_proof"
    # A fresh proof against the current root still works.
    assert world.search("doctor_b", "diabetes")[0]["ok"]


@requires_groth16
def test_proof_hides_the_witness(groth16_world):
    """R6.3: the secret, path and nonce are private inputs, so none of them
    appears in what the gateway or chain sees."""
    world, _ = groth16_world
    request = world.doctors["doctor_a"].last_request
    cap = world.doctors["doctor_a"].capability
    public = json.dumps(request.zk_proof)
    assert str(field_id(cap.zk_secret)) not in public
    assert len(request.zk_proof["public_inputs"]) == 4


@requires_groth16
def test_revoked_doctor_cannot_get_a_new_proof(groth16_world):
    world, _ = groth16_world
    world.revoke_doctor("doctor_a")
    assert "doctor_a" not in world.consent_tree.positions
    assert world.search("doctor_a", "diabetes")[0]["reason"] == "stale_epoch"
    assert world.search("doctor_b", "diabetes")[0]["ok"]


def test_auto_mode_falls_back_when_the_prover_package_is_missing(tmp_path, monkeypatch):
    """A fresh clone has the committed circuit build but not circuits/node_modules.

    Auto mode must then pick the labelled signed fallback, not Groth16 that fails
    at the first proof (found by the clean-clone run).
    """
    import medvault.zk as zk

    for rel in ("build/auth_js/auth.wasm", "build/auth_final.zkey",
                "build/verification_key.json", "build/setup_meta.json"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    monkeypatch.setattr(zk, "CIRCUITS", tmp_path)
    assert zk.ZKAuthorisation.available() is False
    assert zk.ZKAuthorisation("auto").mode == "signed"

    (tmp_path / "node_modules/snarkjs").mkdir(parents=True)
    (tmp_path / "node_modules/snarkjs/package.json").write_text("{}")
    assert zk.ZKAuthorisation.available() is (zk.shutil.which("node") is not None)
