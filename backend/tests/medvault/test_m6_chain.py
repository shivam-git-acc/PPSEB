"""R4 (contract backend) / R6.5: the same consent workflow on a local chain.

These tests need a local Hardhat node on 127.0.0.1:8545 with chain id 31337 and
compiled artefacts. Without one they skip with the command to start it, because
a skipped chain test must never read as "the contract works".
"""

from __future__ import annotations

import pytest

from medvault.config import MedVaultConfig
from medvault.envelope import Scope
from medvault.service import build_world

web3 = pytest.importorskip("web3")


def chain_available() -> bool:
    from pathlib import Path

    from web3 import Web3

    artefacts = Path(__file__).resolve().parents[3] / "contracts" / "artifacts" / "src"
    if not all((artefacts / f"{name}.sol" / f"{name}.json").exists()
               for name in ("ConsentRegistry", "ZKVerifier", "Groth16Verifier")):
        return False
    try:
        node = Web3(Web3.HTTPProvider("http://127.0.0.1:8545", request_kwargs={"timeout": 2}))
        return node.is_connected() and node.eth.chain_id == 31337
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not chain_available(),
    reason="no local chain: run `npm --prefix contracts run compile` and "
           "`npm --prefix contracts run node`",
)


@pytest.fixture(scope="module")
def world():
    # Each world deploys its own three contracts, so modules are independent.
    world = build_world(MedVaultConfig(zk_mode="signed", ledger_mode="hardhat"))
    world.upload_record("r1", "hba1c 7.2", ["diabetes"], tag="lab")
    world.upload_record("r2", "x-ray clear", ["radiology"], tag="radiology")
    return world


def test_contract_state_is_authoritative(world):
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    assert world.ledger.has_valid_grant(
        "doctor_a", Scope.record_tag("lab").scope_hash(), world.ledger.current_epoch(world.patient_id))
    # A scope that was never granted is refused by the contract, not by Python.
    assert not world.ledger.has_valid_grant(
        "doctor_b", Scope.record_tag("radiology").scope_hash(), 0)


def test_grant_and_search_commit_a_receipt(world):
    world.grant_scope("doctor_b", Scope.record_tag("radiology"))
    result, _ = world.search("doctor_b", "radiology")
    assert result["ok"] and result["record_ids"] == ["r2"]
    events = [e["type"] for e in world.ledger.chain_log()]
    assert "Granted" in events and "SearchCommitted" in events
    assert any(r["operation"] == "search_with_proof" or r["operation"] == "search"
               for r in world.ledger.gas_receipts)


def test_revocation_bumps_the_epoch_on_chain(world):
    before = world.ledger.current_epoch(world.patient_id)
    world.revoke_doctor("doctor_a")
    after = world.ledger.current_epoch(world.patient_id)
    assert after == before + 1
    events = [e["type"] for e in world.ledger.chain_log()]
    assert "Revoked" in events and "EpochChanged" in events
    assert world.search("doctor_a", "diabetes")[0]["reason"] == "stale_epoch"
    assert world.search("doctor_b", "radiology")[0]["ok"]


def test_withdrawal_capability_is_still_a_documented_limit(world):
    """R4.16: revocation stops the gateway, not the doctor's own copy."""
    assert world.doctors["doctor_a"].capability is not None
    assert world.retrieve("doctor_a", "r1")[0]["ok"] is False


def test_record_root_matches_the_chain(world):
    on_chain_root, on_chain_version = world.ledger.record_root(world.patient_id)
    assert on_chain_root == world.root
    assert on_chain_version == world.version


def test_chain_rejects_a_non_increasing_version(world):
    from medvault.consent import ConsentError

    root, version = world.ledger.record_root(world.patient_id)
    with pytest.raises(ConsentError):
        world.ledger.put_record(world.patient_id, root, version)


def test_gas_is_recorded_for_every_operation(world):
    operations = {receipt["operation"] for receipt in world.ledger.gas_receipts}
    assert {"deploy_ConsentRegistry", "grant", "revoke", "register_doctor"} <= operations
    assert all(receipt["gas"] > 21_000 for receipt in world.ledger.gas_receipts
               if not receipt["operation"].startswith("deploy_"))


def test_chain_log_carries_no_record_ids(world):
    import json

    log = json.dumps(world.ledger.chain_log())
    assert "r1" not in log and "diabetes" not in log


@pytest.mark.parametrize("mode", ["A", "C"])
def test_proofless_modes_run_on_the_chain_with_auto_proof_mode(mode):
    """Modes A and C have no ZK verifier at the gateway and send no proof.

    With zk_mode="auto" (the UI default) their contract used to be deployed
    with requireProof, so the first search failed with missing_proof. Only
    mode B, which carries proofs, may deploy a proof-requiring contract.
    """
    world = build_world(MedVaultConfig(seed=42, index_mode=mode, ledger_mode="hardhat",
                                       zk_mode="auto"), mode=mode)
    assert world.ledger.require_proof is False
    world.upload_record("r1", "body", ["diabetes"], tag="lab")
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    search, _ = world.search("doctor_a", "diabetes")
    assert search["ok"] is True and search["record_ids"] == ["r1"]
    assert world.retrieve("doctor_a", "r1")[0]["ok"] is True
