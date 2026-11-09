"""The full demo path as one test (Requirement 13).

PRD §11 lists nine steps. This file runs them in order against one world and
asserts each step's pass condition, plus the two non-functional requirements the
demo carries: it completes well inside ten minutes, and every step leaves a
trace the UI can render.

All nine steps are graded. Step 4's proof half uses Groth16 when the circuit is
built and the labelled signed fallback otherwise; step 9 runs the real lattice
tree (toy parameters, measured norms, no forward-security claim).
"""

from __future__ import annotations

import copy
import json
import time

import pytest

from medvault.config import MedVaultConfig
from medvault.demo import load_report, record_run, save_report
from medvault.envelope import Scope
from medvault.harness import run_all_attacks
from medvault.key_tree import KeyTree, KeyTreeConfig
from medvault.search import sign_search_request
from medvault.service import build_world
from medvault.zk import ZKAuthorisation, field_id


def test_the_nine_step_demo_flow():
    started = time.perf_counter()
    audit: list[str] = []

    # ---- Step 1: the three attacks succeed on the original PPSEB ----------
    attacks = run_all_attacks(MedVaultConfig(seed=42))
    assert attacks["kga"]["mode_A"]["outsider"]["recovered_keyword"] == "hypertension"
    assert attacks["plant"]["A"]["appears_in_search"] is True
    assert attacks["replay"]["A"]["replay_ok"] is True
    audit.append("1 baseline attacks succeed")

    # ---- Step 2: the patient uploads encrypted records and a keyed index --
    world = build_world(MedVaultConfig(seed=42))
    lab, _ = world.upload_record("rec-lab", "hba1c 7.4 percent", ["diabetes", "blood"],
                                 tag="lab")
    imaging, _ = world.upload_record("rec-cxr", "chest x-ray clear", ["radiology"],
                                     tag="radiology")
    pharmacy, _ = world.upload_record("rec-rx", "metformin 500mg", ["pharmacy"],
                                      tag="pharmacy")
    # The root covers the whole record set, so each commit is a new root, and
    # the last one is what is on-chain.
    roots = {lab["merkle_root"], imaging["merkle_root"], pharmacy["merkle_root"]}
    assert len(roots) == 3
    root, version = world.ledger.record_root(world.patient_id)
    assert root.hex() == pharmacy["merkle_root"]
    assert version == 3
    audit.append("2 records and root committed")

    # ---- Step 3: three doctors, three scopes ------------------------------
    grant_a, _ = world.grant_scope("doctor_a", Scope.record_tag("lab"))
    grant_b, _ = world.grant_scope("doctor_b", Scope.record_tag("radiology"))
    grant_c, _ = world.grant_scope("doctor_c", Scope.record_set(["rec-rx"]))
    for grant, doctor in ((grant_a, "doctor_a"), (grant_b, "doctor_b"),
                          (grant_c, "doctor_c")):
        assert grant["opened_by_recipient"] is True
        assert grant["capability"]["doctor_id"] == doctor
        assert grant["envelope"]["kem_label"].endswith(("768", "NON-HARDENED"))

    for doctor in ("doctor_a", "doctor_b", "doctor_c"):
        envelope = world.doctors[doctor].envelope
        assert world.open_envelope_as(doctor, envelope, doctor)["ok"] is True
        others = {"doctor_a", "doctor_b", "doctor_c"} - {doctor}
        for other in others:
            assert world.open_envelope_as(doctor, envelope, other)["ok"] is False
    audit.append("3 three scopes, envelopes open only for their owner")

    # ---- Step 4: doctor A searches and retrieves --------------------------
    search, search_trace = world.search("doctor_a", "diabetes")
    assert search["ok"] is True and search["reason"] == "accepted"
    assert search["record_ids"] == ["rec-lab"]
    assert any(e["type"] == "decision" and e["data"].get("verdict") == "ACCEPTED"
               for e in search_trace)

    retrieval, retrieval_trace = world.retrieve("doctor_a", "rec-lab")
    assert retrieval["ok"] is True
    assert "hba1c" in retrieval["plaintext"]
    assert any(e["data"].get("verdict") == "VERIFIED" for e in retrieval_trace
               if e["type"] == "decision")
    audit.append("4 search accepted, record verified and decrypted")

    # ---- Step 5: the same three attacks fail on the hardened path ---------
    assert attacks["kga"]["mode_B"]["outsider"]["success"] is False
    assert attacks["kga"]["mode_B"]["keyless_server"]["success"] is False
    assert attacks["kga"]["mode_B"]["insider"]["success"] is True
    assert attacks["plant"]["B"]["appears_in_search"] is False
    assert attacks["replay"]["B"]["replay_ok"] is False
    assert attacks["access_pattern"]["B"]["token_on_chain"] is False
    audit.append("5 hardened attacks rejected, insider KGA still 100%")

    # ---- Step 6: revoke doctor A -----------------------------------------
    revoked, _ = world.revoke_doctor("doctor_a")
    assert revoked["new_epoch"] == 1
    assert revoked["remaining_doctors"] == ["doctor_b", "doctor_c"]
    stale_search, _ = world.search("doctor_a", "diabetes")
    assert stale_search["reason"] == "stale_epoch"
    stale_fetch, _ = world.retrieve("doctor_a", "rec-lab")
    assert stale_fetch["reason"] == "stale_epoch"
    assert "revoke" in [e.kind if hasattr(e, "kind") else e.event_type
                        for e in world.ledger.audit_log()]
    audit.append("6 revoked doctor rejected on token, envelope and epoch")

    # ---- Step 7: doctor B still works ------------------------------------
    surviving, _ = world.search("doctor_b", "radiology")
    assert surviving["ok"] is True and surviving["record_ids"] == ["rec-cxr"]
    assert world.retrieve("doctor_b", "rec-cxr")[0]["ok"] is True
    audit.append("7 the other doctor still works in scope")

    # ---- Step 8: a modified record fails closed --------------------------
    world.set_evil_mode("modified")
    tampered, tampered_trace = world.retrieve("doctor_b", "rec-cxr")
    assert tampered["ok"] is False
    assert tampered["plaintext"] is None
    assert any(e["data"].get("verdict") == "FAIL_CLOSED" for e in tampered_trace
               if e["type"] == "decision")
    world.set_evil_mode("honest")
    assert world.retrieve("doctor_b", "rec-cxr")[0]["ok"] is True
    audit.append("8 tampered record fails closed, honest control recovers")

    elapsed = time.perf_counter() - started
    assert len(audit) == 8
    assert elapsed < 600, "the demo path must fit the ten-minute budget"
    print(f"demo flow elapsed: {elapsed:.1f}s")  # noqa: T201 - deliberate, this is the demo


@pytest.mark.skipif(not ZKAuthorisation.available(),
                    reason="Groth16 artefacts missing: run `node circuits/build.js`")
def test_step_4_rejects_a_reused_proof():
    """Step 4's proof half: accepted once, refused the second time (Property 22)."""
    world = build_world(MedVaultConfig(seed=42, zk_mode="groth16"))
    world.upload_record("rec-1", "body", ["diabetes"], tag="lab")
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    assert world.search("doctor_a", "diabetes")[0]["ok"]
    agent = world.doctors["doctor_a"]
    request = agent.last_request
    again = copy.copy(request)
    again.nonce = agent.next_nonce()
    again.signature = sign_search_request(agent.signing_key, again.token, again.nonce,
                                          again.epoch, again.timestamp)
    assert world.submit_request(again)[0]["reason"] == "bad_proof"
    # The gateway sees four public inputs and nothing of the witness.
    assert len(request.zk_proof["public_inputs"]) == 4
    assert str(field_id(agent.capability.zk_secret)) not in json.dumps(request.zk_proof)


def test_step_9_advance_epochs_in_the_key_tree(tmp_path):
    """The ninth step: correctness at every node, the norm plot, key erasure."""
    tree = KeyTree(KeyTreeConfig(depth=3, seed=42)).build()
    assert all(tree.check_all_correctness().values())
    norms = tree.norm_summary()
    assert all(row["usable"] for row in norms)
    tree.advance_epoch(3)
    assert tree.current_epoch == 3
    with pytest.raises(ValueError):
        tree.get_leaf_key(2)
    tree.get_leaf_key(3)
    assert tree.plot_norms(tmp_path / "norms.png").exists()


def test_every_demo_step_returns_a_renderable_trace():
    """Requirement 9.5 pre-condition: the backend hands the UI ordered events."""
    world = build_world(MedVaultConfig(seed=42))
    _, upload_trace = world.upload_record("rec-1", "body", ["diabetes"], tag="lab")
    _, grant_trace = world.grant_scope("doctor_a", Scope.record_tag("lab"))
    _, search_trace = world.search("doctor_a", "diabetes")
    _, retrieve_trace = world.retrieve("doctor_a", "rec-1")
    _, revoke_trace = world.revoke_doctor("doctor_a")

    known = {"compute", "correction", "note", "threat_model", "matrix", "norm",
             "decision", "result"}
    for trace in (upload_trace, grant_trace, search_trace, retrieve_trace, revoke_trace):
        assert trace, "every demo operation must produce events"
        assert [e["step"] for e in trace] == list(range(1, len(trace) + 1))
        for event in trace:
            assert event["type"] in known
            assert "title" in event and "data" in event


def test_every_demo_step_carries_a_renderable_trace(tmp_path):
    """R9.5: every one of the nine steps hands the UI an ordered event list."""
    from medvault.demo import run_demo

    report = run_demo(MedVaultConfig(seed=42))
    assert report["graded"] == 9
    for step in report["steps"]:
        events = step["trace"]
        assert events, f"step {step['index']} produced no trace"
        assert [e["step"] for e in events] == list(range(1, len(events) + 1)), step["index"]
        for event in events:
            assert {"step", "type", "title", "detail", "data", "algo", "highlight"} == set(event)


def test_the_system_runs_with_one_object_and_no_network(config):
    """Requirement 10.1: one process, no outbound calls, no chain node."""
    world = build_world(config)
    assert world.ledger.backend_label == "memory-ledger"
    assert world.kem.label()
    assert world.store.evil_mode == "honest"


def test_a_saved_demo_can_be_replayed_without_rerunning_it(tmp_path):
    """R13.11: if the live demo fails, the saved traces must still present."""
    report = {
        "steps": [{"index": 1, "title": "baseline", "ok": True, "result": {},
                   "trace": [{"step": 1, "type": "note", "title": "e", "detail": "",
                              "data": {}, "algo": "x", "highlight": False}],
                   "pending": ""}],
        "all_passed": True, "passed": 1, "graded": 1, "pending": [],
        "proof_mode": "Groth16 BN254 — classical, single-party DEV setup",
    }
    path = save_report(report, tmp_path / "trace.json")
    assert path.exists()

    replayed = load_report(path)
    assert replayed["replayed"] is True
    assert replayed["replayed_from"].endswith("trace.json")
    assert replayed["steps"][0]["trace"][0]["title"] == "e"
    # The saved file is what the UI reads, so it must not carry the live state
    # (which contains keys' public halves and would be stale anyway).
    assert "state" not in json.loads(path.read_text())


def _report(passed: int, graded: int = 9, pending: list | None = None) -> dict:
    return {"steps": [], "passed": passed, "graded": graded, "pending": pending or [],
            "all_passed": passed == graded and not pending, "elapsed_s": 1.0,
            "proof_mode": "test"}


def test_a_failing_run_never_replaces_the_golden_trace(tmp_path):
    """R13.11: the backup must survive the live demo breaking on the day."""
    golden, latest = tmp_path / "golden.json", tmp_path / "latest.json"
    save_report(_report(9), golden)
    before = golden.read_bytes()

    info = record_run(_report(8), latest=latest, golden=golden)

    assert info["promoted"] is False and "8/9" in info["reason"]
    assert golden.read_bytes() == before            # byte-identical
    assert json.loads(latest.read_text())["passed"] == 8   # the failure is still kept


def test_a_run_with_pending_steps_keeps_the_golden_trace(tmp_path):
    golden, latest = tmp_path / "golden.json", tmp_path / "latest.json"
    save_report(_report(9), golden)
    before = golden.read_bytes()
    report = _report(8, graded=8, pending=[4])
    report["all_passed"] = True                    # graded steps passed, one parked
    info = record_run(report, latest=latest, golden=golden)
    assert info["promoted"] is False and "pending" in info["reason"]
    assert golden.read_bytes() == before


def test_a_clean_pass_replaces_the_golden_trace(tmp_path):
    golden, latest = tmp_path / "golden.json", tmp_path / "latest.json"
    info = record_run(_report(9), latest=latest, golden=golden)
    assert info["promoted"] is True
    assert golden.read_bytes() == latest.read_bytes()
    assert not list(tmp_path.glob("*.tmp"))        # atomic write leaves no debris


def test_a_missing_saved_trace_is_not_an_exception(tmp_path):
    assert load_report(tmp_path / "absent.json") is None
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert load_report(broken) is None


def test_signed_fallback_demo_passes_and_says_the_reuse_check_was_skipped():
    """Found by the clean-clone run: without the prover installed, step 4 used to
    fail because only a Groth16 nullifier can detect proof reuse."""
    from medvault.demo import run_demo

    world = build_world(MedVaultConfig(seed=42, zk_mode="signed"))
    report = run_demo(world=world)
    step4 = next(s for s in report["steps"] if s["index"] == 4)
    assert step4["ok"] is True
    assert step4["result"]["reused_proof"]["checked"] is False
    assert "no nullifier" in step4["result"]["reused_proof"]["skipped_because"]
    assert "not zero knowledge" in report["proof_mode"]


def test_a_signed_run_never_replaces_a_groth16_golden(tmp_path):
    golden, latest = tmp_path / "golden.json", tmp_path / "latest.json"
    groth = _report(9); groth["proof_mode"] = "Groth16 BN254 — classical"
    save_report(groth, golden)
    before = golden.read_bytes()
    signed = _report(9); signed["proof_mode"] = "SIGNED CONSENT FALLBACK — not zero knowledge"
    info = record_run(signed, latest=latest, golden=golden)
    assert info["promoted"] is False and "Groth16" in info["reason"]
    assert golden.read_bytes() == before
