"""The core API surface (M1-M4) mounted beside the PPSEB lab.

These tests exercise the router through FastAPI's test client, which is also the
path the UI takes, so a broken envelope shape is caught here rather than in a
screenshot.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import api as backend_api
from medvault import api_core
from medvault.zk import ZKAuthorisation
from ppseb.trace import EVENT_TYPES


@pytest.fixture
def client():
    api_core.SESSION["world"] = None
    return TestClient(backend_api.app)


def envelope_shape(body: dict) -> None:
    assert set(body) == {"result", "trace", "params"}
    assert isinstance(body["trace"], list)
    for event in body["trace"]:
        assert event["type"] in EVENT_TYPES
        assert set(event) == {"step", "type", "title", "detail", "data", "algo",
                              "highlight"}


def test_the_research_surface_is_still_there(client):
    """Requirement 8.1: adding the system layer must not disturb the lab."""
    assert client.get("/api/health").status_code == 200
    paths = {route.path for route in backend_api.app.routes}
    for path in ("/api/init", "/api/keyext", "/api/encrypt-search", "/api/attack/kga",
                 "/api/sweep/start", "/api/boundary/start"):
        assert path in paths
    assert any(path.startswith("/api/medvault") for path in paths)


def test_session_and_state(client):
    response = client.post("/api/medvault/session/new", json={"seed": 42, "mode": "B", "zk_mode": "signed"})
    assert response.status_code == 200
    body = response.json()
    envelope_shape(body)
    assert body["result"]["mode"] == "B"
    assert body["result"]["kem_label"]

    state = client.get("/api/medvault/state").json()
    assert state["result"]["epoch"] == 0
    assert state["result"]["ledger_backend"] == "memory-ledger"


def test_patient_doctor_round_trip(client):
    client.post("/api/medvault/session/new", json={"seed": 42, "mode": "B", "zk_mode": "signed"})

    upload = client.post("/api/medvault/patient/upload", json={
        "record_id": "rec-lab", "text": "hba1c 7.4 percent",
        "keywords": ["diabetes"], "tag": "lab",
    })
    assert upload.status_code == 200
    assert upload.json()["result"]["merkle_root"]

    grant = client.post("/api/medvault/patient/grant", json={
        "doctor_id": "doctor_a",
        "scope": {"kind": "record_tag", "tag": "lab"},
        "expiry_seconds": 86_400,
    })
    assert grant.status_code == 200
    assert grant.json()["result"]["opened_by_recipient"] is True

    search = client.post("/api/medvault/doctor/search",
                         json={"doctor_id": "doctor_a", "keyword": "Diabetes "})
    assert search.json()["result"]["record_ids"] == ["rec-lab"]
    envelope_shape(search.json())

    retrieve = client.post("/api/medvault/doctor/retrieve",
                           json={"doctor_id": "doctor_a", "record_id": "rec-lab"})
    assert retrieve.json()["result"]["ok"] is True
    assert "hba1c" in retrieve.json()["result"]["plaintext"]


def test_tamper_is_reported_through_the_api(client):
    client.post("/api/medvault/session/new", json={"seed": 42, "mode": "B", "zk_mode": "signed"})
    client.post("/api/medvault/patient/upload", json={
        "record_id": "rec-lab", "text": "body", "keywords": ["diabetes"], "tag": "lab"})
    client.post("/api/medvault/patient/grant", json={
        "doctor_id": "doctor_a", "scope": {"kind": "record_tag", "tag": "lab"},
        "expiry_seconds": 3600})
    client.post("/api/medvault/store/evil-mode", json={"mode": "modified"})

    response = client.post("/api/medvault/doctor/retrieve",
                           json={"doctor_id": "doctor_a", "record_id": "rec-lab"})
    result = response.json()["result"]
    assert result["ok"] is False
    assert result["plaintext"] is None
    assert result["reason"] == "content_hash_mismatch"
    assert any(e["data"].get("verdict") == "FAIL_CLOSED" for e in response.json()["trace"])


def test_bad_grant_is_a_400_with_a_reason(client):
    client.post("/api/medvault/session/new", json={"seed": 42, "mode": "B", "zk_mode": "signed"})
    response = client.post("/api/medvault/patient/grant", json={
        "doctor_id": "doctor_a", "scope": {"kind": "record_tag", "tag": "lab"},
        "expiry_seconds": 5,
    })
    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "expiry_out_of_range"


def test_attack_endpoint_returns_the_before_after_table(client):
    client.post("/api/medvault/session/new", json={"seed": 42, "mode": "B", "zk_mode": "signed"})
    response = client.post("/api/medvault/attack/run", json={"kind": "all", "mode": "both"})
    summary = response.json()["result"]["results"]["summary"]
    assert summary["kga_outsider_pct"] == {"A": 100.0, "B": 0.0}
    assert summary["replay_succeeds"] == {"A": True, "B": False}


def test_eval_tables_and_meta(client):
    client.post("/api/medvault/session/new", json={"seed": 42, "mode": "B", "zk_mode": "signed"})
    tables = client.get("/api/medvault/eval/tables").json()["result"]
    assert tables["kga_success"]["mode_B"]["outsider"] <= 2.0
    assert tables["meta"]["seed"] == 42

    meta = client.get("/api/medvault/system/meta").json()["result"]
    assert "do_not_say" in meta["claims"]
    # The interactive surface asks for the proof gate, so it is listed.
    assert meta["gate_policy"]["gates"] == ["signature", "epoch", "nonce", "scope", "proof"]
    zk = client.get("/api/medvault/zk/status").json()["result"]
    assert zk["public_inputs"] == ["root", "nullifier", "scope_id", "epoch_tag"]
    assert zk["mode"] in ("groth16", "signed")


def test_audit_endpoint_exposes_chain_without_tokens(client):
    client.post("/api/medvault/session/new", json={"seed": 42, "mode": "B", "zk_mode": "signed"})
    client.post("/api/medvault/patient/upload", json={
        "record_id": "rec-1", "text": "body", "keywords": ["diabetes"], "tag": "lab"})
    client.post("/api/medvault/patient/grant", json={
        "doctor_id": "doctor_a", "scope": {"kind": "record_tag", "tag": "lab"},
        "expiry_seconds": 3600})
    client.post("/api/medvault/doctor/search",
                json={"doctor_id": "doctor_a", "keyword": "diabetes"})

    payload = client.get("/api/medvault/audit/log").json()["result"]
    assert payload["audit"]
    assert payload["state"]["backend"] == "memory-ledger"
    token_hex = api_core.SESSION["world"].doctors["doctor_a"].last_request.token.hex()
    assert token_hex not in str(payload["chain"])


@pytest.fixture
def trace_paths(tmp_path, monkeypatch):
    """Point the demo's trace files at a temporary folder.

    Without this, running the suite rewrote the committed golden trace.
    """
    from medvault import demo
    golden, latest = tmp_path / "demo_trace.json", tmp_path / "demo_trace.latest.json"
    monkeypatch.setattr(demo, "GOLDEN_TRACE", golden)
    monkeypatch.setattr(demo, "LATEST_TRACE", latest)
    return golden, latest


def test_demo_endpoint_runs_the_whole_sequence(client, trace_paths):
    response = client.post("/api/medvault/system/demo-run?seed=42")
    report = response.json()["result"]
    golden, latest = trace_paths
    assert latest.exists() and golden.exists()
    assert report["trace_saved"]["promoted"] is True
    assert report["all_passed"] is True
    assert report["graded"] == 9     # all nine steps, none parked as pending
    assert report["pending"] == []
    assert report["within_ten_minutes"] is True
    assert all(step["ok"] for step in report["steps"])
    # Whatever mode the machine can run, the report names it honestly.
    assert "Groth16" in report["proof_mode"] or "not zero knowledge" in report["proof_mode"]


def test_demo_trace_endpoint_serves_golden_and_latest_separately(client, trace_paths):
    from medvault.demo import save_report
    golden, latest = trace_paths
    assert client.get("/api/medvault/system/demo-trace").status_code == 404

    save_report({"steps": [], "passed": 9, "graded": 9, "all_passed": True,
                 "pending": []}, golden)
    save_report({"steps": [], "passed": 7, "graded": 9, "all_passed": False,
                 "pending": []}, latest)

    body = client.get("/api/medvault/system/demo-trace").json()
    envelope_shape(body)
    assert body["result"]["passed"] == 9 and body["result"]["replayed_source"] == "golden"
    body = client.get("/api/medvault/system/demo-trace?source=latest").json()
    assert body["result"]["passed"] == 7 and body["result"]["replayed_source"] == "latest"
    assert client.get("/api/medvault/system/demo-trace?source=other").status_code == 422


@pytest.mark.skipif(not ZKAuthorisation.available(),
                    reason="Groth16 prover unavailable: run `npm --prefix circuits ci` (the build itself is committed)")
def test_session_auto_mode_uses_groth16_when_the_circuit_exists(client):
    api_core.SESSION["world"] = None
    body = client.post("/api/medvault/session/new",
                       json={"seed": 42, "mode": "B", "zk_mode": "auto"}).json()
    assert "Groth16" in body["result"]["proof_mode"]
    assert "proof" in body["result"]["gate_policy"]["gates"]
