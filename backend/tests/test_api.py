from fastapi.testclient import TestClient

from api import app

client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_full_flow():
    r = client.post("/api/init", json={"n": 4, "q": 257, "sigma": 4.0, "l": 10})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "shape_table" in body["result"]
    assert len(body["trace"]) > 0

    r = client.post("/api/keyext", json={"periods": 2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"]["max_period"] == 2

    r = client.post("/api/encrypt-search", json={
        "record": "Dx: diabetes, insulin prescribed",
        "keyword": "diabetes",
        "query_keyword": "diabetes",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"]["match"] is True
    assert body["result"]["decrypted_record"] == "Dx: diabetes, insulin prescribed"

    r = client.post("/api/encrypt-search", json={
        "record": "irrelevant",
        "keyword": "diabetes",
        "query_keyword": "asthma",
    })
    assert r.status_code == 200, r.text
    assert r.json()["result"]["match"] is False

    r = client.post("/api/attack/kga", json={
        "secret_keyword": "diabetes",
        "dictionary": ["flu", "asthma", "diabetes", "migraine"],
    })
    assert r.status_code == 200, r.text
    assert r.json()["result"]["recovered_keyword"] == "diabetes"

    r = client.post("/api/attack/forward", json={"J": 2, "h1_variant": "low_norm"})
    assert r.status_code == 200, r.text
    assert len(r.json()["result"]["rows"]) == 2

    r = client.post("/api/attack/spec", json={"periods": 2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"]["paper"]["success"] is False
    assert body["result"]["corrected"]["success"] is True


def test_init_rejects_invalid_params():
    r = client.post("/api/init", json={"n": 4, "q": 256, "sigma": 4.0, "l": 10})
    assert r.status_code == 422
