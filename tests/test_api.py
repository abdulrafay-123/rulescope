from fastapi.testclient import TestClient

from rulescope.api import app

client = TestClient(app)


def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_analyze_sample():
    rules = client.get("/api/sample/rules").text
    profile = client.get("/api/sample/profile").json()
    res = client.post("/api/analyze", json={"rules_text": rules, "profile": profile})
    assert res.status_code == 200
    data = res.json()
    assert data["summary"]["total_rules"] >= 8
    assert data["rules"][0]["sid"]


def test_index():
    res = client.get("/")
    assert res.status_code == 200
    assert b"RuleScope" in res.content
