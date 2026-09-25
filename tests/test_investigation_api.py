from fastapi.testclient import TestClient

from app.main import app
from simulator.linux_auth import ssh_brute_force_investigation_scenario


def test_api_creates_a_batch_and_transitions_an_in_memory_investigation():
    client = TestClient(app)

    created = client.post("/investigations", json={"events": ssh_brute_force_investigation_scenario()})

    assert created.status_code == 200
    investigation = created.json()["investigations"][0]
    assert investigation["status"] == "OPEN"
    assert investigation["outcome"] is None
    investigation_id = investigation["investigation_id"]

    started = client.post(f"/investigations/{investigation_id}/start")
    resolved = client.post(
        f"/investigations/{investigation_id}/resolve",
        json={"outcome": "TRUE_POSITIVE"},
    )

    assert started.status_code == 200
    assert started.json()["status"] == "INVESTIGATING"
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "RESOLVED"
    assert resolved.json()["outcome"] == "TRUE_POSITIVE"


def test_api_returns_404_and_409_for_missing_or_invalid_lifecycle_requests():
    client = TestClient(app)
    assert client.get("/investigations/not-found").status_code == 404
    assert client.post("/investigations/not-found/start").status_code == 404

    created = client.post("/investigations", json={"events": ssh_brute_force_investigation_scenario()})
    investigation_id = created.json()["investigations"][0]["investigation_id"]
    assert client.post(
        f"/investigations/{investigation_id}/resolve",
        json={"outcome": "TRUE_POSITIVE"},
    ).status_code == 409
    assert client.post(
        f"/investigations/{investigation_id}/resolve",
        json={"outcome": "NOT_AN_OUTCOME"},
    ).status_code == 422
    assert client.post(f"/investigations/{investigation_id}/resolve", json={}).status_code == 422
