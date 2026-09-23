from fastapi.testclient import TestClient

from taintgate.ui.app import create_app


def test_authenticated_dry_run():
    api = create_app("synthetic-local-token")
    with TestClient(api) as client:
        assert client.post("/runs", json={"source": "x = 1"}).status_code == 401
        result = client.post(
            "/runs",
            json={"source": "x = 1"},
            headers={"Authorization": "Bearer synthetic-local-token"},
        )
        assert result.status_code == 200
        assert result.json()["status"] == "completed"
        assert (
            client.post(
                "/approvals",
                json={"scope": "a" * 64, "reason": "approve"},
                headers={"Authorization": "Bearer synthetic-local-token"},
            ).status_code
            == 409
        )
