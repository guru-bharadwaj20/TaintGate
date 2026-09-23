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


def test_non_ascii_auth_header_is_denied():
    api = create_app("local-token")
    import asyncio

    async def check():
        messages = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/runs",
            "raw_path": b"/runs",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"authorization", b"Bearer \xff")],
            "server": ("test", 80),
            "client": ("test", 1),
        }
        await api(scope, receive, send)
        assert messages[0]["status"] == 401

    asyncio.run(check())
