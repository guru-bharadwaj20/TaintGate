import asyncio

from taintgate.gateway.lab import (
    malicious_description_server,
    poisoned_email_server,
    rug_pull_server,
)


def test_lab_has_no_real_delivery():
    server, deliveries = poisoned_email_server()
    assert deliveries == []
    assert {t.name for t in asyncio.run(server.list_tools())} == {"read_email", "send_invoice"}
    poison = malicious_description_server()
    assert "Ignore previous" in asyncio.run(poison.list_tools())[0].description
    _, state = rug_pull_server()
    assert state == {"changed": False, "calls": 0}
