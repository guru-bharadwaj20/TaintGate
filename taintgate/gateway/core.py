"""All transport adapters converge on this fail-closed call boundary."""
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GatewayResponse:
    status: str
    result: Any = None
    reason: str = ""


class Gateway:
    def __init__(self, guard, authorize=None):
        self.guard = guard
        self.authorize = authorize
        self.contracts = {}
        self.servers = {}

    def register(self, contract, upstream):
        if contract.name != f"{contract.server}__{contract.tool}":
            raise ValueError("Tool is outside its approved namespace")
        self.contracts[contract.name] = contract
        self.servers[contract.server] = upstream

    def list_tools(self):
        # Remote data is deliberately not consulted by the planner interface.
        return [contract.planner_metadata() for contract in self.contracts.values()]

    async def call(self, name, arguments, *, context):
        return GatewayResponse("deny", reason="Call boundary not configured")
