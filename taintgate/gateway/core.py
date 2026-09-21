"""All transport adapters converge on this fail-closed call boundary."""
from dataclasses import dataclass
from typing import Any
import json
from jsonschema import Draft202012Validator
from mcp.types import JSONRPCMessage


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
        if contract.name in self.contracts:
            raise ValueError("Duplicate qualified tool identity")
        if contract.server in self.servers and self.servers[contract.server] is not upstream:
            raise ValueError("Server identity already bound to another session")
        self.contracts[contract.name] = contract
        self.servers[contract.server] = upstream

    def list_tools(self):
        # Remote data is deliberately not consulted by the planner interface.
        return [contract.planner_metadata() for contract in self.contracts.values()]

    async def call(self, name, arguments, *, context):
        if name not in self.contracts or not isinstance(arguments, dict):
            return GatewayResponse("deny", reason="Unknown tool or invalid arguments")
        try:
            json.dumps(arguments, allow_nan=False)
            Draft202012Validator(self.contracts[name].input_schema).validate(arguments)
        except (ValueError, TypeError, Exception) as error:
            return GatewayResponse("deny", reason="Arguments fail trusted schema")
        return GatewayResponse("deny", reason="Call boundary not configured")


def validate_rpc(payload):
    return JSONRPCMessage.model_validate(payload)
