"""All transport adapters converge on this fail-closed call boundary."""
from dataclasses import dataclass
from typing import Any
import json
import asyncio
from jsonschema import Draft202012Validator
from mcp.types import JSONRPCMessage


@dataclass(frozen=True)
class GatewayResponse:
    status: str
    result: Any = None
    reason: str = ""


class Gateway:
    def __init__(self, guard, authorize=None, timeout=30, max_pending=32):
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        self.guard = guard
        self.authorize = authorize
        self.contracts = {}
        self.servers = {}
        self.pending = {}
        self.timeout = timeout
        if max_pending < 1:
            raise ValueError("Pending bound must be positive")
        self.max_pending = max_pending

    async def _execute(self, server, tool, arguments):
        try:
            async with asyncio.timeout(self.timeout):
                return GatewayResponse("allow", await self.servers[server].call_tool(tool, arguments))
        except TimeoutError:
            return GatewayResponse("error", reason="Upstream timed out")
        except Exception:
            return GatewayResponse("error", reason="Upstream unavailable")

    async def call_with_id(self, request_id, name, arguments, *, context):
        if len(self.pending) >= self.max_pending:
            return GatewayResponse("deny", reason="Gateway overloaded")
        if request_id in self.pending:
            return GatewayResponse("deny", reason="Duplicate active request")
        task = asyncio.create_task(self.call(name, arguments, context=context))
        self.pending[request_id] = task
        try:
            return await task
        finally:
            self.pending.pop(request_id, None)

    def cancel(self, request_id):
        task = self.pending.get(request_id)
        if task is not None:
            task.cancel()
            return True
        return False

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
