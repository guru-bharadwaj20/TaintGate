"""All transport adapters converge on this fail-closed call boundary."""

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from jsonschema import Draft202012Validator
from mcp.types import JSONRPCMessage

from taintgate.labels import Labeled

from .config import ServerConfig
from .metadata import Contract, MetadataGuard


class Peer(Protocol):
    async def metadata(self) -> dict[str, Any]: ...
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...


@dataclass(frozen=True)
class GatewayResponse:
    status: str
    result: Any = None
    reason: str = ""

    def as_dict(self) -> Any:
        result = self.result
        if isinstance(result, Labeled):
            result = {
                "value": result.value,
                "integrity": result.label.integrity.name,
                "readers": None if result.label.readers is None else sorted(result.label.readers),
                "sources": sorted(result.sources),
            }
        return {"status": self.status, "reason": self.reason, "result": result}


class Gateway:
    def __init__(
        self,
        guard: MetadataGuard | None,
        authorize: Callable[[Any, str, dict[str, Any]], str | Awaitable[str]] | None = None,
        timeout: float = 30,
        max_pending: int = 32,
    ) -> None:
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        self.guard = guard
        self.authorize = authorize
        self.contracts: dict[str, Contract] = {}
        self.servers: dict[str, Peer] = {}
        self.config: dict[str, ServerConfig] = {}
        self.pending: dict[str | int, asyncio.Task[GatewayResponse]] = {}
        self.timeout = timeout
        if max_pending < 1:
            raise ValueError("Pending bound must be positive")
        self.max_pending = max_pending
        self.active = 0

    async def _execute(self, server: str, tool: str, arguments: dict[str, Any]) -> GatewayResponse:
        try:
            async with asyncio.timeout(self.timeout):
                result = await self.servers[server].call_tool(tool, arguments)
                return GatewayResponse("allow", self._label(server, result))
        except TimeoutError:
            return GatewayResponse(
                "error", self._label(server, {"error": "timeout"}), reason="Upstream timed out"
            )
        except Exception:
            return GatewayResponse(
                "error",
                self._label(server, {"error": "unavailable"}),
                reason="Upstream unavailable",
            )

    def _label(self, server: Any, result: Any) -> Any:
        if hasattr(result, "model_dump"):
            result = result.model_dump(by_alias=True, exclude_none=True)
        return Labeled(result, self.config[server].result_label, frozenset({"mcp:" + server}))

    async def call_with_id(
        self, request_id: Any, name: Any, arguments: Any, *, context: Any
    ) -> Any:
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

    def cancel(self, request_id: Any) -> Any:
        task = self.pending.get(request_id)
        if task is not None:
            task.cancel()
            return True
        return False

    def register(
        self, contract: Contract, upstream: Peer, config: ServerConfig | None = None
    ) -> None:
        if config is not None and config.name != contract.server:
            raise ValueError("Configuration identity differs from approved server")
        Draft202012Validator.check_schema(contract.input_schema)
        if contract.name != f"{contract.server}__{contract.tool}":
            raise ValueError("Tool is outside its approved namespace")
        if contract.name in self.contracts:
            raise ValueError("Duplicate qualified tool identity")
        if contract.server in self.servers and self.servers[contract.server] is not upstream:
            raise ValueError("Server identity already bound to another session")
        self.contracts[contract.name] = contract
        self.servers[contract.server] = upstream
        self.config[contract.server] = config or ServerConfig(contract.server)

    def list_tools(self) -> Any:
        return [contract.planner_metadata() for contract in self.contracts.values()]

    async def call(self, name: str, arguments: dict[str, Any], *, context: Any) -> GatewayResponse:
        if self.active >= self.max_pending:
            return GatewayResponse("deny", reason="Gateway overloaded")
        self.active += 1
        try:
            return await self._call(name, arguments, context=context)
        finally:
            self.active -= 1

    async def _call(self, name: str, arguments: dict[str, Any], *, context: Any) -> GatewayResponse:
        if name not in self.contracts or not isinstance(arguments, dict):
            return GatewayResponse("deny", reason="Unknown tool or invalid arguments")
        try:
            arguments = json.loads(json.dumps(arguments, allow_nan=False))
            Draft202012Validator(self.contracts[name].input_schema).validate(arguments)
        except Exception:
            return GatewayResponse("deny", reason="Arguments fail trusted schema")
        if self.authorize is None or context is None:
            return GatewayResponse("deny", reason="Missing trusted policy context")
        try:
            decision = self.authorize(context, name, arguments)
            if inspect.isawaitable(decision):
                decision = await decision
        except Exception:
            return GatewayResponse("deny", reason="Policy evaluation failed")
        if decision != "allow":
            return GatewayResponse(
                "ask" if decision == "ask" else "deny",
                reason="Policy requires approval" if decision == "ask" else "Policy denied",
            )
        contract = self.contracts[name]
        try:
            async with asyncio.timeout(self.timeout):
                metadata = await self.servers[contract.server].metadata()
            if contract.tool not in metadata or (
                self.guard is None
                or not self.guard.check(contract.server, contract.tool, metadata[contract.tool])
            ):
                return GatewayResponse("deny", reason="Metadata missing, changed or quarantined")
        except Exception:
            return GatewayResponse("deny", reason="Metadata recheck failed")
        return await self._execute(contract.server, contract.tool, arguments)


def validate_rpc(payload: Any) -> Any:
    return JSONRPCMessage.model_validate(payload)
