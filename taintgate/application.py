"""Trusted host wiring for preflight, labelled execution and MCP enforcement."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from taintgate.audit.log import AuditLog, approval_event, boundary_event, decision_event, plan_event
from taintgate.dlp.outbound import check_outbound
from taintgate.gateway.core import Gateway
from taintgate.interp import Interpreter, RuntimeFault, Tool
from taintgate.labels import Label, Labeled
from taintgate.policy.decisions import Decision, approval_facts, call_facts, decide
from taintgate.policy.defaults import policy_for_tools
from taintgate.policy.engine import Engine
from taintgate.static import Analyzer


def plain(value: Any) -> Any:
    if isinstance(value, Labeled):
        return plain(value.value)
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, tuple | list):
        return [plain(v) for v in value]
    return value


@dataclass(frozen=True)
class Invocation:
    tool: str
    arguments: dict[str, Labeled]
    pc: Label


@dataclass
class RunResult:
    run_id: str
    status: str
    preflight: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    output: dict[str, Any] = field(default_factory=dict)
    metadata_diffs: list[str] = field(default_factory=list)


class Application:
    """Host-only context cannot be supplied through MCP tool argument JSON."""

    def __init__(
        self,
        gateway: Gateway,
        audit: AuditLog,
        *,
        strict: bool = True,
        canaries: tuple[str, ...] = (),
        planner: Any = None,
        quarantine: Any = None,
    ) -> None:
        self.gateway = gateway
        self.audit = audit
        self.strict = strict
        self.canaries = canaries
        self.planner = planner
        self.quarantine = quarantine
        self.policy = policy_for_tools(tuple(gateway.contracts))
        self.engine = Engine(self.policy)
        self.approved: set[str] = set()
        self.pending_scopes: dict[str, str] = {}
        self.plan_digest = ""
        self._run_lock = asyncio.Lock()
        gateway.authorize = self._gateway_authorize

    def decision(self, call: Invocation) -> Any:
        recipients = [
            plain(call.arguments[key])
            for key in ("to", "recipient", "destination", "url")
            if key in call.arguments
        ]
        if any(not isinstance(value, str) or not value for value in recipients):
            return Decision("deny", ("invalid outbound destination",))
        if len(set(recipients)) > 1:
            return Decision("deny", ("conflicting outbound destinations",))
        destination = recipients[0] if recipients else None
        principal = destination or self.gateway.contracts[call.tool].server
        if not call.pc.may_read(principal) or not check_outbound(
            call.arguments, principal, self.canaries
        ):
            return Decision("deny", ("outbound confidentiality or secret check failed",))
        facts = call_facts(
            "pending", call.tool, call.arguments, destination=destination, pc=call.pc
        )
        facts += approval_facts("pending", call.tool, call.arguments)
        decision = decide(self.engine.evaluate(facts), "pending")
        scope = self.scope(call)
        if decision.action == "ask" and scope in self.approved:
            return Decision("allow", ("explicit scoped user approval",))
        return decision

    def scope(self, call: Invocation) -> str:
        metadata = {
            name: contract.planner_metadata() for name, contract in self.gateway.contracts.items()
        }
        labels = {
            name: {
                "integrity": value.label.integrity.name,
                "readers": None if value.label.readers is None else sorted(value.label.readers),
            }
            for name, value in call.arguments.items()
        }
        provenance = sorted(
            {source for value in call.arguments.values() for source in value.sources}
        )
        payload = [
            self.plan_digest,
            self.policy,
            metadata,
            call.tool,
            plain(call.arguments),
            labels,
            provenance,
            call.pc.integrity.name,
            None if call.pc.readers is None else sorted(call.pc.readers),
        ]
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, allow_nan=False).encode()
        ).hexdigest()

    def approve(self, scope: str, reason: str) -> None:
        if scope not in self.pending_scopes or not reason:
            raise ValueError("Unknown approval scope")
        self.audit.append(approval_event(self.pending_scopes[scope], scope, reason))
        self.approved.add(scope)
        del self.pending_scopes[scope]

    def _gateway_authorize(self, context: Any, name: str, arguments: dict[str, Any]) -> str:
        if not isinstance(context, Invocation) or context.tool != name:
            return "deny"
        if plain(context.arguments) != arguments:
            return "deny"
        return str(self.decision(context).action)

    async def run(self, source: str) -> RunResult:
        async with self._run_lock:
            return await self._run(source)

    async def run_request(self, user_request: str) -> RunResult:
        if self.planner is None:
            raise ValueError("No CPU planner configured")
        source = await asyncio.to_thread(self.planner.plan, user_request)
        return await self.run(source)

    async def _run(self, source: str) -> RunResult:
        loop = asyncio.get_running_loop()
        run_id = hashlib.sha256(source.encode()).hexdigest()
        self.plan_digest = run_id
        result = RunResult(run_id, "pending")
        pending: list[Invocation] = []
        tools: dict[str, Tool] = {}
        for name, contract in self.gateway.contracts.items():

            def bridge(*args: Any, _name: str = name, **kwargs: Any) -> Any:
                if args or not pending or pending[-1].tool != _name:
                    raise RuntimeFault(code="invalid_tool_binding")
                response = asyncio.run_coroutine_threadsafe(
                    self.gateway.call(_name, kwargs, context=pending[-1]), loop
                ).result(timeout=self.gateway.timeout + 5)
                if response.status != "allow":
                    raise RuntimeFault(code="gateway_denied")
                return response.result

            label = self.gateway.config[contract.server].result_label
            tools[name] = Tool(bridge, label, name)
        principals = frozenset(
            p for config in self.gateway.config.values() for p in (config.readers or ())
        )
        preflight = Analyzer(tools, principals=principals, strict=self.strict).analyze(source)
        result.preflight = [
            {"line": site.line, "tool": site.tool, "potentially_unsafe": site.potentially_unsafe}
            for site in preflight.calls
        ]

        def authorize(name: str, args: dict[str, Labeled], pc: Label) -> bool:
            call = Invocation(name, args, pc)
            decision = self.decision(call)
            pending.append(call)
            scope = self.scope(call)
            if decision.action == "ask":
                self.pending_scopes[scope] = run_id
            result.decisions.append(
                {
                    "tool": name,
                    "action": decision.action,
                    "reasons": decision.reasons,
                    "scope": scope if decision.action == "ask" else None,
                    "arguments": {
                        key: {
                            "preview": json.dumps(plain(value), ensure_ascii=True)[:256]
                            if public_tree(value) and check_outbound(value, "public", self.canaries)
                            else "[confidential value]",
                            "integrity": value.label.integrity.name,
                        }
                        for key, value in args.items()
                    }
                    if decision.action == "ask"
                    else {},
                }
            )
            return bool(decision.action == "allow")

        def extract(text: str, schema: dict[str, Any]) -> Any:
            from taintgate.quarantine.validation import parse_validated

            if self.quarantine is None:
                raise ValueError("No quarantined extraction backend configured")
            return parse_validated(self.quarantine.decode(text, schema), schema)

        interpreter = Interpreter(
            tools,
            authorize=authorize,
            strict=self.strict,
            extractor=extract if self.quarantine is not None else None,
        )
        self.audit.append(plan_event(run_id, source))
        self.audit.append(boundary_event(run_id))
        try:
            values = await asyncio.to_thread(interpreter.run, source)
            # Runtime values remain private; only explicit public values can be rendered.
            result.output = {
                k: plain(v)
                for k, v in values.items()
                if public_tree(v) and check_outbound(v, "public", self.canaries)
            }
            result.status = "completed"
        except RuntimeFault as error:
            result.status = error.code
        finally:
            result.trace = [
                {"step": i, **{k: v for k, v in event.items() if k != "label"}}
                for i, event in enumerate(interpreter.trace)
            ]
            for decision in result.decisions:
                self.audit.append(
                    decision_event(
                        run_id,
                        decision["tool"],
                        decision["action"],
                        [str(r) for r in decision["reasons"]],
                        {},
                    )
                )
            self.audit.append(boundary_event(run_id, finished=True))
        guard = self.gateway.guard
        if guard is None:
            return result
        for contract in self.gateway.contracts.values():
            if (contract.server, contract.tool) in guard.quarantined:
                try:
                    async with asyncio.timeout(self.gateway.timeout):
                        metadata = await self.gateway.servers[contract.server].metadata()
                    result.metadata_diffs.append(
                        guard.pins.diff(
                            contract.server, contract.tool, metadata.get(contract.tool, {})
                        )
                    )
                except Exception:
                    result.metadata_diffs.append("Changed metadata could not be retrieved")
        return result


def public_tree(value: Any) -> bool:
    if isinstance(value, Labeled):
        return value.label.readers is None and public_tree(value.value)
    if isinstance(value, Mapping):
        return all(public_tree(k) and public_tree(v) for k, v in value.items())
    if isinstance(value, tuple | list):
        return all(public_tree(v) for v in value)
    return type(value) in (str, int, float, bool, type(None))
