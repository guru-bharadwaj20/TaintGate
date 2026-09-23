"""Deterministic Taintgate AgentDojo pipeline variants."""
import json
import time
from typing import Any

from taintgate.inference.backend import Backend
from taintgate.inference.planner import ApprovedSignature, Planner
from taintgate.interp import Interpreter, RuntimeFault, Tool
from taintgate.labels import Integrity, Label, Labeled
from taintgate.policy.decisions import approval_facts, call_facts, decide
from taintgate.policy.defaults import policy_for_tools
from taintgate.policy.engine import Engine

from .adapter import ToolAdapter


class TaintgatePipeline:
    name = 'taintgate_permissive'
    def __init__(self, backend: Backend, strict: bool = False, max_calls: int = 4) -> None:
        self.backend,self.strict,self.max_calls = backend,strict,max_calls
        self.approvals = 0
        self.overheads: list[float] = []
        self.name = 'taintgate_strict' if strict else 'taintgate_permissive'

    def query(self, query: str, runtime: Any, env: Any, messages: Any = None, extra_args: Any = None) -> tuple[Any,...]:
        adapter = ToolAdapter(runtime,env)
        signatures = tuple(ApprovedSignature(n,tuple(f.parameters.model_fields)) for n,f in runtime.functions.items())
        engine = Engine(policy_for_tools(tuple(runtime.functions)))
        count = 0
        def authorize(name: str, args: dict[str,Labeled], pc: Label) -> bool:
            nonlocal count
            count += 1
            if count > self.max_calls:
                return False
            started = time.perf_counter()
            call_id = str(count)
            destination = None
            normalized = dict(args)
            for key,value in args.items():
                if key in ('recipient','recipient_email','recipient_iban','to','url','iban','destination'):
                    destination = str(value.value)
                    normalized['recipient'] = value
            destructive = tuple(n for n in runtime.functions if any(word in n for word in ('delete','transfer','cancel','send','book','reserve','pay')))
            facts = (*call_facts(call_id,name,normalized,destination,pc),
                     *approval_facts(call_id,name,args,destructive_tools=destructive))
            decision = decide(engine.evaluate(facts),call_id)
            self.overheads.append(time.perf_counter() - started)
            if decision.action == 'ask':
                self.approvals += 1
            return bool(decision.action == 'allow')
        tools = adapter.tools()
        if self.strict:
            tools = {n:Tool(t.function,Label(Integrity.UNTRUSTED,frozenset({'user'})),t.identity) for n,t in tools.items()}
        interpreter = Interpreter(tools,authorize,strict=self.strict,max_iterations=self.max_calls)
        output = ''
        try:
            source = Planner(self.backend,signatures,retries=1).plan(query)
            values = interpreter.run(source)
            if values:
                output = json.dumps(adapter.plain(next(reversed(values.values()))),ensure_ascii=False)
        except (ValueError, RuntimeFault):
            output = 'Task could not complete within the deterministic policy and plan budget.'
        trace: list[dict[str,Any]] = [{'role':'assistant','content':None,'tool_calls':adapter.calls}] if adapter.calls else []
        trace.append({'role':'assistant','content':[{'type':'text','content':output}],'tool_calls':None})
        return query,runtime,env,trace,extra_args or {}

class StrictTaintgatePipeline(TaintgatePipeline):
    def __init__(self, backend: Backend, max_calls: int = 4) -> None:
        super().__init__(backend,strict=True,max_calls=max_calls)
