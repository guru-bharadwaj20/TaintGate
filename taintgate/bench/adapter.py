"""AgentDojo tool adapter; benchmark environments remain local simulations."""
from collections.abc import Mapping
from typing import Any
from taintgate.interp import Tool
from taintgate.labels import Integrity, Label, Labeled

class ToolAdapter:
    def __init__(self, runtime: Any, environment: Any) -> None:
        self.runtime, self.environment = runtime, environment
        self.calls: list[Any] = []

    @staticmethod
    def plain(value: Any) -> Any:
        if isinstance(value, Labeled):
            return ToolAdapter.plain(value.value)
        if hasattr(value, 'model_dump'):
            return value.model_dump(mode='json')
        if isinstance(value, Mapping):
            return {str(k):ToolAdapter.plain(v) for k,v in value.items()}
        if isinstance(value,(list,tuple)):
            return [ToolAdapter.plain(v) for v in value]
        return value

    def invoke(self, name: str, args: dict[str, Any]) -> Any:
        from importlib import import_module
        FunctionCall = import_module('agentdojo.functions_runtime').FunctionCall
        call = FunctionCall(function=name, args=self.plain(args), id=str(len(self.calls)))
        self.calls.append(call)
        result,error = self.runtime.run_function(self.environment, name, call.args)
        if error:
            raise ValueError('Benchmark tool returned an error')
        return self.plain(result)

    def tools(self) -> dict[str, Tool]:
        return {name:Tool(lambda _name=name, **kwargs:self.invoke(_name,kwargs),
                          Label(Integrity.UNTRUSTED), f'agentdojo:{name}')
                for name in self.runtime.functions}
