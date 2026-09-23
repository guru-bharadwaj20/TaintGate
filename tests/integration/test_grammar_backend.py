"""Explicit model tests skip unless TAINTGATE_TEST_GGUF is set."""
import os
from pathlib import Path

import pytest

from benchmarks.grammar_backend import GrammarRecognizer
from taintgate.quarantine.grammar import compile_schema


@pytest.mark.model
@pytest.mark.parametrize('schema,valid,invalid', [
    ({'type':'integer'}, ['-2','0','2'], ['0.5','"0"','true']),
    ({'type':'string','enum':['safe','ready']}, ['"safe"','"ready"'], ['"evil"','1']),
    ({'type':'array','items':{'type':'boolean'},'minItems':1,'maxItems':2}, ['[true]','[false,true]'], ['[]','[true,true,true]']),
    ({'type':'object','properties':{'x':{'type':'integer'}},'required':['x'],'additionalProperties':False}, ['{"x":1}'], ['{}','{"x":1,"y":2}']),
])
def test_real_backend_acceptance(schema, valid, invalid):
    path = os.getenv('TAINTGATE_TEST_GGUF')
    if not path:
        pytest.skip('Explicit local GGUF not configured')
    recognizer = GrammarRecognizer(Path(path))
    grammar = compile_schema(schema)
    for text in valid:
        assert recognizer.accepts(grammar,text), (schema,text)
    for text in invalid:
        assert not recognizer.accepts(grammar,text), (schema,text)
