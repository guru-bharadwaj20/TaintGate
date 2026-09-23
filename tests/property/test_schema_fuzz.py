import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from taintgate.quarantine.grammar import SchemaError, compile_schema


@given(st.integers(min_value=0,max_value=8), st.integers(min_value=0,max_value=8))
@settings(max_examples=50, deadline=None)
def test_array_grammar_determinism(low,high):
    schema = {'type':'array','items':{'type':'boolean'},'minItems':low,'maxItems':high}
    if high < low:
        with pytest.raises(SchemaError):
            compile_schema(schema)
    else:
        assert compile_schema(schema) == compile_schema(schema)

def test_reference_expansion_is_bounded():
    defs = {'leaf':{'type':'boolean'}}
    previous='leaf'
    for index in range(15):
        name=f'level{index}'
        defs[name]={'type':'object','properties':{'a':{'$ref':f'#/$defs/{previous}'},'b':{'$ref':f'#/$defs/{previous}'}},'additionalProperties':False}
        previous=name
    with pytest.raises(SchemaError, match='expanded|expansion'):
        compile_schema({'type':'object','properties':{'root':{'$ref':f'#/$defs/{previous}'}},'$defs':defs,'additionalProperties':False})
