import pytest

from taintgate.labels import Integrity, Label, Labeled
from taintgate.quarantine.grammar import SchemaError, compile_schema
from taintgate.quarantine.runner import Quarantine
from taintgate.quarantine.validation import parse_validated


@pytest.mark.parametrize("raw", ["1e400", '{"n": 1e400}', "[1e400]"])
def test_exponent_overflow_is_not_typed_data(raw):
    with pytest.raises((SchemaError, ValueError)):
        parse_validated(raw, {})


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "string", "pattern": "secret.*"},
        {"type": "object", "additionalProperties": True},
        {"type": "array", "items": {"type": "string"}, "maxItems": 10000},
        {"type": "string", "maxLength": 10000},
        {"$ref": "https://attacker.invalid/schema"},
        {"$defs": {"x": {"$ref": "#/$defs/x"}}, "$ref": "#/$defs/x"},
    ],
)
def test_unsupported_or_unbounded_schema_is_rejected(schema):
    with pytest.raises(SchemaError):
        compile_schema(schema)


def test_duplicate_fields_and_response_size_rejected():
    with pytest.raises(SchemaError):
        parse_validated('{"x":1,"x":2}', {})
    with pytest.raises(SchemaError):
        parse_validated('"' + "x" * 100001 + '"', {})


def test_nested_extraction_retains_confidentiality_on_every_leaf():
    class Backend:
        def generate(self, prompt, *, grammar, max_tokens):
            assert "Source:" in prompt and "root ::= " in grammar
            return '{"items":[{"text":"private"}]}'

    schema = {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "maxItems": 3,
                "items": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            }
        },
        "required": ["items"],
    }
    source = Labeled(
        "poisoned private source", Label(readers=frozenset({"owner"})), frozenset({"email:private"})
    )
    result = Quarantine(Backend()).extract(source, schema)
    leaf = result.value["items"].value[0].value["text"]
    assert leaf.value == "private"
    assert leaf.label.readers == {"owner"} and leaf.label.integrity == Integrity.UNTRUSTED
    assert leaf.sources == source.sources
