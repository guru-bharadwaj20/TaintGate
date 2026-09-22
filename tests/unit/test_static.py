from taintgate.labels import Label, Integrity, Labeled
from taintgate.static import Analyzer, AbstractValue


def test_extract_conservative():
    source = AbstractValue(Label(Integrity.UNTRUSTED, {'owner'}))
    result = Analyzer(principals={'owner'}).analyze('x = extract(text, {})', {'text': source})
    assert result.environment['x'].label == source.label
