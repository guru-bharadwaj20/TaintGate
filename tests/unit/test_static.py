from taintgate.labels import Label, Integrity, Labeled
from taintgate.static import Analyzer, AbstractValue


def test_extract_conservative():
    source = AbstractValue(Label(Integrity.UNTRUSTED, {'owner'}))
    result = Analyzer(principals={'owner'}).analyze('x = extract(text, {})', {'text': source})
    assert result.environment['x'].label == source.label


def test_abstract_branch_pc():
    flag = AbstractValue(Label(Integrity.UNTRUSTED))
    result = Analyzer({'send': Label()}, principals={'owner'}).analyze('if flag:\n send("constant")', {'flag': flag})
    assert result.calls[0].label.integrity == Integrity.UNTRUSTED
