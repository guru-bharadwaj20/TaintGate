from taintgate.dlp.markdown import destinations
from taintgate.labels import Integrity, Label, Labeled


def test_image_links_autolinks_and_references():
    value = Labeled(
        "[a](https://a.example) ![b](https://b.example) <https://c.example>\n\n[x][r]\n\n[r]: https://d.example",
        Label(Integrity.UNTRUSTED, frozenset({"user"})),
    )
    found = destinations(value)
    assert {v.value for v in found} == {
        "https://a.example",
        "https://b.example",
        "https://c.example",
        "https://d.example",
    }
    assert all(v.label == value.label for v in found)
