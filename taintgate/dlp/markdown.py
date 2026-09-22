"""CommonMark token processing preserves the complete source label."""
from markdown_it import MarkdownIt
from taintgate.labels import Labeled


def parse_markdown(value):
    if not isinstance(value, Labeled) or not isinstance(value.value, str):
        raise TypeError("Expected a labelled markdown string")
    return MarkdownIt("commonmark", {"html": False}).parse(value.value)


def destinations(value):
    found = []
    def visit(tokens):
        for token in tokens:
            if token.type in {"link_open", "image"}:
                destination = token.attrGet("href" if token.type == "link_open" else "src")
                if destination:
                    found.append(Labeled(destination, value.label, value.sources))
            if token.children:
                visit(token.children)
    visit(parse_markdown(value))
    return found
