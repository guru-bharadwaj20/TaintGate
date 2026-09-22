"""CommonMark token processing preserves the complete source label."""
from markdown_it import MarkdownIt
from taintgate.labels import Labeled
from .urls import labelled_destination_allowed


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


def render_safe(value, allowed_domains=()):
    parser = MarkdownIt("commonmark", {"html": False})
    tokens = parse_markdown(value)
    def visit(items):
        for token in items:
            if token.type in {"link_open", "image"}:
                key = "href" if token.type == "link_open" else "src"
                destination = token.attrGet(key)
                if destination and not labelled_destination_allowed(Labeled(destination, value.label, value.sources), allowed_domains):
                    token.attrSet(key, "")
                    token.attrSet("data-taintgate-blocked", "true")
            if token.children:
                visit(token.children)
    visit(tokens)
    return Labeled(parser.renderer.render(tokens, parser.options, {}), value.label, value.sources)
