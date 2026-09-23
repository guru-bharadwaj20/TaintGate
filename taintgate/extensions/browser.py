"""Label browser response text at a trusted transport boundary."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from taintgate.labels import Integrity, Label, Labeled, provenance_id


def origin_principal(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) browser origins are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credential-bearing origins are forbidden")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = parsed.port
    if ":" in host:
        host = "[" + host + "]"
    suffix = (
        "" if port is None or port == (443 if parsed.scheme == "https" else 80) else ":" + str(port)
    )
    return "origin:" + parsed.scheme + "://" + host + suffix


def browser_value(
    final_response_url: str,
    text: str,
    *,
    readers: Iterable[str] | None = None,
    max_bytes: int = 1048576,
) -> Labeled:
    """The caller supplies the transport-verified final URL, after redirects."""
    origin = origin_principal(final_response_url)
    if not isinstance(text, str) or len(text.encode("utf-8")) > max_bytes:
        raise ValueError("Browser text exceeds the adapter limit")
    permitted = None if readers is None else frozenset(readers)
    source = provenance_id("browser:" + origin, [final_response_url])
    return Labeled(text, Label(Integrity.UNTRUSTED, permitted), frozenset({source}))
