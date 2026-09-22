"""Conservative URL normalization for renderer destinations."""
from urllib.parse import urlsplit, urlunsplit, unquote


def normalize_url(value):
    if not isinstance(value, str) or any(ord(c) < 33 or c == "\\" for c in value):
        raise ValueError("Ambiguous URL")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"https", "http"} or not parsed.hostname:
        raise ValueError("Unsupported destination scheme")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials prohibited")
    host = parsed.hostname.rstrip(".").encode("idna").decode().lower()
    port = parsed.port
    if ":" in host:
        host = "[" + host + "]"
    authority = host + (":" + str(port) if port and port not in {80 if parsed.scheme.lower() == "http" else 443} else "")
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, parsed.fragment))


def decoded_components(value):
    decoded = value
    for _ in range(4):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def destination_allowed(value, allowed_domains):
    try:
        normalized = normalize_url(value)
        host = urlsplit(normalized).hostname
        allowed = {domain.rstrip(".").encode("idna").decode().lower() for domain in allowed_domains}
        return host in allowed
    except (ValueError, UnicodeError):
        return False
