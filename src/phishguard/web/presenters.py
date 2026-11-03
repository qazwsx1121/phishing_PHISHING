"""Display helpers for the HTML pages (and, later, the evaluation report)."""

import re
from collections.abc import Mapping

from phishguard.models import Verdict

VERDICT_LABELS: Mapping[Verdict, str] = {
    Verdict.SAFE: "안전",
    Verdict.SUSPICIOUS: "주의",
    Verdict.DANGEROUS: "위험",
}

# "http:", "https:" optionally followed by any number of slashes (browsers treat
# "http:/a.com" and "http:///a.com" like "http://a.com").
_HTTP_PREFIX = re.compile(r"(?P<scheme>https?)(?P<sep>:/*)", re.IGNORECASE)
_OTHER_SCHEME_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")
_AUTHORITY_END = re.compile(r"[/?#]")
# An already defanged "[.]" maps to itself, so defang() is idempotent.
_HOST_DOT = re.compile(r"\[\.\]|\.")


def defang(url: str) -> str:
    """Make a URL safe to display: ``https://evil.com/x`` -> ``hxxps://evil[.]com/x``.

    Works on raw user text, so it never raises and tolerates a missing scheme. The
    scheme ``http``/``https`` (any case) becomes ``hxxp``/``hxxps`` and the dots of the
    host become ``[.]``. Dots in the userinfo, port, path, query and fragment are kept.
    """
    text = url.strip()

    http = _HTTP_PREFIX.match(text)
    if http:
        head = "hxxp" + http["scheme"][4:].lower() + http["sep"]
        rest = text[http.end() :]
    else:
        other = _OTHER_SCHEME_PREFIX.match(text)
        if other:
            head, rest = other.group(0), text[other.end() :]
        else:
            # No scheme; a protocol-relative "//host/path" still has a host.
            body = text.lstrip("/")
            head, rest = text[: len(text) - len(body)], body

    end = _AUTHORITY_END.search(rest)
    split_at = end.start() if end else len(rest)
    authority, tail = rest[:split_at], rest[split_at:]

    userinfo, at, host = authority.rpartition("@")
    return head + userinfo + at + _HOST_DOT.sub("[.]", host) + tail
