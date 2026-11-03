"""Display helpers for the HTML pages (and, later, the evaluation report)."""

import re
from bisect import bisect_left
from collections.abc import Mapping

from phishguard.models import Verdict

VERDICT_LABELS: Mapping[Verdict, str] = {
    Verdict.SAFE: "안전",
    Verdict.SUSPICIOUS: "주의",
    Verdict.DANGEROUS: "위험",
}

# Step 1 target: "http:" / "https:" anywhere in the text (any case, preceded by anything).
_HTTP_SCHEME = re.compile(r"http(s?):", re.IGNORECASE)
# Step 2 targets, found anywhere in the text. After step 1 an http(s) URL starts with
# "hxxp:" / "hxxps:" followed by any number of slashes (browsers read "http:/a.com" and
# "http:///a.com" like "http://a.com"). Any other "scheme://" counts too, including a
# dotted pseudo-scheme such as "evil.com://x"; its name is anchored at the start of the
# run of name characters so the search stays linear on long inputs.
_URL_START = re.compile(
    r"hxxps?:/*|(?<![A-Za-z0-9+.\-])[A-Za-z0-9+.\-]*:/{2,}",
    re.IGNORECASE,
)
_AUTHORITY_END = re.compile(r"[/?#]")
# An already defanged "[.]" maps to itself, so defang() is idempotent.
_HOST_DOT = re.compile(r"\[\.\]|\.")


def defang(url: str) -> str:
    """Make URL text safe to display: ``https://evil.com/x`` -> ``hxxps://evil[.]com/x``.

    Works on raw user text, so it never raises. Every ``http:``/``https:`` (any case,
    wherever it appears) becomes ``hxxp:``/``hxxps:``. The dots of each URL's host become
    ``[.]``, for the URL at the start of the text, for URLs after other text (``see
    http://a.com``, ``(http://a.com)``) and for URLs inside another URL's path or query.
    A URL's host is the part of its authority after the last ``@``; the authority ends at
    the first ``/``, ``?`` or ``#``. Text that starts without a scheme is read as a host,
    so ``evil.com/login`` becomes ``evil[.]com/login``. Dots in userinfo, port, path,
    query and fragment are kept.
    """
    text = _HTTP_SCHEME.sub(lambda m: "hxxp" + m[1].lower() + ":", url.strip())
    separators = [m.start() for m in _AUTHORITY_END.finditer(text)]
    at_signs = [i for i, char in enumerate(text) if char == "@"]
    spans: list[tuple[int, int]] = []  # slices of ``text`` whose dots get defanged

    def add_host_span(authority_start: int) -> None:
        index = bisect_left(separators, authority_start)
        authority_end = separators[index] if index < len(separators) else len(text)
        # last "@" inside [authority_start, authority_end), via bisect to stay linear
        at_index = bisect_left(at_signs, authority_end) - 1
        host_start = authority_start
        if at_index >= 0 and at_signs[at_index] >= authority_start:
            host_start = at_signs[at_index] + 1
        spans.append((host_start, authority_end))

    # Text without a scheme starts with the host (a protocol-relative "//host" too).
    add_host_span(len(text) - len(text.lstrip("/")))
    for start in _URL_START.finditer(text):
        spans.append(start.span())  # the name of a dotted pseudo-scheme
        add_host_span(start.end())

    pieces: list[str] = []
    position = 0
    for begin, end in sorted(spans):
        begin = max(begin, position)
        if end <= begin:
            continue
        pieces.append(text[position:begin])
        pieces.append(_HOST_DOT.sub("[.]", text[begin:end]))
        position = end
    pieces.append(text[position:])
    return "".join(pieces)
