"""URL normalization: turn messy user input into the host/port/path a browser would use.

Every later stage trusts the host produced here, so the parsing deliberately
mimics browser behaviour where ``urllib.parse.urlsplit`` differs from it
(backslashes, stripped control characters, missing slashes after the scheme).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import idna

from phishguard.errors import InvalidURLError
from phishguard.models import NormalizedURL

MAX_URL_LENGTH: int = 2048

_MSG_EMPTY = "URL을 입력해 주세요."
_MSG_TOO_LONG = "URL이 너무 깁니다."
_MSG_SCHEME = "웹 주소(http/https)만 검사할 수 있습니다."
_MSG_FORMAT = "올바른 URL 형식이 아닙니다."

# Zero-width characters / BOM, plus the three ASCII characters browsers delete anywhere.
_DELETED_CHARS_RE = re.compile("[​‌‍⁠﻿\t\r\n]")
# Leading/trailing whitespace and C0 controls (U+0000 - U+0020).
_EDGE_RE = re.compile(r"^[\s\x00-\x20]+|[\s\x00-\x20]+$")
_WRAPPERS = {"<": ">", '"': '"', "'": "'", "(": ")"}

_HXXP_RE = re.compile(r"^hxxp", re.IGNORECASE)
_BAD_SCHEME_RE = re.compile(r"^(javascript|data|file|vbscript|mailto):", re.IGNORECASE)
_HTTP_SEPARATOR_RE = re.compile(r"^(https?):/*", re.IGNORECASE)
_HAS_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_BRACKETED_RE = re.compile(r"\[([^\]]*)\](?::[0-9]*)?")
_HOST_RE = re.compile(r"[a-z0-9_.-]+")

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _strip_edges(s: str) -> str:
    return _EDGE_RE.sub("", s)


def _clean(raw: str) -> str:
    s = _DELETED_CHARS_RE.sub("", raw)
    s = _strip_edges(s)
    if len(s) >= 2 and _WRAPPERS.get(s[0]) == s[-1]:
        s = s[1:-1]
    return _strip_edges(s)


def _refang(s: str) -> str:
    s = _HXXP_RE.sub("http", s)
    for defanged in ("[.]", "(.)", "{.}"):
        s = s.replace(defanged, ".")
    return s.replace("[:]", ":")


def _backslashes_to_slashes(s: str) -> str:
    """Replace backslashes before the first ``?`` or ``#`` (browsers treat them as ``/``)."""
    cut = len(s)
    for marker in ("?", "#"):
        i = s.find(marker)
        if i != -1:
            cut = min(cut, i)
    return s[:cut].replace("\\", "/") + s[cut:]


def _to_ascii_host(host: str) -> str:
    if host.isascii():
        return host
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except Exception:  # noqa: BLE001 - idna raises several unrelated error types
        pass
    try:
        return host.encode("idna").decode("ascii")
    except Exception as exc:  # noqa: BLE001
        raise InvalidURLError(_MSG_FORMAT) from exc


def normalize_url(raw: str, *, refang: bool = True) -> NormalizedURL:
    s = _clean(raw)

    was_refanged = False
    if refang:
        refanged = _refang(s)
        was_refanged = refanged != s
        s = refanged

    if not s:
        raise InvalidURLError(_MSG_EMPTY)
    if len(s) > MAX_URL_LENGTH:
        raise InvalidURLError(_MSG_TOO_LONG)

    s = _backslashes_to_slashes(s)
    if _BAD_SCHEME_RE.match(s):
        raise InvalidURLError(_MSG_SCHEME)

    s = _HTTP_SEPARATOR_RE.sub(lambda m: m.group(1) + "://", s)

    scheme_added = False
    if not _HAS_SCHEME_RE.match(s):
        s = "http://" + s
        scheme_added = True

    try:
        parts = urlsplit(s)
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise InvalidURLError(_MSG_FORMAT) from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise InvalidURLError(_MSG_SCHEME)

    host = (hostname or "").rstrip(".")
    if not host:
        raise InvalidURLError(_MSG_FORMAT)

    netloc = parts.netloc
    host_part = netloc.rpartition("@")[2]
    is_ipv6 = host_part.startswith("[")
    if is_ipv6:
        m = _BRACKETED_RE.fullmatch(host_part)
        if not m or "%" in m.group(1):
            raise InvalidURLError(_MSG_FORMAT)
        try:
            host = ipaddress.IPv6Address(m.group(1)).compressed
        except ValueError as exc:
            raise InvalidURLError(_MSG_FORMAT) from exc
    else:
        host = _to_ascii_host(host).lower().rstrip(".")
        if not host or not _HOST_RE.fullmatch(host):
            raise InvalidURLError(_MSG_FORMAT)

    if port == _DEFAULT_PORTS[scheme]:
        port = None

    userinfo = netloc.rpartition("@")[0] if "@" in netloc else ""
    path = parts.path or "/"
    query = parts.query

    host_for_url = f"[{host}]" if is_ipv6 else host
    normalized = (
        f"{scheme}://{userinfo + '@' if userinfo else ''}{host_for_url}"
        f"{':' + str(port) if port is not None else ''}{path}"
        f"{'?' + query if query else ''}"
    )
    return NormalizedURL(
        original=raw,
        normalized=normalized,
        scheme=scheme,
        userinfo=userinfo,
        host=host,
        port=port,
        path=path,
        query=query,
        was_refanged=was_refanged,
        scheme_added=scheme_added,
    )
