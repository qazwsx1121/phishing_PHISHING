"""Split a normalized URL host into subdomain / domain / suffix (PSL) and detect IP hosts."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

import tldextract
from tldextract import TLDExtract

from phishguard.models import NormalizedURL, URLParts

_HEX = re.compile(r"0[xX]([0-9a-fA-F]*)", re.ASCII)
_OCTAL = re.compile(r"0[0-7]+", re.ASCII)
_DECIMAL = re.compile(r"0|[1-9][0-9]*", re.ASCII)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _parse_ipv4_number(part: str) -> int | None:
    """WHATWG number parsing with a strict ASCII-only grammar (int() is too lenient)."""
    m = _HEX.fullmatch(part)
    if m:
        return int(m.group(1), 16) if m.group(1) else 0
    if _OCTAL.fullmatch(part):
        return int(part, 8)
    if _DECIMAL.fullmatch(part):
        return int(part, 10)
    return None


def parse_ip_host(host: str) -> IPAddress | None:
    """Return the address a browser would connect to for ``host``, or None if it is not an IP."""
    try:
        text = host
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        if ":" in text:
            if "%" in text:  # zone ids are accepted by ipaddress but not by browsers
                return None
            return ipaddress.IPv6Address(text)
        parts = text.split(".")
        if parts[-1] == "":
            parts.pop()
        if not parts or len(parts) > 4:
            return None
        numbers = []
        for part in parts:
            n = _parse_ipv4_number(part)
            if n is None:
                return None
            numbers.append(n)
        *head, last = numbers
        if any(n > 255 for n in head) or last >= 256 ** (5 - len(numbers)):
            return None
        value = last + sum(n * 256 ** (3 - i) for i, n in enumerate(head))
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


@lru_cache(maxsize=None)
def _extractor(include_private: bool, refresh: bool) -> TLDExtract:
    # lru_cache makes lazy creation safe: a race may build a duplicate instance,
    # but a half-initialised one is never published.
    if refresh:
        return tldextract.TLDExtract(include_psl_private_domains=include_private)
    return tldextract.TLDExtract(
        suffix_list_urls=(), cache_dir=None, include_psl_private_domains=include_private
    )


def _join(domain: str, suffix: str) -> str:
    return f"{domain}.{suffix}" if domain and suffix else ""


def parse_url(url: NormalizedURL, *, psl_refresh: bool = False) -> URLParts:
    host = url.host
    if parse_ip_host(host) is not None:
        return URLParts(host=host, subdomain="", domain="", suffix="", registered_domain="",
                        site_domain="", is_ip=True, is_private_suffix=False)
    icann = _extractor(False, psl_refresh)(host)
    private = _extractor(True, psl_refresh)(host)
    registered = _join(icann.domain, icann.suffix)
    site = _join(private.domain, private.suffix)
    is_private = private.suffix != icann.suffix
    if not private.domain:  # host is itself a private suffix (e.g. github.io)
        site, is_private = registered, False
    return URLParts(host=host, subdomain=icann.subdomain, domain=icann.domain,
                    suffix=icann.suffix, registered_domain=registered, site_domain=site,
                    is_ip=False, is_private_suffix=is_private)
