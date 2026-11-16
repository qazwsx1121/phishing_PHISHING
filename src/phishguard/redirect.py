"""Resolve shortened URLs to their destination without ever contacting the destination.

Security model (see ADR D1/D2): the only hosts this module sends requests to are
allow-listed shortener hosts, and only after every address they resolve to has been
checked to be publicly routable. Redirect targets are read from the ``Location``
header and never requested unless they are themselves shortener hosts.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Callable
from urllib.parse import urljoin

import httpx

from phishguard.errors import InvalidURLError
from phishguard.models import NormalizedURL, RedirectHop, RedirectResult
from phishguard.normalize import browser_url_reference, normalize_url

BROWSER_UA: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
ResolveFn = Callable[[str], list[str]]

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_HEAD_FALLBACK_STATUSES = frozenset({400, 403, 405, 501})
_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
# IPv6 ranges that are never a public destination, whatever Python's is_global says:
# RFC 8215 local-use NAT64, SIIT (::ffff:0:0:0/96), deprecated IPv4-compatible (::/96),
# deprecated site-local (fec0::/10).
_NEVER_PUBLIC_V6 = tuple(
    ipaddress.IPv6Network(n)
    for n in ("64:ff9b:1::/48", "::ffff:0:0:0/96", "::/96", "fec0::/10")
)


def default_resolve(host: str) -> list[str]:
    """IP address strings for ``host`` (may raise OSError or UnicodeError)."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def is_shortener_host(host: str, shorteners: frozenset[str]) -> bool:
    return any(host == s or host.endswith("." + s) for s in shorteners)


def is_public_address(text: str) -> bool:
    """True only for a publicly routable address; fails closed on anything unparsable.

    IPv6 forms that embed an IPv4 address (IPv4-mapped, 6to4, NAT64 64:ff9b::/96)
    are judged by the embedded IPv4 address.
    """
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        embedded: ipaddress.IPv4Address | None = ip.ipv4_mapped or ip.sixtofour
        if embedded is None and ip in _NAT64_PREFIX:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None:
            return embedded.is_global and not embedded.is_multicast
        if any(ip in net for net in _NEVER_PUBLIC_V6):
            return False
    return ip.is_global and not ip.is_multicast


class RedirectResolver:
    def __init__(
        self,
        shorteners: frozenset[str],
        client: httpx.Client,
        *,
        max_hops: int = 5,
        resolve: ResolveFn = default_resolve,
    ) -> None:
        self._shorteners = shorteners
        self._client = client
        self._max_hops = max_hops
        self._resolve = resolve
        # httpx parses the Location header itself (even with follow_redirects=False) and raises
        # InvalidURL / RemoteProtocolError for values a browser would still accept. A response
        # hook runs before that parsing, so we keep the raw status/Location and apply our own
        # browser-like parsing instead.
        self._last = threading.local()
        hooks = client.event_hooks
        hooks["response"] = [*hooks.get("response", []), self._remember_response]
        client.event_hooks = hooks

    def _remember_response(self, response: httpx.Response) -> None:
        self._last.value = (response.status_code, response.headers.get("Location", ""))

    def resolve(self, url: NormalizedURL) -> RedirectResult:
        if not is_shortener_host(url.host, self._shorteners):
            return RedirectResult.not_followed(url.normalized)

        current = url
        seen = {current.normalized}
        hops: list[RedirectHop] = []

        def fail(error: str) -> RedirectResult:
            return RedirectResult(
                final_url=current.normalized,
                hops=tuple(hops),
                is_shortener=True,
                complete=False,
                error=error,
            )

        while True:
            if not is_shortener_host(current.host, self._shorteners):
                return RedirectResult(
                    final_url=current.normalized,
                    hops=tuple(hops),
                    is_shortener=True,
                    complete=True,
                    error=None,
                )
            if len(hops) >= self._max_hops:
                return fail("too_many_redirects")

            try:
                addresses = self._resolve(current.host)
            except (OSError, UnicodeError):
                return fail("dns_error")
            if not addresses:
                return fail("dns_error")
            if not all(is_public_address(a) for a in addresses):
                return fail("blocked_private_address")

            try:
                status, location = self._fetch(current.normalized)
            except (httpx.HTTPError, httpx.InvalidURL, ValueError):
                # ValueError covers UnicodeError / idna.IDNAError for invalid A-labels.
                return fail("network_error")

            if status not in _REDIRECT_STATUSES or not location:
                return fail("no_redirect_from_shortener")

            try:
                nxt = normalize_url(
                    urljoin(current.normalized, browser_url_reference(location)),
                    refang=False,
                )
            except (InvalidURLError, ValueError):
                # ValueError: urljoin("Invalid IPv6 URL"), NFKC netloc delimiters, idna errors.
                return fail("invalid_location")
            hops.append(RedirectHop(current.normalized, status))
            if nxt.normalized in seen:
                current = nxt
                return fail("redirect_loop")
            seen.add(nxt.normalized)
            current = nxt

    def _fetch(self, url: str) -> tuple[int, str]:
        """One request (HEAD, falling back to GET) without following redirects."""
        self._last.value = None
        try:
            return self._request(url)
        except (httpx.InvalidURL, httpx.RemoteProtocolError):
            seen = getattr(self._last, "value", None)
            if seen is not None and seen[0] in _REDIRECT_STATUSES:
                return seen  # httpx rejected the Location value; judge it ourselves
            raise

    def _request(self, url: str) -> tuple[int, str]:
        headers = {"User-Agent": BROWSER_UA}
        response = self._client.head(url, follow_redirects=False, headers=headers)
        if response.status_code in _HEAD_FALLBACK_STATUSES:
            with self._client.stream(
                "GET", url, follow_redirects=False, headers=headers
            ) as streamed:
                return streamed.status_code, streamed.headers.get("Location", "")
        return response.status_code, response.headers.get("Location", "")
