import os
import socket
from collections.abc import Iterator

import httpx
import pytest
import respx

from phishguard.config import load_resources
from phishguard.models import RedirectHop, RedirectResult
from phishguard.normalize import normalize_url
from phishguard.redirect import (
    BROWSER_UA,
    RedirectResolver,
    default_resolve,
    is_public_address,
    is_shortener_host,
)

SHORTENERS = load_resources().shorteners
PUBLIC_IP = "93.184.216.34"


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    # Any request to a host without a registered route raises instead of going out.
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as r:
        yield r


def make_resolver(**kwargs) -> RedirectResolver:
    kwargs.setdefault("resolve", lambda h: [PUBLIC_IP])
    return RedirectResolver(SHORTENERS, httpx.Client(timeout=5.0), **kwargs)


@pytest.fixture
def resolver(router) -> RedirectResolver:
    return make_resolver()


def requested_hosts(router: respx.MockRouter) -> set[str]:
    return {call.request.url.host for call in router.calls}


def resolve(resolver: RedirectResolver, url: str):
    return resolver.resolve(normalize_url(url))


# ---------------------------------------------------------------- is_public_address


@pytest.mark.parametrize(
    "text",
    ["8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"],
)
def test_public_addresses(text):
    assert is_public_address(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fe80::1%eth0",
        "8.8.8.8%x",
        "64:ff9b:1::a00:1",
        "::ffff:0:a00:1",
        "::ffff:0:7f00:1",
        "::7f00:1",
        "::a00:1",
        "fec0::1",
        "224.0.0.1",
        "ff02::1",
        "fc00::1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "2002:a00:1::",
        "not-an-ip",
        "",
    ],
)
def test_non_public_addresses(text):
    assert is_public_address(text) is False


def test_nat64_and_6to4_with_public_embedded_ipv4_are_public():
    assert is_public_address("64:ff9b::808:808") is True
    assert is_public_address("2002:808:808::") is True


# ---------------------------------------------------------------- is_shortener_host


def test_is_shortener_host():
    s = frozenset({"bit.ly"})
    assert is_shortener_host("bit.ly", s)
    assert is_shortener_host("www.bit.ly", s)
    assert not is_shortener_host("abit.ly", s)
    assert not is_shortener_host("bit.ly.evil.example", s)


# ---------------------------------------------------------------- default_resolve


def test_default_resolve_returns_ip_strings(monkeypatch):
    calls = []

    def fake(host, port, **kw):
        calls.append(host)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606::1", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert default_resolve("bit.ly") == ["1.2.3.4", "2606::1"]
    assert calls == ["bit.ly"]


def test_overlong_label_is_dns_error(router, monkeypatch):
    def fake(host, port, **kw):
        if any(len(label) > 63 for label in host.split(".")):
            raise UnicodeError("label too long")
        raise AssertionError("unexpected lookup")

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    url = normalize_url("https://" + "a" * 64 + ".bit.ly/x")
    r = make_resolver(resolve=default_resolve).resolve(url)
    assert r.error == "dns_error" and not r.complete
    assert not router.calls


# ---------------------------------------------------------------- resolve: basics


def test_non_shortener_makes_no_request(resolver, router):
    r = resolve(resolver, "https://evil.example/a")
    assert r.hops == () and r.is_shortener is False and r.complete is True
    assert r.final_url == "https://evil.example/a" and r.error is None
    assert not router.calls


def test_resolves_bitly_single_hop(resolver, router):
    route = router.head("https://bit.ly/abc").respond(
        301, headers={"Location": "https://evil.example/login"}
    )
    r = resolve(resolver, "https://bit.ly/abc")
    assert r.final_url == "https://evil.example/login" and r.complete and r.is_shortener
    assert r.hops == (RedirectHop("https://bit.ly/abc", 301),)
    assert route.calls.last.request.headers["User-Agent"] == BROWSER_UA
    assert requested_hosts(router) == {"bit.ly"}  # no route for evil.example was needed


def test_resolves_korean_shortener(resolver, router):
    router.head("https://han.gl/k").respond(302, headers={"Location": "https://me2.do/x"})
    router.head("https://me2.do/x").respond(301, headers={"Location": "https://phish.example/a"})
    r = resolve(resolver, "https://han.gl/k")
    assert r.final_url == "https://phish.example/a" and r.complete and r.error is None
    assert r.hops == (RedirectHop("https://han.gl/k", 302), RedirectHop("https://me2.do/x", 301))
    assert requested_hosts(router) == {"han.gl", "me2.do"}


def test_head_not_allowed_falls_back_to_get(resolver, router):
    router.head("https://bit.ly/a").respond(405)
    get = router.get("https://bit.ly/a").respond(302, headers={"Location": "https://x.example/"})
    r = resolve(resolver, "https://bit.ly/a")
    assert r.final_url == "https://x.example/" and r.complete
    assert r.hops == (RedirectHop("https://bit.ly/a", 302),)
    assert get.calls.last.request.headers["User-Agent"] == BROWSER_UA


@pytest.mark.parametrize("status", [400, 403, 405, 501])
def test_head_fallback_statuses(resolver, router, status):
    router.head("https://bit.ly/a").respond(status)
    get = router.get("https://bit.ly/a").respond(301, headers={"Location": "https://x.example/"})
    assert resolve(resolver, "https://bit.ly/a").complete
    assert get.called


@pytest.mark.parametrize("status", [404, 410, 429, 500, 503])
def test_other_head_errors_do_not_fall_back(resolver, router, status):
    router.head("https://bit.ly/a").respond(status)
    get = router.get("https://bit.ly/a").respond(301, headers={"Location": "https://x.example/"})
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "no_redirect_from_shortener"
    assert not get.called


class _TrackingStream(httpx.SyncByteStream):
    def __init__(self):
        self.iterated = False
        self.closed = False

    def __iter__(self):
        self.iterated = True
        yield b"body that must not be read"

    def close(self):
        self.closed = True


def test_get_fallback_does_not_read_body(resolver, router):
    stream = _TrackingStream()
    router.head("https://bit.ly/a").respond(405)
    router.get("https://bit.ly/a").mock(
        return_value=httpx.Response(302, headers={"Location": "https://x.example/"}, stream=stream)
    )
    r = resolve(resolver, "https://bit.ly/a")
    assert r.final_url == "https://x.example/"
    assert stream.closed is True
    assert stream.iterated is False


def test_relative_location(resolver, router):
    router.head("https://bit.ly/a").respond(302, headers={"Location": "/b"})
    router.head("https://bit.ly/b").respond(302, headers={"Location": "https://x.example/"})
    r = resolve(resolver, "https://bit.ly/a")
    assert r.final_url == "https://x.example/" and r.complete
    assert [h.url for h in r.hops] == ["https://bit.ly/a", "https://bit.ly/b"]
    assert requested_hosts(router) == {"bit.ly"}


def test_nondefault_port_and_userinfo_requested_as_given(resolver, router):
    route = router.head("https://u:p@bit.ly:8443/a").respond(
        302, headers={"Location": "https://x.example/"}
    )
    r = resolve(resolver, "https://u:p@bit.ly:8443/a")
    assert r.complete and r.final_url == "https://x.example/"
    assert route.called


# ---------------------------------------------------------------- resolve: failure modes


def test_redirect_loop(resolver, router):
    router.head("https://bit.ly/a").respond(302, headers={"Location": "https://bit.ly/b"})
    router.head("https://bit.ly/b").respond(302, headers={"Location": "https://bit.ly/a"})
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "redirect_loop" and not r.complete
    assert [h.url for h in r.hops] == ["https://bit.ly/a", "https://bit.ly/b"]


def test_self_redirect_is_loop(resolver, router):
    router.head("https://bit.ly/a").respond(301, headers={"Location": "https://bit.ly/a"})
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "redirect_loop" and not r.complete
    assert r.final_url == "https://bit.ly/a"
    assert len(router.calls) == 1


def test_too_many_redirects(router):
    resolver = make_resolver(max_hops=2)
    router.head("https://bit.ly/1").respond(302, headers={"Location": "https://bit.ly/2"})
    router.head("https://bit.ly/2").respond(302, headers={"Location": "https://bit.ly/3"})
    three = router.head("https://bit.ly/3").respond(302, headers={"Location": "https://x.example/"})
    r = resolve(resolver, "https://bit.ly/1")
    assert r.error == "too_many_redirects" and not r.complete
    assert len(r.hops) == 2 and r.final_url == "https://bit.ly/3"
    assert not three.called


def test_shortener_200_is_incomplete(resolver, router):
    router.head("https://bit.ly/a").respond(200)
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "no_redirect_from_shortener" and not r.complete
    assert r.final_url == "https://bit.ly/a" and r.hops == () and r.is_shortener


@pytest.mark.parametrize("headers", [{}, {"Location": ""}])
def test_redirect_without_usable_location(resolver, router, headers):
    router.head("https://bit.ly/a").respond(302, headers=headers)
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "no_redirect_from_shortener" and not r.complete
    assert r.hops == ()


def test_timeout_is_network_error(resolver, router):
    router.head("https://bit.ly/a").mock(side_effect=httpx.ConnectTimeout("t"))
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "network_error" and not r.complete and r.final_url == "https://bit.ly/a"


def test_invalid_url_exception_is_network_error(resolver, router):
    router.head("https://bit.ly/a").mock(side_effect=httpx.InvalidURL("bad"))
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "network_error" and not r.complete


def test_protocol_error_without_redirect_is_network_error(resolver, router):
    router.head("https://bit.ly/a").mock(side_effect=httpx.RemoteProtocolError("bad"))
    assert resolve(resolver, "https://bit.ly/a").error == "network_error"


def test_network_error_during_get_fallback(resolver, router):
    router.head("https://bit.ly/a").respond(405)
    router.get("https://bit.ly/a").mock(side_effect=httpx.ReadTimeout("t"))
    assert resolve(resolver, "https://bit.ly/a").error == "network_error"


def test_blocks_private_resolution(router):
    route = router.head("https://bit.ly/a").respond(302, headers={"Location": "https://x.example/"})
    r = make_resolver(resolve=lambda h: ["10.0.0.1"]).resolve(normalize_url("https://bit.ly/a"))
    assert r.error == "blocked_private_address" and not r.complete
    assert route.called is False


@pytest.mark.parametrize("addresses", [[PUBLIC_IP, "127.0.0.1"], ["64:ff9b::a00:1"], ["garbage"]])
def test_any_bad_address_blocks(router, addresses):
    route = router.head("https://bit.ly/a").respond(302, headers={"Location": "https://x.example/"})
    r = make_resolver(resolve=lambda h: addresses).resolve(normalize_url("https://bit.ly/a"))
    assert r.error == "blocked_private_address"
    assert route.called is False


def test_empty_resolution_is_dns_error(router):
    route = router.head("https://bit.ly/a").respond(302, headers={"Location": "https://x.example/"})
    r = make_resolver(resolve=lambda h: []).resolve(normalize_url("https://bit.ly/a"))
    assert r.error == "dns_error" and route.called is False


@pytest.mark.parametrize(
    "exc", [OSError("nxdomain"), socket.gaierror(-2, "nxdomain"), UnicodeError("x")]
)
def test_dns_failure(router, exc):
    def boom(host):
        raise exc

    r = make_resolver(resolve=boom).resolve(normalize_url("https://bit.ly/a"))
    assert r.error == "dns_error" and not r.complete
    assert not router.calls


def test_second_hop_is_also_address_checked(router):
    router.head("https://bit.ly/a").respond(302, headers={"Location": "https://me2.do/b"})
    second = router.head("https://me2.do/b").respond(302, headers={"Location": "https://x.example/"})
    resolver = make_resolver(resolve=lambda h: ["10.0.0.1"] if h == "me2.do" else [PUBLIC_IP])
    r = resolver.resolve(normalize_url("https://bit.ly/a"))
    assert r.error == "blocked_private_address" and r.final_url == "https://me2.do/b"
    assert r.hops == (RedirectHop("https://bit.ly/a", 302),)
    assert second.called is False


# ---------------------------------------------------------------- Location parsing


def test_javascript_location_is_invalid(resolver, router):
    router.head("https://bit.ly/a").respond(302, headers={"Location": "javascript:alert(1)"})
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "invalid_location" and not r.complete
    assert r.final_url == "https://bit.ly/a" and r.hops == ()


@pytest.mark.parametrize(
    "location",
    [
        "\\\\evil.example\\x",
        "//evil.example/x",
        "/\\evil.example/x",
        "\thttps://evil.example/x\r\n",
        "ht\ttps://evil.example/x",
        "https:\r\n//evil.example/x",
        " https://evil.example/x \x1f",
    ],
)
def test_location_is_read_like_a_browser(resolver, router, location):
    # httpx rejects raw CR/LF in header values only when sending; the mock hands them back as-is.
    router.head("https://bit.ly/a").respond(302, headers={"Location": location})
    r = resolve(resolver, "https://bit.ly/a")
    assert r.complete and r.error is None
    assert r.final_url == "https://evil.example/x"
    assert requested_hosts(router) == {"bit.ly"}  # evil.example was never contacted


def test_backslash_after_query_is_kept(resolver, router):
    router.head("https://bit.ly/a").respond(
        302, headers={"Location": "https://x.example/p?next=a\\b"}
    )
    r = resolve(resolver, "https://bit.ly/a")
    assert r.final_url == "https://x.example/p?next=a\\b"


# ---------------------------------------------------------------- never raises (fix round 1)

_BAD_LOCATIONS = [
    "https://evil.example]/x",
    "https://evil.example[@bit.ly/",
    "//[evil",
    "https://[::1/x",
]


@pytest.mark.parametrize("location", _BAD_LOCATIONS)
def test_malformed_netloc_location_is_invalid(resolver, router, location):
    router.head("https://bit.ly/a").respond(302, headers={"Location": location})
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "invalid_location" and not r.complete
    assert r.final_url == "https://bit.ly/a" and r.hops == ()


def test_utf8_nfkc_delimiter_location_does_not_raise(resolver, router):
    raw = "https://ex℀ample.com@bit.ly/".encode()
    router.head("https://bit.ly/a").mock(
        return_value=httpx.Response(302, headers=[(b"Location", raw)])
    )
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "invalid_location" and not r.complete


_BAD_ALABELS = ["https://xn--zz.bit.ly/a", "https://xn--bit-ly.bit.ly/a"]


@pytest.mark.parametrize("url", _BAD_ALABELS)
def test_invalid_alabel_input_url_is_network_error(resolver, router, url):
    r = resolve(resolver, url)
    assert r.error == "network_error" and not r.complete
    assert r.final_url == url
    assert not router.calls


@pytest.mark.parametrize("target", _BAD_ALABELS)
def test_invalid_alabel_location_target_is_network_error(resolver, router, target):
    router.head("https://bit.ly/a").respond(302, headers={"Location": target})
    r = resolve(resolver, "https://bit.ly/a")
    assert r.error == "network_error" and not r.complete
    # httpx itself rejects the invalid A-label while building its redirect request, so the
    # failure surfaces during the request to bit.ly; either way it is a contained network_error.
    assert requested_hosts(router) == {"bit.ly"}


def test_fuzzed_locations_never_raise(resolver, router):
    import random

    rng = random.Random(42)
    alphabet = (
        list("[]@\\%/?#:.&=;")
        + ["xn--", "xn--zz", "bit.ly", "evil.example", "https://", "//", "http:", "℀", "é", "\u0000", "\t", "\r", "\n", "\x7f", "‮"]
        + [chr(c) for c in range(0, 32)]
    )
    for _ in range(300):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 12)))
        raw = text.encode("utf-8")
        if b"\r" in raw or b"\n" in raw:
            raw = raw.replace(b"\r", b"").replace(b"\n", b"")
        router.reset()
        router.head("https://bit.ly/a").mock(
            return_value=httpx.Response(302, headers=[(b"Location", raw)])
        )
        # Everything else (including later hops) is a shortener 200, never a real host.
        router.head(host__regex=r".*\.?(bit\.ly|me2\.do|han\.gl)$").respond(200)
        result = resolver.resolve(normalize_url("https://bit.ly/a"))
        assert isinstance(result, RedirectResult), text
        assert all(is_shortener_host(h, SHORTENERS) for h in requested_hosts(router))


# ---------------------------------------------------------------- live


@pytest.mark.network
def test_live_shortener():
    short_url = os.environ.get("PHISHGUARD_LIVE_SHORT_URL")
    if not short_url:
        pytest.skip("PHISHGUARD_LIVE_SHORT_URL is not set")
    with httpx.Client(timeout=10.0) as client:
        r = RedirectResolver(SHORTENERS, client).resolve(normalize_url(short_url))
    assert r.is_shortener and r.complete and r.error is None
    assert r.hops
