import random
import re

import pytest

from phishguard.models import Verdict
from phishguard.web.presenters import VERDICT_LABELS, defang


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://evil.com/login", "hxxps://evil[.]com/login"),
        ("http://a.b.c/x.html", "hxxp://a[.]b[.]c/x.html"),
        ("http://1.2.3.4/", "hxxp://1[.]2[.]3[.]4/"),
        # scheme match is case-insensitive
        ("HTTP://a.com", "hxxp://a[.]com"),
        ("HttpS://A.com/X", "hxxps://A[.]com/X"),
        # malformed scheme separators must not leave a live scheme or host
        ("http:/a.com/x", "hxxp:/a[.]com/x"),
        ("http:///a.com/x", "hxxp:///a[.]com/x"),
        ("//a.com/x", "//a[.]com/x"),
        # no scheme: the host dots are still defanged
        ("evil.com/login", "evil[.]com/login"),
        ("evil.com", "evil[.]com"),
        ("httpbin.org/get", "httpbin[.]org/get"),
        # other schemes are kept as written
        ("ftp://a.com/f.txt", "ftp://a[.]com/f.txt"),
        # dots outside the host (path, query, fragment) stay unchanged
        ("http://a.com/p.html?x=a.b#c.d", "hxxp://a[.]com/p.html?x=a.b#c.d"),
        ("evil.com?x=a.b", "evil[.]com?x=a.b"),
        ("evil.com#f.x", "evil[.]com#f.x"),
        ("http://a.com/@x.y/z", "hxxp://a[.]com/@x.y/z"),
        ("http://a.com:8080/x.y", "hxxp://a[.]com:8080/x.y"),
        # userinfo: only the part after the last "@" is the host
        ("http://user.name:pw@a.b.com/x", "hxxp://user.name:pw@a[.]b[.]com/x"),
        ("http://a@b@c.com/x", "hxxp://a@b@c[.]com/x"),
        ("http://paypal.com@evil.com/", "hxxp://paypal.com@evil[.]com/"),
        # surrounding whitespace is dropped
        ("  http://a.com/x  ", "hxxp://a[.]com/x"),
        # already defanged input stays as it is
        ("hxxps://evil[.]com/login", "hxxps://evil[.]com/login"),
    ],
)
def test_defang(url, expected):
    assert defang(url) == expected


@pytest.mark.parametrize(
    "url, expected",
    [
        # text before the scheme must not hide the URL
        ("(http://evil.com)", "(hxxp://evil[.]com)"),
        ("<http://evil.com/a>", "<hxxp://evil[.]com/a>"),
        ('"http://evil.com"', '"hxxp://evil[.]com"'),
        ("see http://evil.com/x", "see hxxp://evil[.]com/x"),
        ("\x00http://evil.com", "\x00hxxp://evil[.]com"),
        ("xhttp://evil.com", "xhxxp://evil[.]com"),
        ("xhttp:///evil.com/a", "xhxxp:///evil[.]com/a"),
        ("see HTTPS://Evil.com/x and http://b.org", "see hxxps://Evil[.]com/x and hxxp://b[.]org"),
        ("http:evil.com/a.b", "hxxp:evil[.]com/a.b"),
        # a second URL inside another URL's path, query or authority
        ("http://a.com/r?u=http://b.com/x.y", "hxxp://a[.]com/r?u=hxxp://b[.]com/x.y"),
        ("http://a.com/go/https://b.com/p.q", "hxxp://a[.]com/go/hxxps://b[.]com/p.q"),
        ("HTTP://a.com/x?next=HTTPS://b.com", "hxxp://a[.]com/x?next=hxxps://b[.]com"),
        ("http://a.com#http://b.com/c.d", "hxxp://a[.]com#hxxp://b[.]com/c.d"),
        ("http://a.com:http://b.com", "hxxp://a[.]com:hxxp://b[.]com"),
        # a dotted pseudo-scheme is a host-like name too
        ("evil.com://x.y", "evil[.]com://x[.]y"),
        ("a.b.c://x.y/z.w", "a[.]b[.]c://x[.]y/z.w"),
        ("see evil.com://x.y", "see evil[.]com://x[.]y"),
        # other schemes with extra slashes still reach the host
        ("ftp:///evil.com/f.txt", "ftp:///evil[.]com/f.txt"),
    ],
)
def test_defang_urls_embedded_in_other_text(url, expected):
    assert defang(url) == expected


_LIVE_SCHEME = re.compile(r"https?:", re.IGNORECASE)
_FUZZ_PIECES = [
    "http://", "HTTPS://", "hxxp://", "hXXps:/", "http:", "://", ":///", "[.]", "[", "]",
    "evil.com", "a.b", ".", "@", "?", "#", "/", " ", "(", ")", '"', "<", ">", "\x00", "x",
    "1", "-", "+", ":",
]


def test_defang_leaves_no_live_http_scheme_in_random_text():
    rng = random.Random(42)
    for _ in range(3000):
        text = "".join(rng.choice(_FUZZ_PIECES) for _ in range(rng.randint(1, 10)))
        out = defang(text)
        assert not _LIVE_SCHEME.search(out), (text, out)
        assert defang(out) == out, (text, out)


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "http",
        "http:",
        "http://",
        "https:///",
        "//",
        "@",
        "@@@",
        "http://@",
        "http://@/",
        "?",
        "#",
        "...",
        "\x00",
        "\n\t",
        "\ud800",
        "💥.com/💥.x",
        "http://[::1]:80/a.b",
        "a" * 10000,
        "." * 10000,
        "(http://",
        "a" * 10000 + "://" + "b." * 5000,
        "http:" * 2000,
        "http://" * 2000,
        "/" * 10000,
        "@" * 10000,
    ],
)
def test_defang_never_raises_and_is_idempotent(text):
    once = defang(text)
    assert isinstance(once, str)
    assert defang(once) == once


def test_verdict_labels_cover_every_verdict():
    assert VERDICT_LABELS == {
        Verdict.SAFE: "안전",
        Verdict.SUSPICIOUS: "주의",
        Verdict.DANGEROUS: "위험",
    }
    assert set(VERDICT_LABELS) == set(Verdict)
