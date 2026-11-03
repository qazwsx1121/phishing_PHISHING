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
