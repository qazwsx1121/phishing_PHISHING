import random
import socket

import pytest

from phishguard.errors import InvalidURLError
from phishguard.normalize import normalize_url
from phishguard.parse import _extractor, parse_ip_host, parse_url


@pytest.mark.parametrize("host, expected", [
    ("192.168.1.1", "192.168.1.1"), ("3232235777", "192.168.1.1"),
    ("0xc0a80101", "192.168.1.1"), ("0300.0250.1.1", "192.168.1.1"),
    ("127.1", "127.0.0.1"), ("::1", "::1"), ("[::1]", "::1"),
    ("example.com", None), ("1.2.3.4.5", None), ("999.1.1.1", None), ("123.example", None),
    ("0x", "0.0.0.0"), ("0X7F.1", "127.0.0.1"), ("0x7f.1", "127.0.0.1"), ("0", "0.0.0.0"),
    ("192.168.1.1.", "192.168.1.1"),
    ("1.1.1.256", None), ("1..2", None), ("08.1.1.1", None), ("09", None),
    ("1_0.1.1.1", None), ("+1.1.1.1", None), ("-1.1.1.1", None),
    ("１.1.1.1", None), (" 1.1.1.1", None), ("1.1.1.1\n", None),
    ("fe80::1%eth0", None), ("", None), (".", None), ("1.2.3.4..", None),
    ("0x100000000", None), ("4294967295", "255.255.255.255"), ("4294967296", None),
    ("1.2.65536", None), ("1.2.65535", "1.2.255.255"),
])
def test_parse_ip_host(host, expected):
    ip = parse_ip_host(host)
    assert (str(ip) if ip else None) == expected


def test_ipv4_mapped_ipv6_is_ipv6():
    ip = parse_ip_host("::ffff:1.2.3.4")
    assert ip is not None and ip.version == 6


def p(raw):
    return parse_url(normalize_url(raw))


def test_multi_label_suffix():
    r = p("http://www.example.co.kr/")
    assert (r.subdomain, r.domain, r.suffix, r.registered_domain) == ("www", "example", "co.kr", "example.co.kr")


def test_brand_as_subdomain():
    r = p("http://naver.com.login-check.xyz/a")
    assert r.subdomain == "naver.com" and r.registered_domain == "login-check.xyz"


def test_private_suffix_shared_hosting():
    r = p("https://paypal-login.github.io/")
    assert r.registered_domain == "github.io" and r.subdomain == "paypal-login"
    assert r.site_domain == "paypal-login.github.io" and r.is_private_suffix


def test_apex_of_private_suffix_falls_back_to_icann():
    for host in ("github.io", "blogspot.com"):
        r = p(f"https://{host}/")
        assert r.registered_domain == host
        assert r.site_domain == host
        assert r.is_private_suffix is False


def test_ip_host():
    r = p("http://3232235777/login")
    assert r.is_ip and r.registered_domain == ""


@pytest.mark.parametrize("raw", ["http://127.1/", "http://0x7f.1/", "http://[::1]/"])
def test_ip_forms_have_empty_domain_fields(raw):
    n = normalize_url(raw)
    r = parse_url(n)
    assert r.is_ip and not r.is_private_suffix
    assert (r.subdomain, r.domain, r.suffix, r.registered_domain, r.site_domain) == ("",) * 5
    assert r.host == n.host  # host is passed through unchanged, not canonicalised


def test_five_part_dotted_numbers_are_not_ip():
    # Browsers reject this host outright (WHATWG: ends in a number but is not valid IPv4);
    # here it is simply "not an IP" and has no registered domain.
    r = p("http://1.2.3.4.5/")
    assert not r.is_ip and r.registered_domain == ""


def test_no_public_suffix():
    assert p("http://localhost/").registered_domain == ""


def test_host_that_is_only_a_public_suffix():
    r = p("http://co.kr/")
    assert r.registered_domain == "" and not r.is_ip


def test_wildcard_and_exception_rules():
    # PSL has "*.kawasaki.jp" (wildcard) and "!city.kawasaki.jp" (exception).
    r = p("http://www.city.kawasaki.jp/")  # exception rule: city.kawasaki.jp is registrable
    assert (r.suffix, r.domain, r.subdomain) == ("kawasaki.jp", "city", "www")
    assert r.registered_domain == "city.kawasaki.jp"
    r = p("http://a.b.kawasaki.jp/")  # wildcard rule: b.kawasaki.jp is the suffix
    assert (r.suffix, r.domain, r.subdomain) == ("b.kawasaki.jp", "a", "")
    assert r.registered_domain == "a.b.kawasaki.jp"


def test_korean_idn():
    n = normalize_url("http://예시.한국/")
    r = parse_url(n)
    assert r.suffix == "xn--3e0b707e"
    assert r.registered_domain == n.host


def test_deep_subdomain():
    r = p("http://a.b.c.example.co.kr/")
    assert r.subdomain == "a.b.c" and r.registered_domain == "example.co.kr"


def test_psl_snapshot_makes_no_network_call(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")

    _extractor.cache_clear()
    monkeypatch.setattr(socket, "socket", boom)
    try:
        r = parse_url(normalize_url("https://www.example.co.kr/"), psl_refresh=False)
    finally:
        _extractor.cache_clear()
    assert r.registered_domain == "example.co.kr"


def test_extractors_are_reused():
    assert _extractor(False, False) is _extractor(False, False)
    assert _extractor(True, False) is not _extractor(False, False)


def _random_text(rng):
    pieces = ["0", "1", "255", "256", "0x", "0X", "7f", ".", "..", ":", "::", "[", "]", "%",
              "-", "+", "_", " ", "\n", "１", "08", "xn--", "co.kr", "github.io", "com",
              "http://", "/", "a", "ffff", "é", "한국"]
    if rng.random() < 0.3:
        return "".join(chr(rng.randint(0, 0x2FFF)) for _ in range(rng.randint(0, 30)))
    return "".join(rng.choice(pieces) for _ in range(rng.randint(0, 14)))


def test_fuzz_never_raises():
    rng = random.Random(42)
    parsed = 0
    for _ in range(5000):
        text = _random_text(rng)
        parse_ip_host(text)
        try:
            n = normalize_url(text)
        except InvalidURLError:
            continue
        parse_url(n)
        parsed += 1
    assert parsed > 100
