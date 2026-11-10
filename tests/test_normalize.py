import random

import pytest

from phishguard.errors import InvalidURLError
from phishguard.models import NormalizedURL
from phishguard.normalize import MAX_URL_LENGTH, normalize_url


@pytest.mark.parametrize("raw, expected", [
    ("  HTTPS://WWW.Example.COM:443/Path?q=1#frag ", "https://www.example.com/Path?q=1"),
    ("example.com", "http://example.com/"),
    ("example.com:8080/x", "http://example.com:8080/x"),
    ("http://example.com./", "http://example.com/"),
    ("​http://a.com/﻿", "http://a.com/"),
    ("<http://a.com/b>", "http://a.com/b"),
    ("http://[::1]:8080/", "http://[::1]:8080/"),
])
def test_messy_inputs(raw, expected):                    # Review Focus 3
    assert normalize_url(raw).normalized == expected


def test_scheme_added_flag():
    assert normalize_url("example.com").scheme_added is True
    assert normalize_url("http://example.com").scheme_added is False


def test_refang():
    n = normalize_url("hxxps://evil[.]com/login")
    assert n.normalized == "https://evil.com/login" and n.was_refanged


def test_idn_host_is_punycoded():                        # Review Focus 2
    n = normalize_url("http://네이버.com/")
    assert n.host.startswith("xn--") and n.host.endswith(".com")
    assert normalize_url("http://xn--950bt9s8xi.com/").host == "xn--950bt9s8xi.com"  # 이미 punycode면 그대로


def test_userinfo_is_kept():
    n = normalize_url("http://paypal.com@evil.com/x")
    assert n.userinfo == "paypal.com" and n.host == "evil.com"


@pytest.mark.parametrize("raw", ["", "   ", "javascript:alert(1)", "ftp://a.com/", "http://", "http://a.com:99999/", "data:text/html,x"])
def test_invalid_inputs_raise(raw):
    with pytest.raises(InvalidURLError):
        normalize_url(raw)


def test_too_long():
    with pytest.raises(InvalidURLError, match="너무 깁니다"):
        normalize_url("http://a.com/" + "a" * 2100)


# ---- Controller rulings: parser-differential hardening ----

def test_max_url_length_is_single_definition():
    import phishguard.web.app as app_module
    assert MAX_URL_LENGTH == 2048
    assert app_module.MAX_URL_LENGTH is MAX_URL_LENGTH


def test_backslash_before_at_does_not_hide_real_host():
    n = normalize_url("http://evil.com\\@naver.com/")
    assert n.host == "evil.com"
    assert n.userinfo == ""


def test_backslashes_scheme_and_path_but_query_untouched():
    n = normalize_url("http:\\\\evil.com\\a?x=\\y")
    assert n.host == "evil.com"
    assert n.path == "/a"
    assert n.query == "x=\\y"


def test_backslash_in_fragment_untouched_and_dropped():
    n = normalize_url("http://a.com/p#frag\\x")
    assert n.normalized == "http://a.com/p"


def test_backslash_replaced_without_refang():
    n = normalize_url("http://evil.com\\@naver.com/", refang=False)
    assert n.host == "evil.com"


@pytest.mark.parametrize("raw", [
    "ht\ttp://evil.com/",
    "http://ev\nil.com/",
    "http://evil.com/\r\n",
    "ht\r\ntp://ev\til.com/",
])
def test_tab_cr_lf_removed_anywhere(raw):
    assert normalize_url(raw).host == "evil.com"


@pytest.mark.parametrize("raw", [
    "\x00http://evil.com",
    "\x01\x1f http://evil.com \x00",
    "　http://evil.com　",
])
def test_control_and_whitespace_stripped(raw):
    assert normalize_url(raw).host == "evil.com"


@pytest.mark.parametrize("raw", [
    "http:/evil.com", "http:///evil.com", "http:evil.com",
    "HTTP:evil.com", "https:////evil.com",
])
def test_slashes_after_scheme_normalised(raw):
    n = normalize_url(raw)
    assert n.host == "evil.com"
    assert n.scheme in ("http", "https")


def test_slashes_after_scheme_keeps_path():
    assert normalize_url("https:/evil.com/a/b").normalized == "https://evil.com/a/b"


@pytest.mark.parametrize("raw, expected", [
    ("(http://evil.com/a)", "http://evil.com/a"),
    ('"http://evil.com/a"', "http://evil.com/a"),
    ("'http://evil.com/a'", "http://evil.com/a"),
    (" < http://evil.com/a > ", "http://evil.com/a"),
])
def test_wrapping_pairs_removed(raw, expected):
    assert normalize_url(raw).normalized == expected


def test_only_one_wrapping_pair_removed():
    with pytest.raises(InvalidURLError):
        normalize_url("<<http://evil.com/a>>")


def test_scheme_split_by_tab_is_still_rejected():
    with pytest.raises(InvalidURLError):
        normalize_url("java\tscript:alert(1)")


@pytest.mark.parametrize("raw", [
    "see http://evil.com/x",
    "http://evil%2ecom/",
    "http://[bad/",
    "http://exa mple.com/",
    "http://a.com]/",
    "http://[::1/",
    "http://ev!l.com/",
])
def test_garbage_hosts_rejected(raw):
    with pytest.raises(InvalidURLError):
        normalize_url(raw)


def test_urlsplit_value_error_becomes_invalid_url_error():
    # NFKC netloc check inside urlsplit raises ValueError for "＃" (fullwidth #).
    with pytest.raises(InvalidURLError, match="올바른 URL 형식이 아닙니다."):
        normalize_url("http://a.com＃@b.com/")


def test_userinfo_is_everything_before_last_at():
    n = normalize_url("http://paypal.com@x@evil.com/")
    assert n.userinfo == "paypal.com@x"
    assert n.host == "evil.com"
    assert n.normalized == "http://paypal.com@x@evil.com/"


def test_idn_trailing_ideographic_dot_stripped():
    n = normalize_url("http://네이버.com。/")
    assert not n.host.endswith(".")
    assert n.host.startswith("xn--")
    assert n.normalized.endswith(".com/")


def test_multiple_trailing_dots_stripped():
    assert normalize_url("http://a.com.../").host == "a.com"


def test_port_zero_is_kept():
    n = normalize_url("http://a.com:0/")
    assert n.port == 0
    assert n.normalized == "http://a.com:0/"


def test_default_ports_dropped_other_kept():
    assert normalize_url("http://a.com:80/").port is None
    assert normalize_url("https://a.com:443/").port is None
    assert normalize_url("https://a.com:80/").port == 80


def test_refang_false_does_not_refang():
    # Documented behaviour: with refang=False the "hxxp" scheme is not rewritten,
    # so the non-http(s) scheme is rejected with InvalidURLError.
    with pytest.raises(InvalidURLError):
        normalize_url("hxxp://evil[.]com", refang=False)
    # And a refang-able bracketed host without hxxp must not be refanged either.
    try:
        n = normalize_url("http://evil[.]com", refang=False)
    except InvalidURLError:
        pass
    else:  # pragma: no cover - would be a bug
        assert n.was_refanged is False


def test_refang_mixed_case_and_bracketed_colon():
    n = normalize_url("HXXPS://evil(.)com[:]8080/")
    assert n.normalized == "https://evil.com:8080/"
    assert n.was_refanged is True
    assert n.scheme == "https"
    assert n.port == 8080


def test_refang_braces_dot():
    n = normalize_url("http://evil{.}com/")
    assert n.host == "evil.com" and n.was_refanged


def test_no_refang_flag_false_for_clean_url():
    assert normalize_url("http://a.com/").was_refanged is False


def test_returns_normalized_url_with_original():
    raw = "  http://A.com/x  "
    n = normalize_url(raw)
    assert isinstance(n, NormalizedURL)
    assert n.original == raw


def test_path_and_query_case_preserved_and_empty_path_slash():
    n = normalize_url("http://A.com?Q=Ab")
    assert n.path == "/" and n.query == "Q=Ab"
    assert n.normalized == "http://a.com/?Q=Ab"


def test_empty_after_cleanup():
    for raw in ["​", "\x00", "<>", "()", "\t\n"]:
        with pytest.raises(InvalidURLError):
            normalize_url(raw)


def test_ipv6_host_is_bracketed():
    n = normalize_url("http://[2001:db8::1]/x")
    assert n.host == "2001:db8::1"
    assert n.normalized == "http://[2001:db8::1]/x"


# ---- Fuzz: only InvalidURLError may escape ----

_FRAGMENTS = [
    "http://", "https://", "http:", "hxxp://", "HXXPS://", "ftp://", "javascript:",
    "evil", "naver", "com", ".", "..", "。", "[.]", "(.)", "{.}", "[:]", "[", "]", "(", ")",
    "<", ">", '"', "'", "@", ":", "/", "//", "\\", "\\\\", "?", "#", "%", "%2e", "%40", "%zz",
    "\t", "\r", "\n", "\x00", "\x1f", " ", "​", "﻿", "　",
    "네이버", "xn--", "xn--950bt9s8xi", "ＡＢＣ", "／", "＠", "＃", "：", "．",
    "::1", "[::1]", "[bad", "99999", "0", "8080", "a" * 70, "-", "_", "é", "ß", "İ",
]


def _random_text(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.4:
        n = rng.randint(0, 40)
        return "".join(chr(rng.choice([
            rng.randint(0, 0x7F), rng.randint(0, 0x7F), rng.randint(0x80, 0x2FFF),
            rng.randint(0xFF00, 0xFFEF), rng.randint(0, 0x20),
        ])) for _ in range(n))
    parts = [rng.choice(_FRAGMENTS) for _ in range(rng.randint(1, 12))]
    return "".join(parts)


def test_fuzz_only_invalid_url_error_escapes():
    rng = random.Random(42)
    ok = 0
    for _ in range(5000):
        text = _random_text(rng)
        for refang in (True, False):
            try:
                n = normalize_url(text, refang=refang)
            except InvalidURLError:
                continue
            ok += 1
            assert isinstance(n, NormalizedURL)
            assert n.scheme in ("http", "https")
            assert n.host
            assert n.normalized.startswith(n.scheme + "://")
    assert ok > 0
