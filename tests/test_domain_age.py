import sqlite3
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

import phishguard.domain_age as da
from phishguard.cache import TTLCache
from phishguard.domain_age import (
    BOOTSTRAP_FAILURE_TTL,
    IANA_RDAP_BOOTSTRAP,
    DomainAgeLookup,
    parse_rdap_registration,
    whois_creation_date,
)

UTC = timezone.utc
BOOT = {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
NOW = datetime(2024, 1, 12, 3, 4, 5, tzinfo=UTC)
RDAP_URL = "https://rdap.verisign.com/com/v1/domain/example.com"


def rdap_body(date="2024-01-02T03:04:05Z"):
    return {"events": [{"eventAction": "registration", "eventDate": date}]}


@pytest.fixture
def router():
    # NB: `@respx.mock(...)` as a decorator builds a private router that module-level
    # `respx.get` routes do not belong to, so use an explicit router instead.
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as r:
        yield r


_CLIENT: httpx.Client | None = None


@pytest.fixture(scope="module", autouse=True)
def _shared_client():
    # One client for the module: building one per test costs ~0.3 s (SSL context).
    global _CLIENT
    _CLIENT = httpx.Client()
    yield
    _CLIENT.close()
    _CLIENT = None


@pytest.fixture
def cache():
    c = TTLCache(":memory:")
    yield c
    c.close()


def make(cache, whois_fn=lambda d: None, now=lambda: NOW, **kw):
    return DomainAgeLookup(cache, _CLIENT, whois_fn=whois_fn, now=now, **kw)


# ---------- parse_rdap_registration ----------

def test_parse_rdap_registration():
    p = {"events": [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": "2024-01-02T03:04:05Z"}]}
    assert parse_rdap_registration(p) == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_parse_earliest_of_several_registration_events():
    p = {"events": [{"eventAction": "registration", "eventDate": "2024-01-02T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": "2001-05-06T00:00:00+02:00"},
                    {"eventAction": "registration", "eventDate": "garbage"}]}
    assert parse_rdap_registration(p) == datetime(2001, 5, 5, 22, 0, tzinfo=UTC)


def test_parse_naive_date_is_utc():
    p = {"events": [{"eventAction": "registration", "eventDate": "2024-01-02T03:04:05"}]}
    assert parse_rdap_registration(p) == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)


@pytest.mark.parametrize("payload", [
    [], "x", None, 5, {}, {"events": None}, {"events": "registration"}, {"events": {"a": 1}},
    {"events": ["registration", None, 3]},
    {"events": [{"eventAction": "registration", "eventDate": 20240102}]},
    {"events": [{"eventAction": "registration", "eventDate": None}]},
    {"events": [{"eventAction": "registration"}]},
    {"events": [{"eventAction": "registration", "eventDate": "not-a-date"}]},
    {"events": [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}]},
])
def test_parse_malformed_payloads_return_none(payload):
    assert parse_rdap_registration(payload) is None


@pytest.mark.parametrize("bad", ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"])
def test_parse_overflowing_date_alone_is_none(bad):
    p = {"events": [{"eventAction": "registration", "eventDate": bad}]}
    assert parse_rdap_registration(p) is None


@pytest.mark.parametrize("bad", ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"])
def test_parse_overflowing_date_does_not_hide_valid_event(bad):
    p = {"events": [{"eventAction": "registration", "eventDate": bad},
                    {"eventAction": "registration", "eventDate": "2020-05-05T00:00:00Z"}]}
    assert parse_rdap_registration(p) == datetime(2020, 5, 5, tzinfo=UTC)


def test_parse_skips_placeholder_before_min():
    p = {"events": [{"eventAction": "registration", "eventDate": "1970-01-01T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": "2020-05-05T00:00:00Z"}]}
    assert parse_rdap_registration(p) == datetime(2020, 5, 5, tzinfo=UTC)


def test_parse_only_placeholder_is_none():
    p = {"events": [{"eventAction": "registration", "eventDate": "1970-01-01T00:00:00Z"}]}
    assert parse_rdap_registration(p) is None


# ---------- whois_creation_date ----------

class _Entry:
    def __init__(self, creation_date):
        self.creation_date = creation_date


def test_whois_mixed_list_is_normalised(monkeypatch):
    mixed = [
        datetime(2020, 6, 1),                                           # naive -> UTC
        datetime(2019, 1, 1, 12, tzinfo=timezone(timedelta(hours=2))),  # aware
        "2001-01-01", None, 42,                                         # ignored
    ]
    monkeypatch.setattr(da.whois, "whois", lambda domain, **kw: _Entry(mixed))
    assert whois_creation_date("example.com") == datetime(2019, 1, 1, 10, tzinfo=UTC)


def test_whois_overflowing_entry_does_not_hide_valid_one(monkeypatch):
    overflow = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5)))
    mixed = [overflow, datetime(9999, 12, 31, 23, tzinfo=timezone(timedelta(hours=-5))),
             datetime(2019, 3, 3)]
    monkeypatch.setattr(da.whois, "whois", lambda domain, **kw: _Entry(mixed))
    assert whois_creation_date("example.com") == datetime(2019, 3, 3, tzinfo=UTC)


def test_whois_skips_placeholder_before_min(monkeypatch):
    mixed = [datetime(1970, 1, 1), datetime(2019, 3, 3)]
    monkeypatch.setattr(da.whois, "whois", lambda domain, **kw: _Entry(mixed))
    assert whois_creation_date("example.com") == datetime(2019, 3, 3, tzinfo=UTC)


def test_whois_only_placeholder_is_none(monkeypatch):
    monkeypatch.setattr(da.whois, "whois", lambda domain, **kw: _Entry([datetime(1970, 1, 1)]))
    assert whois_creation_date("example.com") is None


def test_whois_single_naive_datetime(monkeypatch):
    monkeypatch.setattr(da.whois, "whois", lambda domain, **kw: _Entry(datetime(2020, 1, 1)))
    assert whois_creation_date("example.com") == datetime(2020, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize("value", [None, [], ["x", None], "2020-01-01"])
def test_whois_no_usable_date_is_none(monkeypatch, value):
    monkeypatch.setattr(da.whois, "whois", lambda domain, **kw: _Entry(value))
    assert whois_creation_date("example.com") is None


def test_whois_exception_is_none(monkeypatch):
    def boom(domain, **kw):
        raise RuntimeError("down")

    monkeypatch.setattr(da.whois, "whois", boom)
    assert whois_creation_date("example.com") is None


def test_whois_passes_timeout_and_quiet_when_supported(monkeypatch):
    seen = {}

    def fake(url, quiet=False, timeout=10):
        seen.update(quiet=quiet, timeout=timeout)
        return _Entry(datetime(2020, 1, 1, tzinfo=UTC))

    monkeypatch.setattr(da.whois, "whois", fake)
    whois_creation_date("example.com")
    assert seen == {"quiet": True, "timeout": da.WHOIS_SOCKET_TIMEOUT}
    assert da.WHOIS_SOCKET_TIMEOUT == 8


def test_whois_does_not_pass_unsupported_kwargs(monkeypatch):
    monkeypatch.setattr(da.whois, "whois", lambda url: _Entry(datetime(2020, 1, 1, tzinfo=UTC)))
    assert whois_creation_date("example.com") == datetime(2020, 1, 1, tzinfo=UTC)


# ---------- lookup: brief scenarios ----------

def test_rdap_success_and_cache_hit(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    route = router.get(RDAP_URL).respond(json=rdap_body())
    lk = make(cache)
    first = lk.lookup("example.com")
    assert first.source == "rdap" and first.age_days == pytest.approx(10.0) and not first.cached
    second = lk.lookup("example.com")
    assert second.cached and route.call_count == 1
    assert second.source == "rdap" and second.age_days == pytest.approx(10.0)


def test_cached_age_is_recomputed_from_now(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(json=rdap_body())
    t = [NOW]
    lk = make(cache, now=lambda: t[0])
    lk.lookup("example.com")
    t[0] = NOW + timedelta(days=5)
    assert lk.lookup("example.com").age_days == pytest.approx(15.0)


def test_rdap_404_falls_back_to_whois(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(404)
    info = make(cache, whois_fn=lambda d: datetime(2020, 1, 1, tzinfo=UTC)).lookup("example.com")
    assert info.source == "whois" and info.creation_date == datetime(2020, 1, 1, tzinfo=UTC)
    assert info.age_days is not None and info.error is None


def test_all_sources_fail_returns_unknown(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    route = router.get(RDAP_URL).mock(side_effect=httpx.ConnectTimeout("t"))
    lk = make(cache)
    first = lk.lookup("example.com")
    assert first.age_days is None and first.source == "none" and first.error == "lookup_failed"
    second = lk.lookup("example.com")
    assert second.cached and second.age_days is None and second.error == "lookup_failed"
    assert route.call_count == 1


def test_rate_limited_uses_short_ttl(router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    route = router.get(RDAP_URL).respond(429)
    t = [1000.0]
    cache = TTLCache(":memory:", now=lambda: t[0])
    whois_calls = []
    lk = DomainAgeLookup(cache, _CLIENT, whois_fn=lambda d: whois_calls.append(d),
                         now=lambda: NOW)
    info = lk.lookup("example.com")
    assert info.error == "rate_limited" and info.source == "none"
    assert whois_calls == ["example.com"]  # WHOIS still tried after a 429
    t[0] += 3000
    assert lk.lookup("example.com").cached
    assert route.call_count == 1
    t[0] += 601  # 3601 s after the first lookup
    assert not lk.lookup("example.com").cached
    assert route.call_count == 2
    cache.close()


def test_rate_limited_then_whois_success_is_positive(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(429)
    info = make(cache, whois_fn=lambda d: datetime(2020, 1, 1, tzinfo=UTC)).lookup("example.com")
    assert info.source == "whois" and info.error is None


def test_whois_timeout_returns_quickly(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(404)
    lk = make(cache, whois_fn=lambda d: time.sleep(3), timeout=0.5)
    start = time.monotonic()
    info = lk.lookup("example.com")
    assert time.monotonic() - start < 1.5
    assert info.error == "lookup_failed" and info.age_days is None


def test_tld_not_in_bootstrap_uses_whois(cache, router):
    route = router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    seen = []

    def fake_whois(d):
        seen.append(d)
        return datetime(2005, 1, 1, tzinfo=UTC)

    info = make(cache, whois_fn=fake_whois).lookup("kisa.or.kr")
    assert info.source == "whois" and seen == ["kisa.or.kr"]
    assert route.call_count == 1


@pytest.mark.parametrize("arg", ["", "localhost"])
def test_not_a_domain_makes_no_request(cache, arg, router):
    info = make(cache).lookup(arg)
    assert info.error == "not_a_domain" and info.source == "none" and info.domain == arg
    assert len(router.calls) == 0


# ---------- ruling 1: argument validation ----------

@pytest.mark.parametrize("arg", [
    "example.com/../x", "a b.com", "example.com?x", "exa mple.com", "-", "a..com",
    "a." + "b" * 300 + ".com", "bücher.de", ".com", "a.b..", "..", "example.com\nx",
])
def test_invalid_domains_rejected_without_any_access(arg, router):
    class Boom(TTLCache):
        def get(self, key):
            raise AssertionError("cache touched")

        def set(self, key, value, ttl_seconds):
            raise AssertionError("cache touched")

    c = Boom(":memory:")
    whois_calls = []
    lk = DomainAgeLookup(c, _CLIENT, whois_fn=lambda d: whois_calls.append(d),
                         now=lambda: NOW)
    info = lk.lookup(arg)
    c.close()
    assert info.error == "not_a_domain" and info.domain == arg
    assert len(router.calls) == 0 and whois_calls == []


def test_domain_is_normalised_before_lookup(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    route = router.get(RDAP_URL).respond(json=rdap_body())
    info = make(cache).lookup("  Example.COM. ")
    assert route.call_count == 1 and info.domain == "example.com" and info.source == "rdap"


# ---------- ruling 2: never raises ----------

class _BrokenCache(TTLCache):
    def get(self, key):
        raise sqlite3.OperationalError("locked")

    def set(self, key, value, ttl_seconds):
        raise sqlite3.OperationalError("locked")


def test_cache_errors_are_survived(router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(json=rdap_body())
    c = _BrokenCache(":memory:")
    lk = DomainAgeLookup(c, _CLIENT, whois_fn=lambda d: None, now=lambda: NOW)
    info = lk.lookup("example.com")
    c.close()
    assert info.source == "rdap" and info.age_days == pytest.approx(10.0)


@pytest.mark.parametrize("boot", [
    [], "x", {}, {"services": None}, {"services": {"a": 1}}, {"services": ["x"]},
    {"services": [[["com"]]]}, {"services": [[["com"], []]]},
    {"services": [[["com"], [5]]]}, {"services": [[[5], ["https://x/"]]]},
    {"services": [[["com"], "https://x/"]]},
])
def test_malformed_bootstrap_falls_back_to_whois(cache, boot, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=boot)
    info = make(cache, whois_fn=lambda d: datetime(2020, 1, 1, tzinfo=UTC)).lookup("example.com")
    assert info.source == "whois"


@pytest.mark.parametrize("body", [[], "x", {"events": "x"}, {"events": [1]}, {"nothing": 1}])
def test_malformed_rdap_body_falls_back_to_whois(cache, body, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(json=body)
    info = make(cache, whois_fn=lambda d: datetime(2020, 1, 1, tzinfo=UTC)).lookup("example.com")
    assert info.source == "whois"


def test_rdap_invalid_json_falls_back_to_whois(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(200, content=b"<html>")
    info = make(cache, whois_fn=lambda d: datetime(2020, 1, 1, tzinfo=UTC)).lookup("example.com")
    assert info.source == "whois"


def test_whois_fn_exception_is_a_failure(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(404)

    def boom(d):
        raise RuntimeError("nope")

    info = make(cache, whois_fn=boom).lookup("example.com")
    assert info.error == "lookup_failed" and info.source == "none"


def test_malformed_cached_entry_is_a_miss(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(json=rdap_body())
    cache.set("age:example.com", {"creation_date": "garbage", "source": "rdap", "error": None}, 60)
    info = make(cache).lookup("example.com")
    assert info.source == "rdap" and not info.cached


# ---------- ruling 4/5: normalisation and sanity bounds ----------

def test_naive_now_is_treated_as_utc(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(json=rdap_body())
    info = make(cache, now=lambda: NOW.replace(tzinfo=None)).lookup("example.com")
    assert info.age_days == pytest.approx(10.0)


@pytest.mark.parametrize(
    "bogus", ["2024-01-14T00:00:00Z", "1984-12-31T23:59:59Z", "1970-01-01T00:00:00Z"]
)
def test_rdap_bogus_date_falls_through_to_whois(cache, bogus, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(json=rdap_body(bogus))
    info = make(cache, whois_fn=lambda d: datetime(2015, 1, 1, tzinfo=UTC)).lookup("example.com")
    assert info.source == "whois" and info.creation_date == datetime(2015, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "bogus",
    [NOW + timedelta(days=2), datetime(1984, 12, 31, tzinfo=UTC), datetime(1970, 1, 1)],
)
def test_whois_bogus_date_is_a_failure(cache, bogus, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(404)
    info = make(cache, whois_fn=lambda d: bogus).lookup("example.com")
    assert info.error == "lookup_failed" and info.age_days is None and info.source == "none"


def test_bounds_edges_are_accepted(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(json=rdap_body("1985-01-01T00:00:00Z"))
    info = make(cache).lookup("example.com")
    assert info.source == "rdap" and info.creation_date == datetime(1985, 1, 1, tzinfo=UTC)
    assert da.MIN_CREATION_DATE == datetime(1985, 1, 1, tzinfo=UTC)
    assert da.MAX_FUTURE_SKEW == timedelta(days=1)


def test_slightly_future_date_gives_age_zero(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(json=rdap_body((NOW + timedelta(hours=5)).isoformat()))
    assert make(cache).lookup("example.com").age_days == 0.0


# ---------- ruling 7: bootstrap ----------

def test_bootstrap_prefers_https_and_lowercases_tlds(cache, router):
    boot = {"services": [[["COM"], ["http://insecure.example/",
                                    "https://rdap.verisign.com/com/v1/"]]]}
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=boot)
    route = router.get(RDAP_URL).respond(json=rdap_body())
    assert make(cache).lookup("example.com").source == "rdap"
    assert route.call_count == 1


def test_bootstrap_uses_first_url_when_none_is_https(cache, router):
    boot = {"services": [[["com"], ["http://rdap.verisign.com/com/v1/"]]]}
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=boot)
    route = router.get("http://rdap.verisign.com/com/v1/domain/example.com").respond(
        json=rdap_body())
    assert make(cache).lookup("example.com").source == "rdap"
    assert route.call_count == 1


def test_bootstrap_failure_is_cached_for_five_minutes(router):
    boot_route = router.get(IANA_RDAP_BOOTSTRAP).mock(side_effect=httpx.ConnectTimeout("t"))
    t = [1000.0]
    cache = TTLCache(":memory:", now=lambda: t[0])
    lk = DomainAgeLookup(cache, _CLIENT, whois_fn=lambda d: None, now=lambda: NOW)
    assert BOOTSTRAP_FAILURE_TTL == 300
    lk.lookup("one.com")
    assert boot_route.call_count == 1
    lk.lookup("two.com")
    assert boot_route.call_count == 1  # straight to WHOIS
    t[0] += 301
    lk.lookup("three.com")
    assert boot_route.call_count == 2
    cache.close()


# ---------- rulings 8/9: redirects and client hooks ----------

def test_rdap_redirect_is_not_followed(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(302, headers={"Location": "http://169.254.169.254/x"})
    info = make(cache, whois_fn=lambda d: datetime(2020, 1, 1, tzinfo=UTC)).lookup("example.com")
    assert info.source == "whois"
    assert len(router.calls) == 2  # bootstrap + RDAP only; Location never requested


def test_client_event_hooks_untouched(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    router.get(RDAP_URL).respond(json=rdap_body())
    client = httpx.Client()  # own client: asserts on its event_hooks
    try:
        _hooks_untouched(router, cache, client)
    finally:
        client.close()


def _hooks_untouched(router, cache, client):
    before = {k: list(v) for k, v in client.event_hooks.items()}
    DomainAgeLookup(cache, client, whois_fn=lambda d: None, now=lambda: NOW).lookup("example.com")
    assert {k: list(v) for k, v in client.event_hooks.items()} == before


def test_rdap_sends_accept_header(cache, router):
    router.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    route = router.get(RDAP_URL).respond(json=rdap_body())
    make(cache).lookup("example.com")
    assert route.calls[0].request.headers["accept"] == "application/rdap+json"


# ---------- ruling 11: shared executor ----------

def test_executor_threads_are_named():
    assert da._WHOIS_EXECUTOR._thread_name_prefix == "phishguard-whois"
    assert da._WHOIS_EXECUTOR._max_workers == 4


# ---------- live ----------

@pytest.mark.network
def test_live_google_com():
    info = DomainAgeLookup(TTLCache(":memory:"), httpx.Client()).lookup("google.com")
    print(info)
    assert info.age_days > 9000


@pytest.mark.network
def test_live_kr_domain():
    info = DomainAgeLookup(TTLCache(":memory:"), httpx.Client()).lookup("kisa.or.kr")
    print(info)
    assert info.age_days is not None, f"kr lookup failed: {info}"
