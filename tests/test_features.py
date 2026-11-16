import math
import random
from datetime import datetime, timezone

import pytest

from phishguard.config import load_resources
from phishguard.errors import InvalidURLError
from phishguard.features import extract_features, match_keywords, shannon_entropy
from phishguard.models import (
    FEATURE_NAMES,
    DomainInfo,
    RedirectHop,
    RedirectResult,
)
from phishguard.normalize import normalize_url
from phishguard.parse import parse_url

RES = load_resources()


def fv(raw, *, age=None, redirect=None):
    n = normalize_url(raw)
    if age is not None:
        domain = DomainInfo("x", datetime(2020, 1, 1, tzinfo=timezone.utc), age, "rdap", False, None)
    else:
        domain = DomainInfo.unknown("x")
    if redirect is None:
        redirect = RedirectResult.not_followed(n.normalized)
    return extract_features(n, parse_url(n), redirect, domain, RES)


def test_match_keywords_token_boundary():
    assert match_keywords("tossup.com", ["toss"]) == set()
    assert match_keywords("toss-login.com", ["toss"]) == {"toss"}
    assert match_keywords("mypaypalaccount.com", ["paypal"]) == {"paypal"}


def test_match_keywords_and_entropy_edges():
    assert match_keywords("", ["a"]) == set()
    assert match_keywords("\ud800 x", ["x"]) == {"x"}
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0 and shannon_entropy("ab") == 1.0
    assert shannon_entropy("abcd") == 2.0
    assert shannon_entropy("\ud800\ud801") == 1.0


def test_brand_in_subdomain():
    f = fv("http://naver.com.login-check.xyz/a")
    assert f.values["brand_in_subdomain"] == 1.0 and f.evidence["brand_in_subdomain"] == "네이버"
    assert f.values["is_risky_tld"] == 1.0 and f.evidence["registered_domain"] == "login-check.xyz"
    assert f.evidence["tld"] == "xyz" and f.evidence["port"] == ""


def test_official_domain_not_flagged():
    f = fv("https://www.naver.com/")
    assert f.values["brand_in_subdomain"] == f.values["brand_in_path"] == f.values["brand_in_domain_label"] == 0.0


def test_naver_login_page():
    f = fv("https://www.naver.com/login")
    assert f.values["brand_in_subdomain"] == f.values["brand_in_path"] == f.values["brand_in_domain_label"] == 0.0
    assert f.values["num_suspicious_keywords"] == 1.0


def test_official_subdomain():
    assert fv("https://mail.naver.com/").values["brand_in_subdomain"] == 0.0


def test_official_shortener_domain():
    f = fv("https://naver.me/abc")
    assert f.values["brand_in_subdomain"] == f.values["brand_in_path"] == f.values["brand_in_domain_label"] == 0.0


def test_brand_in_path():
    assert fv("http://evil.example/paypal/login").values["brand_in_path"] == 1.0


def test_brand_in_path_percent_encoded():
    f = fv("http://evil.example/%70aypal/login")
    assert f.values["brand_in_path"] == 1.0 and f.evidence["brand_in_path"] == "PayPal"


def test_brand_in_path_of_other_site_is_by_design():
    # By design: the feature records "brand name in the path of a site that is not
    # that brand's". The rule weights decide what that means.
    assert fv("https://www.google.com/search?q=paypal").values["brand_in_path"] == 1.0


def test_percent_encoded_suspicious_keyword_in_query():
    assert fv("http://evil.example/x?next=%6Cogin").values["num_suspicious_keywords"] == 1.0


def test_keyword_in_raw_and_decoded_counts_once():
    assert fv("http://evil.example/login?x=%6Cogin").values["num_suspicious_keywords"] == 1.0


def test_combosquat():
    assert fv("https://paypal-secure.com/").values["brand_in_domain_label"] == 1.0


def test_two_brands_first_in_file_order_wins():
    f = fv("http://paypal.naver.evil.example/")
    assert f.values["brand_in_subdomain"] == 1.0
    assert f.evidence["brand_in_subdomain"] == "네이버"  # listed before PayPal in brands.yaml


def test_shared_hosting():
    f = fv("https://paypal-login.github.io/")
    assert f.values["brand_in_subdomain"] == 1.0 and f.values["is_private_suffix"] == 1.0
    assert f.evidence["registered_domain"] == "github.io"


def test_ip_and_userinfo():
    f = fv("http://paypal.com@3232235777/")
    assert f.values["is_ip_host"] == 1.0 and f.values["has_userinfo"] == 1.0


def test_ip_host_with_brand_path():
    f = fv("http://192.168.0.1/paypal")
    assert f.values["is_ip_host"] == 1.0 and f.values["brand_in_path"] == 1.0
    assert f.values["num_subdomains"] == 0.0
    assert f.evidence["tld"] == "" and f.evidence["registered_domain"] == ""


def test_punycode_feature():
    assert fv("http://네이버.com/").values["has_punycode"] == 1.0


def test_num_subdomains_excludes_www():
    assert fv("http://www.a.example.com/").values["num_subdomains"] == 1.0
    assert fv("http://www.example.com/").values["num_subdomains"] == 0.0


def test_num_subdomains_ignores_empty_labels():
    assert fv("http://a..b.example.com/").values["num_subdomains"] == 2.0


def test_nonstandard_port():
    f = fv("http://example.com:8080/")
    assert f.values["has_nonstandard_port"] == 1.0 and f.evidence["port"] == "8080"
    g = fv("https://example.com/")
    assert g.values["has_nonstandard_port"] == 0.0 and g.evidence["port"] == ""


def test_query_params_counted_with_blanks():
    assert fv("http://a.com/?a=1&b=&c").values["num_query_params"] == 3.0


def test_embedded_url():
    assert fv("http://a.com/r?u=https%3A%2F%2Fevil.com").values["has_embedded_url"] == 1.0


def test_redirect_features():
    hops = (RedirectHop("http://x.co/1", 301), RedirectHop("http://y.co/2", 302))
    r = RedirectResult("http://b.com/", hops, True, True, None)
    f = fv("http://a.com/", redirect=r)
    assert f.values["is_shortener"] == 1.0 and f.values["redirect_count"] == 2.0
    assert fv("http://a.com/").values["is_shortener"] == 0.0


def test_domain_age_known():
    f = fv("http://a.com/", age=12.5)
    assert f.values["domain_age_days"] == 12.5 and f.values["domain_age_unknown"] == 0.0


def test_domain_age_missing_is_nan_and_flag():
    f = fv("http://a.com/")
    assert math.isnan(f.values["domain_age_days"]) and f.values["domain_age_unknown"] == 1.0


@pytest.mark.parametrize("age", [math.inf, -math.inf, math.nan, 10**400])
def test_nonfinite_age_treated_as_unknown(age):
    f = fv("http://a.com/", age=age)
    assert math.isnan(f.values["domain_age_days"]) and f.values["domain_age_unknown"] == 1.0


def test_feature_vector_complete():
    assert set(fv("http://a.com/").values) == set(FEATURE_NAMES)


def test_all_values_are_float():
    f = fv("https://paypal-login.github.io/x?a=1", age=3.0)
    assert all(type(v) is float for v in f.values.values())


def _random_text(rng):
    pieces = ["a", "b", ".", "..", "-", "/", "?", "&", "=", "%", "%70", "%3A%2F%2F", "@", ":", "80",
              "paypal", "naver", "login", "xn--", "co.kr", "github.io", "com", "http://", "https://",
              "[::1]", "0x7f", "1.2.3.4", "한국", "é", " "]
    if rng.random() < 0.2:
        return "".join(chr(rng.randint(0, 0x2FFF)) for _ in range(rng.randint(0, 30)))
    return "".join(rng.choice(pieces) for _ in range(rng.randint(0, 14)))


def test_fuzz_never_raises_and_is_finite():
    rng = random.Random(42)
    exercised = 0
    for _ in range(5000):
        text = _random_text(rng)
        try:
            n = normalize_url(text)
        except InvalidURLError:
            continue
        p = parse_url(n)
        for age in (None, 5.0):
            if age is None:
                d = DomainInfo.unknown("x")
            else:
                d = DomainInfo("x", None, age, "rdap", False, None)
            f = extract_features(n, p, RedirectResult.not_followed(n.normalized), d, RES)
            assert set(f.values) == set(FEATURE_NAMES)
            for k, v in f.values.items():
                assert type(v) is float
                if k != "domain_age_days":
                    assert math.isfinite(v)
        exercised += 1
    assert exercised >= 100


def _same(a, b):
    return all((math.isnan(a[k]) and math.isnan(b[k])) or a[k] == b[k] for k in FEATURE_NAMES)


def test_deterministic():
    n = normalize_url("http://paypal.naver.evil.example/%70aypal?x=1")
    p = parse_url(n)
    args = (n, p, RedirectResult.not_followed(n.normalized), DomainInfo.unknown("x"), RES)
    a, b = extract_features(*args), extract_features(*args)
    assert _same(a.values, b.values) and a.evidence == b.evidence


BRAND_KEYS = ("brand_in_subdomain", "brand_in_path", "brand_in_domain_label")


@pytest.mark.parametrize("raw", [
    "https://kakaobank.com/",
    "https://www.kakaobank.com/login",
    "https://sub.kakaobank.com/kakaobank?q=kakaobank",
    "https://kakaobank.kakaobank.com/",
])
def test_owner_brand_keyword_superset_not_flagged(raw):
    f = fv(raw)
    assert all(f.values[k] == 0.0 for k in BRAND_KEYS)
    assert not any(k in f.evidence for k in BRAND_KEYS)


def test_kakaobank_lookalike_subdomain_still_flagged():
    f = fv("http://kakaobank.com.evil.example/")
    assert f.values["brand_in_subdomain"] == 1.0
    # registered domain owned by nobody, so nothing is suppressed; the first brand in
    # brands.yaml order that matches the token "kakaobank" is reported
    first = next(b.name for b in RES.brands if "kakao" in b.keywords or "kakaobank" in b.keywords)
    assert f.evidence["brand_in_subdomain"] == first


def test_unrelated_brand_still_reported_on_owned_domain():
    f = fv("https://www.kakaobank.com/paypal/login")
    assert f.values["brand_in_path"] == 1.0 and f.evidence["brand_in_path"] == "PayPal"


def test_official_domain_shapes_never_flagged_for_every_brand():
    for brand in RES.brands:
        kw = brand.keywords[0]
        for d in brand.official_domains:
            for raw in (f"https://{d}/", f"https://www.{d}/login",
                        f"https://sub.{d}/{kw}?q={kw}", f"https://{kw}.{d}/"):
                f = fv(raw)
                assert all(f.values[k] == 0.0 for k in BRAND_KEYS), (raw, f.evidence)
