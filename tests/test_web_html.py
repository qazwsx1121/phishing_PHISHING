import logging
import re
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import phishguard.web
from phishguard.models import (
    DomainInfo,
    ModelResult,
    RedirectHop,
    RedirectResult,
    RuleResult,
    Verdict,
)
from phishguard.web.app import create_app
from phishguard.web.stub import make_sample_result

DISCLAIMER = "이 결과는 참고용이며 안전을 보장하지 않습니다. 의심되면 링크를 열지 마세요."
WEB_DIR = Path(phishguard.web.__file__).parent


class FixedAnalyzer:
    def __init__(self, result):
        self.result = result

    def analyze(self, raw_url):
        return self.result


def client_for(result) -> TestClient:
    return TestClient(create_app(FixedAnalyzer(result)))


def post_url(client, url="http://naver.com.login-check.xyz/a"):
    return client.post("/analyze", data={"url": url})


# ---- form page -------------------------------------------------------------------


def test_index_has_form(client):
    html = client.get("/").text
    assert '<form method="post" action="/analyze"' in html and 'name="url"' in html


def test_index_has_no_error_message(client):
    assert 'role="alert"' not in client.get("/").text


# ---- result page: brief requirements -----------------------------------------------


def test_result_page_shows_verdict_reasons_and_disclaimer(client):
    html = post_url(client).text
    assert "주의" in html and "verdict-suspicious" in html
    assert "서브도메인에 있습니다" in html
    assert "참고용이며 안전을 보장하지 않습니다" in html
    assert "hxxp://naver[.]com[.]login-check[.]xyz/a" in html


def test_result_page_has_no_clickable_input_link(client):
    html = post_url(client).text
    assert 'href="http://naver.com.login-check.xyz' not in html


def test_input_is_html_escaped(client):
    html = post_url(client, 'http://a.com/"><script>alert(1)</script>').text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_invalid_url_rerenders_form_with_error(client):
    r = client.post("/analyze", data={"url": "invalid"})
    assert r.status_code == 400 and "올바른 URL 형식이 아닙니다." in r.text and 'value="invalid"' in r.text


# ---- result page: stub values and missing data -------------------------------------


def test_stub_result_page_content(client):
    html = post_url(client).text
    assert "45점" in html  # rule score
    assert DISCLAIMER in html
    assert "리다이렉트 없음" in html
    assert "학습된 모델 없음" in html
    assert "login-check.xyz" in html  # registered domain


def test_missing_values_are_shown_in_korean_not_as_none(client):
    html = post_url(client).text
    assert html.count("확인 불가") == 2  # creation date and age
    assert "None" not in html


def test_page_without_hits_or_warnings_does_not_break():
    base = make_sample_result()
    result = replace(base, rule=RuleResult(0, Verdict.SAFE, ()), warnings=())
    html = post_url(client_for(result)).text
    assert "verdict-safe" in html and "안전" in html
    assert DISCLAIMER in html


def test_known_domain_age_and_model_are_shown():
    base = make_sample_result()
    result = replace(
        base,
        domain=DomainInfo("login-check.xyz", datetime(2024, 1, 15, 3, 0), 300.4, "rdap", False, None),
        model=ModelResult(0.873, Verdict.DANGEROUS, "v1"),
    )
    html = post_url(client_for(result)).text
    assert "2024-01-15" in html
    assert "300일" in html
    assert "87.3%" in html
    assert "verdict-dangerous" in html and "위험" in html  # final verdict is the more severe one
    assert "확인 불가" not in html
    assert "학습된 모델 없음" not in html


def test_model_with_unknown_probability_does_not_print_none():
    base = make_sample_result()
    result = replace(base, model=ModelResult(float("nan"), Verdict.SAFE, "v1"))
    html = post_url(client_for(result)).text
    assert "None" not in html and not re.search(r"nan", html, re.IGNORECASE)
    assert "확인 불가" in html


def test_ip_host_without_registered_domain_or_subdomain():
    base = make_sample_result()
    parts = replace(base.parts, host="1.2.3.4", subdomain="", registered_domain="", is_ip=True)
    # a model and a warning keep "학습된 모델 없음" / "경고 없음" out of the count
    model = ModelResult(0.1, Verdict.SAFE, "v1")
    result = replace(base, parts=parts, model=model, warnings=("경고 하나",))
    html = post_url(client_for(result)).text
    assert "None" not in html
    assert html.count("없음") == 3  # registered domain, subdomain, redirects


def test_redirect_hops_are_listed_and_defanged():
    base = make_sample_result()
    redirect = RedirectResult(
        final_url="http://evil.com/x.html",
        hops=(RedirectHop("http://bit.ly/abc", 301), RedirectHop("http://t.co/zz", 302)),
        is_shortener=True,
        complete=True,
        error=None,
    )
    html = post_url(client_for(replace(base, redirect=redirect))).text
    assert "hxxp://bit[.]ly/abc" in html and "301" in html
    assert "hxxp://t[.]co/zz" in html and "302" in html
    assert "hxxp://evil[.]com/x.html" in html  # final URL
    assert "리다이렉트 없음" not in html
    assert "http://bit.ly" not in html and "http://evil.com" not in html


def test_warnings_are_listed():
    base = make_sample_result()
    result = replace(base, warnings=("도메인 정보를 조회하지 못했습니다.", "다른 경고 <b>"))
    html = post_url(client_for(result)).text
    assert "도메인 정보를 조회하지 못했습니다." in html
    assert "다른 경고 &lt;b&gt;" in html  # escaped


# ---- result page: no links, no external resources ----------------------------------


def test_every_link_and_resource_on_rendered_pages_is_site_local():
    base = make_sample_result()
    redirect = RedirectResult(
        final_url="http://evil.com/x", hops=(RedirectHop("http://bit.ly/a", 301),),
        is_shortener=True, complete=True, error=None,
    )
    pages = [
        TestClient(create_app(FixedAnalyzer(base))).get("/").text,
        post_url(client_for(replace(base, redirect=redirect))).text,
        TestClient(create_app(FixedAnalyzer(base))).post("/analyze", data={"url": ""}).text,
    ]
    for html in pages:
        assert "<script" not in html.lower()
        targets = re.findall(r'(?:href|src|action)="([^"]*)"', html)
        assert targets, "expected at least the stylesheet link"
        assert all(t.startswith("/") and not t.startswith("//") for t in targets), targets


def test_templates_do_not_use_safe_filter_or_external_urls():
    for path in (WEB_DIR / "templates").glob("*.html"):
        text = path.read_text(encoding="utf-8")
        assert "|safe" not in text.replace(" ", ""), path.name
        assert "autoescape false" not in text.lower(), path.name
        assert "http://" not in text and "https://" not in text, path.name


def test_static_stylesheet_is_served_and_wraps_long_urls(client):
    r = client.get("/static/style.css")
    assert r.status_code == 200 and "text/css" in r.headers["content-type"]
    assert "word-break: break-all" in r.text
    assert "http://" not in r.text and "https://" not in r.text and "@import" not in r.text


# ---- POST /analyze error handling ----------------------------------------------------


@pytest.mark.parametrize("data", [{}, {"url": ""}, {"url": "   "}])
def test_blank_or_missing_url_rerenders_form_with_400(client, data):
    r = client.post("/analyze", data=data)
    assert r.status_code == 400
    assert "URL을 입력해 주세요." in r.text
    assert '<form method="post" action="/analyze"' in r.text


def test_too_long_url_rerenders_form_with_400(client):
    url = "http://a.com/" + "a" * 2100
    r = client.post("/analyze", data={"url": url})
    assert r.status_code == 400
    assert "URL이 너무 깁니다." in r.text
    assert 'name="url"' in r.text


def test_unexpected_error_returns_500_and_logs(caplog):
    class Boom:
        def analyze(self, raw_url):
            raise RuntimeError("secret internal detail")

    client = TestClient(create_app(Boom()), raise_server_exceptions=False)
    with caplog.at_level(logging.ERROR, logger="phishguard.web.app"):
        r = client.post("/analyze", data={"url": "http://a.com"})
    assert r.status_code == 500
    assert "분석 중 오류가 발생했습니다." in r.text
    assert 'value="http://a.com"' in r.text
    assert "secret internal detail" not in r.text
    assert any(rec.exc_info for rec in caplog.records)
