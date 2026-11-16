"""Feature extraction: the 25-number vector used by both rules and ML models."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from urllib.parse import parse_qsl, unquote

from phishguard.config import Resources
from phishguard.models import (
    FEATURE_NAMES,
    DomainInfo,
    FeatureVector,
    NormalizedURL,
    RedirectResult,
    URLParts,
)

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_EMBEDDED_URL = re.compile(r"https?(://|%3A%2F%2F)", re.IGNORECASE)


def match_keywords(text: str, keywords: Iterable[str]) -> set[str]:
    """Keywords found in text: whole token, or substring of a token when len >= 5."""
    tokens = [t for t in _TOKEN_SPLIT.split(text.lower()) if t]
    token_set = set(tokens)
    found: set[str] = set()
    for k in keywords:
        if k in token_set or (len(k) >= 5 and any(k in t for t in tokens)):
            found.add(k)
    return found


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character; 0.0 for the empty string."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values()) + 0.0


def _variants(text: str) -> tuple[str, ...]:
    """Raw text plus its once-percent-decoded form (deduplicated)."""
    decoded = unquote(text, errors="replace")
    return (text,) if decoded == text else (text, decoded)


def _brand_match(texts: Iterable[str], parts: URLParts, resources: Resources) -> str | None:
    """Name of the first brand (file order) found in any text and not owning the site."""
    texts = tuple(texts)
    for brand in resources.brands:
        if parts.registered_domain in brand.official_domains:
            continue
        if any(match_keywords(t, brand.keywords) for t in texts):
            return brand.name
    return None


def extract_features(
    url: NormalizedURL,
    parts: URLParts,
    redirect: RedirectResult,
    domain: DomainInfo,
    resources: Resources,
) -> FeatureVector:
    host = url.host
    labels = [x for x in parts.subdomain.split(".") if x]
    if labels and labels[0] == "www":
        labels = labels[1:]

    pq_texts = _variants(f"{url.path} {url.query}")
    kw_texts = [f"{host} {url.path} {url.query}", *_variants(f"{url.path} {url.query}")]
    suspicious: set[str] = set()
    for t in kw_texts:
        suspicious |= match_keywords(t, resources.suspicious_keywords)

    brand_hits = {
        "brand_in_subdomain": _brand_match([parts.subdomain], parts, resources),
        "brand_in_path": _brand_match(pq_texts, parts, resources),
        "brand_in_domain_label": _brand_match([parts.domain], parts, resources),
    }

    tld = parts.suffix.rsplit(".", 1)[-1] if parts.suffix else ""
    age = domain.age_days
    age_known = age is not None and math.isfinite(age)

    values: dict[str, float] = {
        "url_length": len(url.normalized),
        "host_length": len(host),
        "path_length": len(url.path),
        "num_subdomains": len(labels),
        "num_dots_host": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits_host": sum(1 for c in host if c.isdigit()),
        "is_ip_host": parts.is_ip,
        "has_userinfo": url.userinfo != "",
        "has_punycode": any(x.startswith("xn--") for x in host.split(".")),
        "is_https": url.scheme == "https",
        "has_nonstandard_port": url.port is not None,
        "num_query_params": len(parse_qsl(url.query, keep_blank_values=True)),
        "num_suspicious_keywords": len(suspicious),
        "brand_in_subdomain": brand_hits["brand_in_subdomain"] is not None,
        "brand_in_path": brand_hits["brand_in_path"] is not None,
        "brand_in_domain_label": brand_hits["brand_in_domain_label"] is not None,
        "is_shortener": redirect.is_shortener,
        "redirect_count": len(redirect.hops),
        "is_private_suffix": parts.is_private_suffix,
        "is_risky_tld": bool(tld) and tld in resources.risky_tlds,
        "host_entropy": shannon_entropy(parts.domain or host),
        "has_embedded_url": _EMBEDDED_URL.search(f"{url.path}?{url.query}") is not None,
        "domain_age_days": float(age) if age_known else math.nan,
        "domain_age_unknown": not age_known,
    }
    floats = {name: float(values[name]) for name in FEATURE_NAMES}

    evidence = {
        "registered_domain": parts.registered_domain,
        "site_domain": parts.site_domain,
        "tld": tld,
        "port": "" if url.port is None else str(url.port),
    }
    for key, name in brand_hits.items():
        if name is not None:
            evidence[key] = name
    return FeatureVector(values=floats, evidence=evidence)
