"""Domain registration date lookup: RDAP first, WHOIS as fallback, SQLite-cached.

Design rules: a wrong date must not slip through (dates are normalised to UTC and
sanity-bounded), and a failed or slow lookup must never raise or stall the caller.
"""

from __future__ import annotations

import inspect
import logging
import re
import sqlite3
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import whois

from phishguard.cache import TTLCache
from phishguard.models import DomainInfo

logger = logging.getLogger(__name__)

IANA_RDAP_BOOTSTRAP: str = "https://data.iana.org/rdap/dns.json"
POSITIVE_TTL: int = 30 * 86400
NEGATIVE_TTL: int = 86400
RATE_LIMIT_TTL: int = 3600
BOOTSTRAP_TTL: int = 7 * 86400
BOOTSTRAP_FAILURE_TTL: int = 300

# Registries emit placeholder dates; anything outside these bounds is "not found".
MIN_CREATION_DATE: datetime = datetime(1985, 1, 1, tzinfo=timezone.utc)
MAX_FUTURE_SKEW: timedelta = timedelta(days=1)

WHOIS_SOCKET_TIMEOUT: int = 8

WhoisFn = Callable[[str], datetime | None]

_BOOTSTRAP_KEY = "rdap:bootstrap"
_DOMAIN_RE = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+")
_MAX_DOMAIN_LEN = 253
_SOURCES = frozenset({"rdap", "whois", "none"})

# Shared on purpose: a `with ThreadPoolExecutor()` block would wait for a hung WHOIS
# thread on exit and defeat the timeout.
_WHOIS_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="phishguard-whois")


def _to_utc(value: Any) -> datetime | None:
    """Timezone-aware UTC datetime (naive means UTC); None for non-datetimes."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def whois_creation_date(domain: str) -> datetime | None:
    """Creation date from python-whois (earliest valid one), or None on any failure."""
    try:
        params = inspect.signature(whois.whois).parameters
        kwargs: dict[str, Any] = {}
        if "timeout" in params:
            kwargs["timeout"] = WHOIS_SOCKET_TIMEOUT
        if "quiet" in params:
            kwargs["quiet"] = True
        entry = whois.whois(domain, **kwargs)
        value = getattr(entry, "creation_date", None)
        if value is None and isinstance(entry, Mapping):
            value = entry.get("creation_date")
        items = value if isinstance(value, (list, tuple)) else [value]
        dates = [d for d in (_to_utc(i) for i in items) if d is not None]
        return min(dates) if dates else None
    except Exception:  # noqa: BLE001 - WHOIS libraries fail in many ways; all mean "unknown"
        logger.warning("whois lookup failed for %s", domain, exc_info=True)
        return None


def parse_rdap_registration(payload: Any) -> datetime | None:
    """Earliest valid ``registration`` event date in an RDAP payload, else None."""
    if not isinstance(payload, Mapping):
        return None
    events = payload.get("events")
    if not isinstance(events, list):
        return None
    found: list[datetime] = []
    for event in events:
        if not isinstance(event, Mapping) or event.get("eventAction") != "registration":
            continue
        raw = event.get("eventDate")
        if not isinstance(raw, str):
            continue
        try:
            parsed = _to_utc(datetime.fromisoformat(raw.replace("Z", "+00:00")))
        except ValueError:
            continue
        if parsed is not None:
            found.append(parsed)
    return min(found) if found else None


def _parse_bootstrap(data: Any) -> dict[str, str]:
    """``{tld: base_url}`` from an IANA bootstrap document; ValueError if malformed."""
    if not isinstance(data, Mapping) or not isinstance(data.get("services"), list):
        raise ValueError("bootstrap: bad shape")
    mapping: dict[str, str] = {}
    for service in data["services"]:
        if not isinstance(service, (list, tuple)) or len(service) < 2:
            raise ValueError("bootstrap: bad service")
        tlds, urls = service[0], service[1]
        if (
            not isinstance(tlds, list)
            or not isinstance(urls, list)
            or not urls
            or not all(isinstance(t, str) for t in tlds)
            or not all(isinstance(u, str) for u in urls)
        ):
            raise ValueError("bootstrap: bad service entries")
        base = next((u for u in urls if u.startswith("https://")), urls[0])
        for tld in tlds:
            mapping.setdefault(tld.lower(), base)
    return mapping


def _valid_mapping(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    )


class DomainAgeLookup:
    def __init__(
        self,
        cache: TTLCache,
        client: httpx.Client,
        *,
        whois_fn: WhoisFn = whois_creation_date,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        timeout: float = 8.0,
    ) -> None:
        self.cache = cache
        self.client = client
        self.whois_fn = whois_fn
        self.now = now
        self.timeout = timeout

    # ---- public ----

    def lookup(self, registered_domain: str) -> DomainInfo:
        """Look up a domain's creation date. Never raises."""
        try:
            return self._lookup(registered_domain)
        except Exception:  # noqa: BLE001 - last line of defence; analysis must go on
            logger.exception("domain age lookup crashed for %r", registered_domain)
            return DomainInfo.unknown(str(registered_domain), "lookup_failed")

    # ---- internals ----

    @staticmethod
    def _normalise(domain: Any) -> str | None:
        if not isinstance(domain, str):
            return None
        d = domain.strip().lower()
        if d.endswith("."):
            d = d[:-1]
        if len(d) > _MAX_DOMAIN_LEN or not _DOMAIN_RE.fullmatch(d):
            return None
        return d

    def _now_utc(self) -> datetime:
        value = _to_utc(self.now())
        return value if value is not None else datetime.now(timezone.utc)

    def _cache_get(self, key: str) -> Any | None:
        try:
            return self.cache.get(key)
        except sqlite3.Error:
            logger.exception("cache read failed for %s", key)
            return None

    def _cache_set(self, key: str, value: Any, ttl: float) -> None:
        try:
            self.cache.set(key, value, ttl)
        except sqlite3.Error:
            logger.exception("cache write failed for %s", key)

    def _age_days(self, created: datetime, now: datetime) -> float:
        return max(0.0, (now - created).total_seconds() / 86400)

    def _in_bounds(self, created: datetime | None, now: datetime) -> datetime | None:
        if created is None:
            return None
        if created < MIN_CREATION_DATE or created > now + MAX_FUTURE_SKEW:
            logger.warning("ignoring implausible creation date %s", created.isoformat())
            return None
        return created

    def _from_cache(self, domain: str, entry: Any, now: datetime) -> DomainInfo | None:
        try:
            if not isinstance(entry, Mapping):
                return None
            source, error, raw = entry["source"], entry.get("error"), entry.get("creation_date")
            if source not in _SOURCES or not (error is None or isinstance(error, str)):
                return None
            if raw is None:
                if source != "none":
                    return None
                return DomainInfo(domain, None, None, "none", True, error)
            if source == "none" or not isinstance(raw, str):
                return None
            created = _to_utc(datetime.fromisoformat(raw))
            if created is None:
                return None
            return DomainInfo(domain, created, self._age_days(created, now), source, True, error)
        except (KeyError, ValueError, TypeError):
            return None

    def _lookup(self, argument: str) -> DomainInfo:
        domain = self._normalise(argument)
        if domain is None:
            return DomainInfo.unknown(argument if isinstance(argument, str) else str(argument),
                                      "not_a_domain")
        now = self._now_utc()
        key = f"age:{domain}"
        hit = self._from_cache(domain, self._cache_get(key), now)
        if hit is not None:
            return hit

        rate_limited = False
        created: datetime | None = None
        source = "none"
        try:
            created, rate_limited = self._rdap(domain, now)
        except Exception:  # noqa: BLE001 - any RDAP problem just means "try WHOIS"
            logger.warning("rdap lookup failed for %s", domain, exc_info=True)
        if created is not None:
            source = "rdap"
        else:
            created = self._in_bounds(self._whois(domain), now)
            if created is not None:
                source = "whois"

        if created is not None:
            self._cache_set(key, {"creation_date": created.isoformat(), "source": source,
                                  "error": None}, POSITIVE_TTL)
            return DomainInfo(domain, created, self._age_days(created, now), source, False, None)

        error = "rate_limited" if rate_limited else "lookup_failed"
        ttl = RATE_LIMIT_TTL if rate_limited else NEGATIVE_TTL
        self._cache_set(key, {"creation_date": None, "source": "none", "error": error}, ttl)
        return DomainInfo.unknown(domain, error)

    def _bootstrap(self) -> dict[str, str]:
        cached = self._cache_get(_BOOTSTRAP_KEY)
        if _valid_mapping(cached):
            return cached
        try:
            resp = self.client.get(
                IANA_RDAP_BOOTSTRAP,
                headers={"Accept": "application/json"},
                timeout=self.timeout,
                follow_redirects=False,
            )
            if resp.status_code != 200:
                raise ValueError(f"bootstrap status {resp.status_code}")
            mapping = _parse_bootstrap(resp.json())
        except Exception:  # noqa: BLE001 - includes httpx errors and bad JSON/shape
            logger.warning("rdap bootstrap fetch failed", exc_info=True)
            self._cache_set(_BOOTSTRAP_KEY, {}, BOOTSTRAP_FAILURE_TTL)
            return {}
        self._cache_set(_BOOTSTRAP_KEY, mapping, BOOTSTRAP_TTL)
        return mapping

    def _rdap(self, domain: str, now: datetime) -> tuple[datetime | None, bool]:
        """Return (creation date or None, whether the server said 429)."""
        base = self._bootstrap().get(domain.rsplit(".", 1)[1])
        if not base:
            return None, False
        resp = self.client.get(
            f"{base.rstrip('/')}/domain/{domain}",
            headers={"Accept": "application/rdap+json"},
            timeout=self.timeout,
            follow_redirects=False,
        )
        if resp.status_code == 429:
            return None, True
        if resp.status_code != 200:
            return None, False
        return self._in_bounds(parse_rdap_registration(resp.json()), now), False

    def _whois(self, domain: str) -> datetime | None:
        future = _WHOIS_EXECUTOR.submit(self.whois_fn, domain)
        try:
            return _to_utc(future.result(timeout=self.timeout))
        except Exception:  # noqa: BLE001 - timeout or any error from whois_fn
            logger.warning("whois failed or timed out for %s", domain, exc_info=True)
            future.cancel()
            return None
