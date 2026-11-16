"""Small SQLite-backed key/value cache with per-entry expiry (JSON values only)."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


class TTLCache:
    """Thread-safe TTL cache. One connection is shared behind a lock because the web
    app calls it from a thread pool."""

    def __init__(self, path: Path | str, *, now: Callable[[], float] = time.time) -> None:
        self._now = now
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS kv ("
                "key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at REAL NOT NULL)"
            )
            self._conn.commit()

    def get(self, key: str) -> Any | None:
        """Return the stored value, or None if missing, expired or unreadable."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value, expires_at FROM kv WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        value, expires_at = row
        if expires_at <= self._now():
            return None
        try:
            return json.loads(value)
        except ValueError:
            return None

    def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        payload = json.dumps(value)
        expires_at = self._now() + ttl_seconds
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO kv (key, value, expires_at) VALUES (?, ?, ?)",
                (key, payload, expires_at),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
