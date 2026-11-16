import sqlite3
import threading

from phishguard.cache import TTLCache


def test_set_get_and_expiry():
    t = [1000.0]
    c = TTLCache(":memory:", now=lambda: t[0])
    c.set("k", {"a": 1}, ttl_seconds=10)
    assert c.get("k") == {"a": 1}
    t[0] = 1011.0
    assert c.get("k") is None
    c.close()


def test_persists_across_instances(tmp_path):
    first = TTLCache(tmp_path / "c.sqlite3")
    first.set("k", [1, 2], 60)
    first.close()
    second = TTLCache(tmp_path / "c.sqlite3")
    try:
        assert second.get("k") == [1, 2]
    finally:
        second.close()


def test_set_overwrites_existing_key():
    c = TTLCache(":memory:")
    c.set("k", 1, 60)
    c.set("k", 2, 60)
    assert c.get("k") == 2
    c.close()


def test_missing_key_is_none():
    c = TTLCache(":memory:")
    assert c.get("nope") is None
    c.close()


def test_invalid_json_value_is_a_miss(tmp_path):
    path = tmp_path / "c.sqlite3"
    c = TTLCache(path)
    c.set("k", 1, 60)
    c.close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE kv SET value = ? WHERE key = ?", ("{not json", "k"))
    raw.commit()
    raw.close()
    c = TTLCache(path)
    try:
        assert c.get("k") is None
    finally:
        c.close()


def test_concurrent_set_and_get_from_threads():
    c = TTLCache(":memory:")
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            for i in range(100):
                key = f"k{n}-{i % 10}"
                c.set(key, {"n": n, "i": i}, 60)
                got = c.get(key)
                assert got is not None and got["n"] == n
        except BaseException as exc:  # noqa: BLE001 - surfaced via the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    c.close()
    assert errors == []
