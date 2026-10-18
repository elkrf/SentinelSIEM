"""Couche de persistance SQLite (thread-safe)."""
import json
import sqlite3
import threading
import time

from .config import DB_PATH, DEFAULT_SETTINGS

_lock = threading.RLock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_conn.row_factory = sqlite3.Row
_conn.execute("PRAGMA journal_mode=WAL")
_conn.execute("PRAGMA synchronous=NORMAL")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    rule_id INTEGER NOT NULL,
    level INTEGER NOT NULL,
    description TEXT NOT NULL,
    module TEXT NOT NULL,
    groups TEXT,
    mitre TEXT,
    tactics TEXT,
    agent TEXT,
    summary TEXT,
    full_log TEXT,
    data TEXT,
    status TEXT DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level);
CREATE INDEX IF NOT EXISTS idx_alerts_module ON alerts(module);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);

CREATE TABLE IF NOT EXISTS fim_baseline (
    path TEXT PRIMARY KEY,
    sha256 TEXT,
    size INTEGER,
    mtime REAL,
    mode INTEGER,
    owner TEXT,
    is_dir INTEGER DEFAULT 0,
    updated REAL
);

CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY,
    ts REAL,
    original_path TEXT,
    stored_path TEXT,
    sha256 TEXT,
    size INTEGER,
    reason TEXT,
    engine TEXT,
    status TEXT DEFAULT 'quarantined'
);

CREATE TABLE IF NOT EXISTS sca_results (
    check_id TEXT PRIMARY KEY,
    title TEXT,
    category TEXT,
    status TEXT,
    detail TEXT,
    remediation TEXT,
    cis TEXT,
    severity TEXT,
    ts REAL
);

CREATE TABLE IF NOT EXISTS alert_ai_notes (
    alert_id INTEGER PRIMARY KEY,
    ts REAL,
    model TEXT,
    text TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

with _lock:
    _conn.executescript(SCHEMA)


def execute(sql, params=()):
    with _lock:
        return _conn.execute(sql, params)


def query(sql, params=()):
    with _lock:
        return [dict(r) for r in _conn.execute(sql, params).fetchall()]


def query_one(sql, params=()):
    with _lock:
        r = _conn.execute(sql, params).fetchone()
        return dict(r) if r else None


def executemany(sql, rows):
    with _lock:
        _conn.execute("BEGIN")
        try:
            _conn.executemany(sql, rows)
            _conn.execute("COMMIT")
        except Exception:
            _conn.execute("ROLLBACK")
            raise


# ---------------------------------------------------------------- settings
_settings_cache = None


def get_settings() -> dict:
    global _settings_cache
    if _settings_cache is None:
        s = json.loads(json.dumps(DEFAULT_SETTINGS))
        for row in query("SELECT key, value FROM settings WHERE key NOT LIKE '\\_%' ESCAPE '\\'"):
            try:
                s[row["key"]] = json.loads(row["value"])
            except Exception:
                pass
        _settings_cache = s
    return _settings_cache


def set_settings(values: dict):
    global _settings_cache
    for k, v in values.items():
        if k in DEFAULT_SETTINGS:
            execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (k, json.dumps(v)))
    _settings_cache = None
    return get_settings()


def get_private(key, default=None):
    r = query_one("SELECT value FROM settings WHERE key=?", ("_" + key,))
    return json.loads(r["value"]) if r else default


def set_private(key, value):
    execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", ("_" + key, json.dumps(value)))


def purge_old_alerts():
    days = int(get_settings().get("retention_days", 30))
    cutoff = time.time() - days * 86400
    execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
    execute("DELETE FROM alert_ai_notes WHERE alert_id NOT IN (SELECT id FROM alerts)")
