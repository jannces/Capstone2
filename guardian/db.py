"""
guardian/db.py
SQLite backend (WAL mode, thread-safe).
Tables: admins, devices, threats, connection_log, admin_log, reports, settings.
"""
import sqlite3
import threading
import datetime
from .config import Config, DB_PATH

_local = threading.local()
_write_lock = threading.Lock()      # serialize writes (SQLite = 1 writer)


def get_db() -> sqlite3.Connection:
    """One connection per thread, WAL mode, dict rows."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


def execute(sql: str, params: tuple = (), commit: bool = True):
    """Thread-safe write helper."""
    with _write_lock:
        db = get_db()
        cur = db.execute(sql, params)
        if commit:
            db.commit()
        return cur


def query(sql: str, params: tuple = ()) -> list:
    """Read helper — returns list of dicts."""
    cur = get_db().execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def query_one(sql: str, params: tuple = ()):
    rows = query(sql, params)
    return rows[0] if rows else None


def now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────
#  SCHEMA
# ─────────────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    mac            TEXT PRIMARY KEY,
    ip             TEXT,
    hostname       TEXT DEFAULT '',
    vendor         TEXT DEFAULT '',
    status         TEXT DEFAULT 'online',          -- online / offline
    first_seen     TEXT,
    last_seen      TEXT,
    total_online_secs INTEGER DEFAULT 0,           -- accumulated online time
    session_start  TEXT,                            -- current session start
    is_gateway     INTEGER DEFAULT 0,
    is_self        INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS threats (
    id           TEXT PRIMARY KEY,
    ts           TEXT NOT NULL,
    threat_type  TEXT NOT NULL,
    severity     TEXT NOT NULL,                    -- Critical/High/Medium/Low
    src_ip       TEXT DEFAULT '',
    src_mac      TEXT DEFAULT '',
    dst_ip       TEXT DEFAULT '',
    description  TEXT DEFAULT '',
    detection_rule TEXT DEFAULT '',
    evidence     TEXT DEFAULT '',
    mitigation   TEXT DEFAULT '',
    status       TEXT DEFAULT 'New',               -- New/Acknowledged/Resolved/False Positive
    ack_by       TEXT DEFAULT '',
    ack_at       TEXT DEFAULT '',
    detect_latency_ms INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connection_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    event     TEXT NOT NULL,                       -- connected/disconnected/reconnected
    mac       TEXT,
    ip        TEXT,
    hostname  TEXT DEFAULT '',
    vendor    TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS admin_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    username  TEXT,
    action    TEXT NOT NULL,                       -- login/logout/password_change/...
    detail    TEXT DEFAULT '',
    ip        TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS reports (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    report_type TEXT NOT NULL,                     -- threat/connection/device/security
    fmt       TEXT NOT NULL,                       -- csv/pdf
    filename  TEXT NOT NULL,
    created_by TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_threats_ts   ON threats(ts);
CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_conn_ts      ON connection_log(ts);
CREATE INDEX IF NOT EXISTS idx_admin_ts     ON admin_log(ts);
"""


def init_db():
    """Create schema, seed default admin + default settings."""
    with _write_lock:
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()

    # Seed default admin
    if not query_one("SELECT id FROM admins LIMIT 1"):
        from .auth import hash_password
        execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)",
            (Config.DEFAULT_ADMIN_USER,
             hash_password(Config.DEFAULT_ADMIN_PASS),
             now()),
        )
        print(f"[*] Default admin created: {Config.DEFAULT_ADMIN_USER} / "
              f"{Config.DEFAULT_ADMIN_PASS}  — CHANGE THIS IMMEDIATELY.")

    # Seed settings
    defaults = {
        "alarm_enabled":          "1" if Config.ALARM_ENABLED_DEFAULT else "0",
        "probe_interval":         str(Config.PROBE_INTERVAL_SECS),
        "offline_miss_threshold": str(Config.OFFLINE_MISS_THRESHOLD),
        "monitoring_interface":   "",
    }
    for k, v in defaults.items():
        execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?,?)", (k, v))

    # Anything marked online from a previous run is stale — reset it.
    execute("UPDATE devices SET status='offline', session_start=NULL "
            "WHERE status='online'")


def get_setting(key: str, default: str = "") -> str:
    row = query_one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


def set_setting(key: str, value: str):
    execute("INSERT INTO settings (key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def log_admin(username: str, action: str, detail: str = "", ip: str = ""):
    execute("INSERT INTO admin_log (ts, username, action, detail, ip) "
            "VALUES (?,?,?,?,?)", (now(), username, action, detail, ip))


def purge_old():
    """
    Retention job: connection_log/threats/admin_log grow unbounded on a
    long-running monitor, so rows older than the configured retention
    are deleted and the WAL is checkpointed to reclaim disk.
    Returns the number of rows removed.
    """
    def _cutoff(days: int) -> str:
        return ((datetime.datetime.now() - datetime.timedelta(days=days))
                .strftime("%Y-%m-%d %H:%M:%S"))

    removed = 0
    for table, days in (("connection_log", Config.RETENTION_CONNLOG_DAYS),
                        ("threats",        Config.RETENTION_THREAT_DAYS),
                        ("admin_log",      Config.RETENTION_ADMINLOG_DAYS)):
        cur = execute(f"DELETE FROM {table} WHERE ts < ?", (_cutoff(days),))
        removed += max(cur.rowcount, 0)

    with _write_lock:
        get_db().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    if removed:
        print(f"[*] Retention: purged {removed} expired log rows.")
    return removed
