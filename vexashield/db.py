"""Local sqlite store for settings and the dashboard admin account.

The flat conf file stays the runtime view - systemd units and the CLI read it.
This database is written first so a lost conf file does not lose the webhooks,
and it is the only place the admin password hash lives.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from typing import Any

from . import core

DB_FILE = core.STATE / "vexashield.db"
PBKDF2_ROUNDS = 200_000

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS config (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL DEFAULT '',
    updated TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    created       TEXT NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE), timeout=15)
    conn.executescript(_SCHEMA)
    try:
        os.chmod(DB_FILE, 0o600)
    except OSError:
        pass
    return conn


def put_config(cfg: dict[str, Any]) -> None:
    now = core.utc_iso()
    rows = [(str(k), "" if v is None else str(v), now) for k, v in cfg.items()]
    if not rows:
        return
    with _lock:
        with _connect() as conn:
            conn.executemany(
                "INSERT INTO config(key, value, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated=excluded.updated",
                rows,
            )


def get_config() -> dict[str, str]:
    if not DB_FILE.exists():
        return {}
    try:
        with _lock:
            with _connect() as conn:
                rows = conn.execute("SELECT key, value FROM config").fetchall()
    except sqlite3.Error as exc:
        core.log("warn", f"config database unreadable: {exc}")
        return {}
    return {row[0]: row[1] for row in rows}


def set_admin(password: str, email: str = "") -> bool:
    """Store the dashboard admin password as a pbkdf2 digest."""
    if not password:
        return False
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS
    ).hex()
    stored = f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt}${digest}"
    now = core.utc_iso()
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO admin(id, password_hash, email, created) "
                "VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "password_hash=excluded.password_hash, email=excluded.email",
                (stored, email.strip(), now),
            )
    return True


def set_email(email: str) -> None:
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO admin(id, email, created) VALUES (1, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET email=excluded.email",
                (email.strip(), core.utc_iso()),
            )


def admin() -> dict[str, str]:
    """The admin row, or an empty dict when no account exists yet."""
    if not DB_FILE.exists():
        return {}
    try:
        with _lock:
            with _connect() as conn:
                row = conn.execute(
                    "SELECT password_hash, email, created FROM admin WHERE id=1"
                ).fetchone()
    except sqlite3.Error:
        return {}
    if not row:
        return {}
    return {"password_hash": row[0], "email": row[1], "created": row[2]}


def has_password() -> bool:
    return bool(admin().get("password_hash"))


def check_password(candidate: str) -> bool:
    stored = admin().get("password_hash", "")
    if not stored or not candidate:
        return False
    try:
        algo, rounds, salt, digest = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac(
            "sha256", candidate.encode(), bytes.fromhex(salt), int(rounds)
        ).hex()
    except (ValueError, TypeError, OverflowError):
        return False
    return hmac.compare_digest(got, digest)
