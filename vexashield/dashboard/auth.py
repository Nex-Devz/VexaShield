"""Session handling for the dashboard."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path

from .. import core

SESSION_DIR = core.STATE / "sessions"
TTL = 12 * 3600
LOGIN_WINDOW = 60
LOGIN_MAX = 5

_attempts: dict[str, list[float]] = {}


def login_allowed(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _attempts.get(ip, []) if now - t < LOGIN_WINDOW]
    _attempts[ip] = hits
    return len(hits) < LOGIN_MAX


def record_attempt(ip: str) -> None:
    _attempts.setdefault(ip, []).append(time.time())


def check_token(candidate: str, expected: str) -> bool:
    if not expected:
        return False
    return hmac.compare_digest(candidate.encode(), expected.encode())


def create_session(ip: str) -> dict:
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    sid = secrets.token_urlsafe(24)
    csrf = secrets.token_urlsafe(18)
    payload = {"id": sid, "csrf": csrf, "ip": ip,
               "created": time.time(), "expires": time.time() + TTL}
    (SESSION_DIR / f"{sid}.json").write_text(json.dumps(payload), encoding="utf-8")
    return payload


def load_session(sid: str) -> dict | None:
    if not sid or len(sid) > 80:
        return None
    path = SESSION_DIR / f"{sid}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if data.get("expires", 0) < time.time():
        try:
            path.unlink()
        except OSError:
            pass
        return None
    return data


def destroy_session(sid: str) -> None:
    if sid and len(sid) <= 80:
        try:
            (SESSION_DIR / f"{sid}.json").unlink()
        except OSError:
            pass


def sweep() -> None:
    if not SESSION_DIR.is_dir():
        return
    for f in SESSION_DIR.glob("*.json"):
        try:
            if json.loads(f.read_text(encoding="utf-8")).get("expires", 0) < time.time():
                f.unlink()
        except (OSError, ValueError):
            continue


def constant_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
