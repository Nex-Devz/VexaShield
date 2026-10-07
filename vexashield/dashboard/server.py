"""VexaShield dashboard - stdlib HTTP server (no framework, no pip)."""

from __future__ import annotations

import hmac
import json
import mimetypes
import secrets
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .. import backup as backup_mod
from .. import core, ddos, state, ufw
from . import auth

STATIC = Path(__file__).resolve().parent / "static"
MAX_BODY = 64 * 1024
_state_lock = threading.Lock()
_backup_running = False


class Handler(BaseHTTPRequestHandler):
    server_version = "VexaShield"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------- plumbing
    def log_message(self, fmt: str, *args) -> None:  # quiet access log
        pass

    @property
    def ip(self) -> str:
        return self.client_address[0]

    def _cookies(self) -> SimpleCookie:
        jar = SimpleCookie()
        if self.headers.get("Cookie"):
            try:
                jar.load(self.headers["Cookie"])
            except Exception:  # noqa: BLE001
                pass
        return jar

    def _session(self) -> dict | None:
        morsel = self._cookies().get("vs_sid")
        return auth.load_session(morsel.value) if morsel else None

    def _send(self, code: int, body: bytes, ctype: str,
              extra: dict | None = None, cache: bool = False) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; "
                         "style-src 'self'; script-src 'self'; "
                         "connect-src 'self'; frame-ancestors 'none'")
        if not cache:
            self.send_header("Cache-Control", "no-store")
        else:
            self.send_header("Cache-Control", "public, max-age=300")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, code: int = 200, extra: dict | None = None) -> None:
        self._send(code, json.dumps(data).encode(), "application/json", extra)

    def _page(self, name: str, code: int = 200) -> None:
        path = STATIC / name
        if not path.is_file():
            self._send(404, b"not found", "text/plain")
            return
        body = path.read_bytes()
        self._send(code, body, "text/html; charset=utf-8")

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0:
            return {}
        if length > MAX_BODY:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    # ------------------------------------------------------------ endpoints
    def do_GET(self) -> None:  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        path = url.path

        if path.startswith("/static/"):
            return self._static(path[len("/static/"):])
        if path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")
        if path in ("/", "/index.html", "/login"):
            sess = self._session()
            if path == "/login" and not sess:
                return self._page("login.html")
            if not sess:
                return self._page("login.html")
            return self._page("index.html")
        try:
            if path.startswith("/api/"):
                sess = self._session()
                if path == "/api/health":
                    return self._json({"ok": True, "version": core.VERSION})
                if not sess:
                    return self._json({"error": "unauthorized"}, 401)
                if path == "/api/session":
                    return self._json({"ok": True,
                                       "csrf": sess.get("csrf", ""),
                                       "user": "root"})
                return self._api_get(path, url.query, sess)
            self._send(404, b"not found", "text/plain")
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001 - never drop the connection
            core.log("err", f"GET {path}: {type(exc).__name__}: {exc}")
            try:
                self._json({"error": "internal error"}, 500)
            except Exception:  # noqa: BLE001
                pass

    def do_POST(self) -> None:  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        path = url.path
        if path == "/api/login":
            return self._login()
        if path == "/api/logout":
            return self._logout()
        try:
            sess = self._session()
            if not sess:
                return self._json({"error": "unauthorized"}, 401)
            csrf = self.headers.get("X-VS-CSRF", "")
            if not csrf or not hmac.compare_digest(csrf, sess.get("csrf", "")):
                return self._json({"error": "csrf"}, 403)
            return self._api_post(path, self._body())
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001
            core.log("err", f"POST {path}: {type(exc).__name__}: {exc}")
            try:
                self._json({"error": "internal error"}, 500)
            except Exception:  # noqa: BLE001
                pass

    # --------------------------------------------------------------- auth
    def _login(self) -> None:
        if not auth.login_allowed(self.ip):
            auth.record_attempt(self.ip)
            return self._json({"error": "too many attempts, wait a minute"}, 429)
        body = self._body()
        token = str(body.get("token", ""))
        cfg = core.load_config()
        if not auth.check_token(token, cfg.get("dash_token", "")):
            auth.record_attempt(self.ip)
            state.clear_cache()
            return self._json({"error": "invalid token"}, 401)
        auth._attempts.pop(self.ip, None)
        sess = auth.create_session(self.ip)
        cookie = (f"vs_sid={sess['id']}; Path=/; HttpOnly; SameSite=Strict; "
                  f"Max-Age={auth.TTL}")
        self._json({"ok": True, "csrf": sess["csrf"]},
                   extra={"Set-Cookie": cookie})

    def _logout(self) -> None:
        jar = self._cookies()
        m = jar.get("vs_sid")
        if m:
            auth.destroy_session(m.value)
        self._json({"ok": True},
                   extra={"Set-Cookie": "vs_sid=; Path=/; HttpOnly; Max-Age=0"})

    # ------------------------------------------------------------- routing
    def _api_get(self, path: str, query: str, sess: dict | None = None) -> None:
        if path == "/api/overview":
            return self._json(state.overview())
        if path == "/api/bans":
            return self._json(state.bans())
        if path == "/api/drops":
            return self._json({"drops": state.kernel_drops(80)})
        if path == "/api/events":
            return self._json({"events": state.recent_events(120)})
        if path == "/api/backups":
            cfg = core.load_config()
            return self._json({
                "files": backup_mod.list_backups(cfg),
                "verify": backup_mod.verify(cfg),
                "history": core.read_json(core.STATE / "backups.json",
                                          {"runs": [], "last": None}),
                "running": _backup_running,
            })
        if path == "/api/config":
            return self._json(_public_config(core.load_config()))
        return self._json({"error": "not found"}, 404)

    def _api_post(self, path: str, body: dict) -> None:
        cfg = core.load_config()

        if path == "/api/ban":
            ok, msg = state.ban(str(body.get("jail", "vs-portscan")),
                                str(body.get("ip", "")))
            _security_log(f"manual ban {body.get('ip')} -> {msg}")
            return self._json({"ok": ok, "msg": msg})

        if path == "/api/unban":
            ok, msg = state.unban(str(body.get("jail", "vs-portscan")),
                                  str(body.get("ip", "")))
            _security_log(f"manual unban {body.get('ip')} -> {msg}")
            return self._json({"ok": ok, "msg": msg})

        if path == "/api/backup/run":
            global _backup_running
            with _state_lock:
                if _backup_running:
                    return self._json({"ok": False, "msg": "backup already running"}, 409)
                _backup_running = True
            threading.Thread(target=_run_backup, args=(cfg,), daemon=True).start()
            return self._json({"ok": True, "msg": "backup started"})

        if path == "/api/protection":
            prof = str(body.get("profile", cfg.get("profile")))
            if prof not in ddos.PROFILES:
                return self._json({"error": "unknown profile"}, 400)
            cfg["profile"] = prof
            if "log_drops" in body:
                cfg["log_drops"] = 1 if body.get("log_drops") else 0
            core.save_config(cfg)
            ddos.apply(cfg)
            state.clear_cache()
            return self._json({"ok": True, "profile": prof})

        if path == "/api/protection/reload":
            ddos.apply(cfg)
            if int(cfg.get("nginx_enabled", 1)):
                ddos.nginx_install(cfg)
            if int(cfg.get("f2b_enabled", 1)):
                ddos.fail2ban_install(cfg)
                ddos.install_discord_action()
                core.run(["fail2ban-client", "reload"])
            state.clear_cache()
            return self._json({"ok": True})

        if path == "/api/config":
            updatable = {
                "backup_at", "backup_retention", "backup_compress",
                "nginx_rate", "nginx_burst", "nginx_conn",
                "mention_id", "f2b_http_ban", "f2b_flood_ban",
                "profile", "log_drops", "enable_backup", "enable_ddos",
            }
            changed = False
            for key in updatable:
                if key in body:
                    val = body[key]
                    if isinstance(_core_default(key), int) and not isinstance(val, bool):
                        try:
                            val = int(val)
                        except (TypeError, ValueError):
                            continue
                    cfg[key] = val
                    changed = True
            if changed:
                core.save_config(cfg)
                if int(cfg.get("nginx_enabled", 1)) and any(
                        k in body for k in ("nginx_rate", "nginx_burst", "nginx_conn")):
                    ddos.nginx_install(cfg)
                state.clear_cache()
            return self._json({"ok": True, "config": _public_config(cfg)})

        if path == "/api/ufw/reload":
            res = ufw.configure(cfg, enable=bool(body.get("enable", True)))
            state.clear_cache()
            return self._json(res)

        return self._json({"error": "not found"}, 404)

    # -------------------------------------------------------------- static
    def _static(self, rel: str) -> None:
        target = (STATIC / rel).resolve()
        if not str(target).startswith(str(STATIC.resolve())) or not target.is_file():
            return self._send(404, b"not found", "text/plain")
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send(200, target.read_bytes(), ctype, cache=True)


def _core_default(key: str):
    return core.config_defaults().get(key, 0)


def _run_backup(cfg: dict) -> None:
    global _backup_running
    try:
        backup_mod.run_backup(cfg)
    finally:
        state.clear_cache()
        with _state_lock:
            _backup_running = False


def _security_log(msg: str) -> None:
    core.init_logging("security")
    core.log("info", msg)


def _public_config(cfg: dict) -> dict:
    """Config safe to expose - webhook URLs and tokens are never returned."""
    def mask(v: str) -> str:
        v = str(v or "")
        if not v:
            return ""
        tail = v[-8:] if len(v) > 8 else v
        return f"••••••••{tail}"

    return {
        "profile": cfg.get("profile"),
        "log_drops": cfg.get("log_drops"),
        "dash_port": cfg.get("dash_port"),
        "db_name": cfg.get("db_name"),
        "backup_at": cfg.get("backup_at"),
        "backup_retention": cfg.get("backup_retention"),
        "backup_compress": cfg.get("backup_compress"),
        "backup_dir": cfg.get("backup_dir"),
        "nginx_rate": cfg.get("nginx_rate"),
        "nginx_burst": cfg.get("nginx_burst"),
        "nginx_conn": cfg.get("nginx_conn"),
        "mention_id": cfg.get("mention_id"),
        "f2b_http_ban": cfg.get("f2b_http_ban"),
        "f2b_flood_ban": cfg.get("f2b_flood_ban"),
        "enable_backup": cfg.get("enable_backup"),
        "enable_ddos": cfg.get("enable_ddos"),
        "webhook_alert": mask(cfg.get("alert_webhook")),
        "webhook_backup": mask(cfg.get("backup_webhook")),
        "has_token": bool(cfg.get("dash_token")),
    }


def serve(bind: str, port: int) -> None:
    auth.sweep()
    core.ensure_dirs()
    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.daemon_threads = True
    httpd.allow_reuse_address = True
    core.log("ok", f"dashboard listening on http://{bind}:{port}")
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        core.log("info", "dashboard stopped")
    finally:
        httpd.server_close()
