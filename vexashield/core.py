"""VexaShield - shared runtime: paths, config, logging, subprocess helpers."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

VERSION = "1.0.0"
PRODUCT = "VexaShield"

# ----------------------------------------------------------------- paths
ROOT = Path(os.environ.get("VS_ROOT", "/opt/vexashield"))
ETC = Path(os.environ.get("VS_ETC", "/etc/vexashield"))
STATE = Path(os.environ.get("VS_STATE", "/var/lib/vexashield"))
LOGDIR = Path(os.environ.get("VS_LOGDIR", "/var/log/vexashield"))
RUNDIR = Path(os.environ.get("VS_RUN", "/run/vexashield"))
CONFIG_FILE = ETC / "vexashield.conf"

_DEFAULTS: dict[str, Any] = {
    # protection
    "profile": "standard",              # lite | standard | aggressive
    "log_drops": 1,
    "strict_firewall": 1,               # default-deny INPUT (ufw)
    "allowed_ports": "22,80,443,7890",  # tcp list given to ufw
    "allowed_ports_udp": "7890",
    "allowed_port_ranges": "2000-2050",  # pterodactyl game ports (tcp+udp)
    # discord
    "alert_webhook": "",
    "backup_webhook": "",
    "mention_id": "",
    # database backup
    "db_name": "panel",
    "db_user": "root",
    "db_pass": "",
    "db_host": "",
    "db_all_databases": 0,
    "attack_pps_alert": 500,
    "backup_dir": "/var/backups/vexashield",
    "backup_at": "02:00",
    "backup_retention": 7,
    "backup_compress": 6,
    "backup_chunk_mb": 8,
    "backup_notify": 1,
    # nginx http flood
    "nginx_enabled": 1,
    "nginx_rate": "10r/s",
    "nginx_burst": 30,
    "nginx_conn": 25,
    "nginx_whitelist": "",
    # fail2ban
    "f2b_enabled": 1,
    "f2b_http_retry": 12,
    "f2b_http_find": 60,
    "f2b_http_ban": 600,
    "f2b_scan_retry": 5,
    "f2b_scan_find": 600,
    "f2b_scan_ban": 86400,
    "f2b_flood_enabled": 1,
    "f2b_flood_retry": 15,
    "f2b_flood_find": 60,
    "f2b_flood_ban": 1800,
    # dashboard
    "dash_port": 7890,
    "dash_bind": "0.0.0.0",
    "dash_token": "",
    # feature toggles
    "enable_ddos": 1,
    "enable_backup": 1,
    "enable_nginx": 1,
}


# ----------------------------------------------------------------- logging
_COLORS = {
    "ok": "\033[32m", "info": "\033[34m", "warn": "\033[33m",
    "err": "\033[31m", "step": "\033[36m", "dim": "\033[2m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_LOGFILE: Path | None = None


def _colorize(on: bool, color: str, text: str) -> str:
    return f"{color}{text}{_RESET}" if on else text


def log(level: str, msg: str, *, echo: bool = True) -> None:
    if echo:
        use = sys.stdout.isatty()
        tag = {"ok": " ok ", "info": "info", "warn": "warn",
               "err": "fail", "step": " .  "}.get(level, "  ")
        line = _colorize(use, _COLORS.get(level, ""), f"[{tag}]") + f" {msg}"
        (sys.stderr if level == "err" else sys.stdout).write(line + "\n")
    if _LOGFILE:
        try:
            with open(_LOGFILE, "a", encoding="utf-8") as fh:
                fh.write(f"{utc_iso()} [{level}] {msg}\n")
        except OSError:
            pass


def init_logging(name: str) -> None:
    global _LOGFILE
    ensure_dirs()
    _LOGFILE = LOGDIR / f"{name}.log"
    try:
        os.chmod(_LOGFILE, 0o640)
    except OSError:
        pass


def die(msg: str, code: int = 1) -> "None":
    log("err", msg)
    raise SystemExit(code)


def ensure_dirs() -> None:
    for p in (ETC, STATE, LOGDIR, RUNDIR,
              STATE / "rules", STATE / "backups", STATE / "sessions"):
        try:
            p.mkdir(parents=True, exist_ok=True)
            if p in (ETC, STATE):
                os.chmod(p, 0o700)
        except OSError:
            pass


def need_root() -> None:
    if os.geteuid() != 0:
        die("root privileges required (run with sudo)")


# ----------------------------------------------------------------- time/fmt
def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.1f}TB"


def rel_time(ts: float | str | None) -> str:
    if ts is None:
        return "never"
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return str(ts)
    d = time.time() - ts
    if d < 0:
        d = 0
    for limit, div, name in ((60, 1, "s"), (3600, 60, "m"),
                             (86400, 3600, "h"), (2592000, 86400, "d")):
        if d < limit:
            return f"{int(d // div)}{name} ago"
    return f"{int(d // 2592000)}mo ago"


# ----------------------------------------------------------------- config
def config_defaults() -> dict[str, Any]:
    return dict(_DEFAULTS)


def load_config() -> dict[str, Any]:
    cfg = config_defaults()
    if CONFIG_FILE.exists():
        for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if key not in cfg:
                continue
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            if isinstance(_DEFAULTS[key], int):
                try:
                    val = int(val)
                except ValueError:
                    pass
            cfg[key] = val
    if not cfg.get("backup_webhook"):
        cfg["backup_webhook"] = cfg.get("alert_webhook", "")
    if not cfg.get("dash_token"):
        cfg["dash_token"] = secrets.token_urlsafe(32)
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    ensure_dirs()
    lines = [
        f"# {PRODUCT} configuration - generated {utc_iso()}",
        "# Holds webhook URLs and DB credentials. Keep out of version control.",
        "",
    ]
    for key in _DEFAULTS:
        if key in cfg:
            lines.append(f"{key}={cfg[key]!r}".replace("'", '"'))
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(CONFIG_FILE)
    log("ok", f"config written -> {CONFIG_FILE}")


# ----------------------------------------------------------------- process
def run(cmd: Iterable[str] | str, *, check: bool = False, timeout: int = 120,
        input_text: str | None = None, env: dict | None = None
        ) -> subprocess.CompletedProcess:
    if isinstance(cmd, str):
        cmd = ["/bin/sh", "-c", cmd]
    else:
        cmd = [str(c) for c in cmd]
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            check=check, input=input_text, env=env,
        )
    except FileNotFoundError:
        # a missing optional tool must never crash a request handler
        return subprocess.CompletedProcess(cmd, 127, "",
                                           f"{cmd[0]}: command not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, data: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(path)


@contextmanager
def timer():
    start = time.time()
    yield lambda: time.time() - start


def prompt(label: str, default: str = "", *, secret: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    if secret:
        import getpass
        val = getpass.getpass(f"{label}{suffix}: ")
    else:
        val = input(f"{label}{suffix}: ").strip()
    return val or default


def choose(label: str, options: list[str], default: str) -> str:
    print(_colorize(sys.stdout.isatty(), _BOLD, label))
    for i, opt in enumerate(options, 1):
        print(f"   {i}) {opt}")
    raw = input(f"Choice [{default}]: ").strip()
    if not raw:
        return default
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    return raw if raw in options else default


def confirm(label: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input(f"{label} [{hint}]: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")
