"""State collectors for the dashboard (no external dependencies)."""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path

from . import core, ddos, ufw

_cache: dict = {"ts": 0.0, "data": {}}
_TTL = 4.0


# ------------------------------------------------------------- small reads
def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def cpu_load() -> dict:
    out = {"cores": os.cpu_count() or 1, "percent": 0.0, "load": []}
    one, five, fifteen = os.getloadavg()
    out["load"] = [round(one, 2), round(five, 2), round(fifteen, 2)]
    out["percent"] = round(min(100.0, one / out["cores"] * 100), 1)
    return out


def memory() -> dict:
    info = {}
    for line in _read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        info[k.strip()] = v.strip()
    total = int(info.get("MemTotal", "0 kB").split()[0]) * 1024
    avail = int(info.get("MemAvailable", "0 kB").split()[0]) * 1024
    used = max(0, total - avail)
    swap_t = int(info.get("SwapTotal", "0 kB").split()[0]) * 1024
    swap_f = int(info.get("SwapFree", "0 kB").split()[0]) * 1024
    return {"total": total, "used": used, "available": avail,
            "percent": round(used / total * 100, 1) if total else 0.0,
            "swap_percent": round((swap_t - swap_f) / swap_t * 100, 1) if swap_t else 0.0}


def disks() -> list[dict]:
    out = []
    seen = set()
    for line in _read("/proc/mounts").splitlines():
        dev, mnt, fstype, *_ = line.split()
        if not dev.startswith("/dev/") or dev in seen:
            continue
        if fstype in ("squashfs", "tmpfs", "overlay", "proc", "sysfs", "devtmpfs"):
            continue
        seen.add(dev)
        try:
            st = os.statvfs(mnt)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            continue
        free = st.f_bfree * st.f_frsize
        used = total - free
        out.append({"mount": mnt, "device": dev, "total": total,
                    "used": used, "free": free,
                    "percent": round(used / total * 100, 1)})
    return out


def uptime_seconds() -> float:
    try:
        return float(_read("/proc/uptime").split()[0])
    except (ValueError, IndexError):
        return 0.0


def conntrack_count() -> int:
    txt = _read("/proc/sys/net/netfilter/nf_conntrack_count")
    if txt.strip().isdigit():
        return int(txt.strip())
    txt = _read("/proc/net/nf_conntrack")
    return len([l for l in txt.splitlines() if l.strip()]) if txt else 0


def network() -> dict:
    rx = tx = 0
    for line in _read("/proc/net/dev").splitlines()[2:]:
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        parts = rest.split()
        if name.strip() == "lo" or len(parts) < 9:
            continue
        rx += int(parts[0])
        tx += int(parts[8])
    return {"rx": rx, "tx": tx}


def services() -> list[dict]:
    names = ["nginx", "fail2ban", "ufw", "vexashield-dashboard",
             "vexashield-backup.timer", "vexashield-monitor",
             "mariadb", "ssh"]
    out = []
    for n in names:
        res = core.run(["systemctl", "is-active", n])
        out.append({"name": n, "state": (res.stdout.strip() or "unknown"),
                    "enabled": core.run(["systemctl", "is-enabled", n]).stdout.strip()})
    return out


# ----------------------------------------------------------------- fail2ban
def bans() -> dict:
    out = {"jails": [], "total": 0}
    if not core.have("fail2ban-client"):
        return out
    res = core.run(["fail2ban-client", "status"], timeout=20)
    names: list[str] = []
    for line in res.stdout.splitlines():
        if "Jail list" in line:
            names = [x.strip() for x in line.split(":", 1)[-1].split(",") if x.strip()]
    for jail in names:
        res_j = core.run(["fail2ban-client", "status", jail], timeout=20)
        info = {"jail": jail, "currently_banned": 0, "total_banned": 0, "ips": []}
        if res_j.returncode == 0:
            for line in res_j.stdout.splitlines():
                if "Currently banned" in line:
                    info["currently_banned"] = int(line.rsplit(":", 1)[-1].strip())
                elif "Total banned" in line:
                    info["total_banned"] = int(line.rsplit(":", 1)[-1].strip())
                elif "Banned IP list" in line:
                    info["ips"] = line.rsplit(":", 1)[-1].split()
        out["jails"].append(info)
        out["total"] += info["currently_banned"]
    return out


def ban(jail: str, ip: str) -> tuple[bool, str]:
    res = core.run(["fail2ban-client", "set", jail, "banip", ip], timeout=30)
    return res.returncode == 0, (res.stderr or res.stdout).strip()


def unban(jail: str, ip: str) -> tuple[bool, str]:
    res = core.run(["fail2ban-client", "set", jail, "unbanip", ip], timeout=30)
    return res.returncode == 0, (res.stderr or res.stdout).strip()


# ------------------------------------------------------------------ events
def recent_events(limit: int = 60) -> list[dict]:
    rows: list[dict] = []
    for name in ("backup", "monitor", "security", "install"):
        p = core.LOGDIR / f"{name}.log"
        if not p.exists():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines[-limit:]:
            parts = line.split("] ", 1)
            if len(parts) == 2 and parts[0].count("[") == 1:
                ts, rest = parts[0][1:], parts[1]
                lvl, _, msg = rest.partition(" ")
                rows.append({"ts": ts, "level": lvl.strip(), "msg": msg.strip(),
                             "source": name})
    rows.sort(key=lambda r: r["ts"], reverse=True)
    return rows[:limit]


def kernel_drops(limit: int = 40) -> list[dict]:
    if not core.have("journalctl"):
        return []
    res = core.run(["journalctl", "-k", "-n", "400", "--no-pager", "-o", "short-iso"],
                   timeout=25)
    rows = []
    pat = re.compile(r"^(?P<ts>\S+\s+\S+)\s+.*?(VS-SCAN|VS-FLOOD):\s+(?P<rest>.*)$")
    src = re.compile(r"SRC=(?P<src>\d+\.\d+\.\d+\.\d+)")
    dpt = re.compile(r"DPT=(?P<dpt>\d+)")
    proto = re.compile(r"PROTO=(?P<p>\w+)")
    for line in reversed(res.stdout.splitlines()):
        m = pat.search(line)
        if not m:
            continue
        s = src.search(m.group("rest"))
        p = proto.search(m.group("rest"))
        d = dpt.search(m.group("rest"))
        rows.append({"ts": m.group("ts"),
                     "kind": "scan" if "SCAN" in line else "flood",
                     "ip": s.group("src") if s else "?",
                     "proto": p.group("p") if p else "?",
                     "port": d.group("dpt") if d else "-"})
        if len(rows) >= limit:
            break
    return rows


# ----------------------------------------------------------------- overview
def overview(force: bool = False) -> dict:
    now = time.time()
    if not force and _cache["data"] and now - _cache["ts"] < _TTL:
        return _cache["data"]

    cfg = core.load_config()
    protection = ddos.health(cfg)
    data = {
        "generated": core.utc_iso(),
        "hostname": os.uname().nodename,
        "product": core.PRODUCT,
        "version": core.VERSION,
        "protection": protection,
        "cpu": cpu_load(),
        "memory": memory(),
        "disks": disks(),
        "network": network(),
        "uptime": uptime_seconds(),
        "conntrack": conntrack_count(),
        "bans": bans(),
        "backups": core.read_json(core.STATE / "backups.json",
                                  {"runs": [], "last": None}),
        "backup_files": _backup_files(cfg),
        "services": services(),
        "ufw": ufw.status(),
        "events": recent_events(30),
        "drops": kernel_drops(30),
        "config": {
            "profile": cfg.get("profile"),
            "dash_port": cfg.get("dash_port"),
            "db_name": cfg.get("db_name"),
            "backup_at": cfg.get("backup_at"),
            "backup_retention": cfg.get("backup_retention"),
            "nginx_rate": cfg.get("nginx_rate"),
            "webhook_alert": bool(cfg.get("alert_webhook")),
            "webhook_backup": bool(cfg.get("backup_webhook")),
        },
        "spark": _spark_buffer(protection.get("packets", 0)),
    }
    _cache["data"] = data
    _cache["ts"] = now
    return data


def _backup_files(cfg: dict) -> list[dict]:
    from . import backup as _b
    return _b.list_backups(cfg)


_SPARK: list[int] = []


def _spark_buffer(current: int) -> list[int]:
    if _SPARK and current < _SPARK[-1]:
        _SPARK.clear()
    if not _SPARK or current != _SPARK[-1]:
        _SPARK.append(current)
        if len(_SPARK) > 60:
            _SPARK.pop(0)
    return list(_SPARK)


def clear_cache() -> None:
    _cache["data"] = {}
    _cache["ts"] = 0.0
