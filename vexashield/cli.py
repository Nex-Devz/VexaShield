"""VexaShield command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import backup, core, ddos, state, ufw
from . import __version__


def _cmd_status(a) -> int:
    cfg = core.load_config()
    if a.json:
        data = state.overview(force=True)
        data["config"] = core.load_config() if a.full else data.get("config")
        print(json.dumps(data, indent=2))
        return 0

    p = ddos.counters()
    core.log("info", f"{core.PRODUCT} v{core.VERSION} on {os.uname().nodename}")
    if p["loaded"]:
        core.log("ok", f"scrubbing chain loaded - profile={p['profile']} "
                       f"inspected={p['packets']:,} dropped={p['dropped']:,}")
    else:
        core.log("warn", "scrubbing chain NOT loaded - run: vexashield ddos apply")

    h = ddos.health(cfg)
    for label, val in (("sysctl", h["sysctl"]), ("nginx", h["nginx"]),
                       ("fail2ban", h["fail2ban"]), ("ufw", bool(h["ufw"]))):
        core.log("ok" if val else "warn", f"  {label:<9} {'active' if val else 'off'}")

    b = state.bans()
    core.log("info", f"banned now: {b['total']} across {len(b['jails'])} jail(s)")
    last = core.read_json(core.STATE / "last_backup.json", {}) or {}
    if last:
        state_txt = "ok" if last.get("ok") else "failed"
        core.log("ok" if last.get("ok") else "err",
                 f"last backup: {state_txt} {last.get('file', '')} "
                 f"({core.rel_time(last.get('at'))})")
    return 0


def _cmd_ddos(a) -> int:
    cfg = core.load_config()
    if a.action == "apply":
        core.init_logging("security")
        if a.profile:
            cfg["profile"] = a.profile
            core.save_config(cfg)
        ddos.apply(cfg, quiet=a.quiet)
        if int(cfg.get("nginx_enabled", 1)):
            ddos.nginx_install(cfg)
        return 0
    if a.action == "reset":
        ddos.reset()
        return 0
    if a.action == "status":
        print(json.dumps(ddos.counters(), indent=2))
        return 0
    if a.action == "profile":
        if a.value not in ddos.PROFILES:
            core.die(f"unknown profile {a.value!r} - choose {', '.join(ddos.PROFILES)}")
        cfg["profile"] = a.value
        core.save_config(cfg)
        ddos.apply(cfg)
        return 0
    return 1


def _cmd_backup(a) -> int:
    cfg = core.load_config()
    if a.action == "run":
        res = backup.run_backup(cfg)
        return 0 if res["ok"] else 2
    if a.action == "list":
        rows = backup.list_backups(cfg)
        if not rows:
            core.log("info", "no archives yet")
            return 0
        for r in rows:
            print(f"{core.human_bytes(r['size']):>10}  {r['age']:>10}  {r['file']}")
        return 0
    if a.action == "verify":
        bad = 0
        for r in backup.verify(cfg):
            flag = "ok  " if r["valid"] else "FAIL"
            print(f"{flag}  {r['file']}  entries={r['entries']} {r['error']}")
            bad += 0 if r["valid"] else 1
        return 1 if bad else 0
    return 1


def _cmd_bans(a) -> int:
    if a.action == "add":
        ok, msg = state.ban(a.jail, a.ip)
        core.log("ok" if ok else "err", msg or f"banned {a.ip} in {a.jail}")
        return 0 if ok else 1
    if a.action == "del":
        ok, msg = state.unban(a.jail, a.ip)
        core.log("ok" if ok else "err", msg or f"unbanned {a.ip}")
        return 0 if ok else 1
    data = state.bans()
    if a.json:
        print(json.dumps(data, indent=2))
        return 0
    for j in data["jails"]:
        print(f"{j['jail']:<22} active={j['currently_banned']:<4} "
              f"lifetime={j['total_banned']}")
        for ip in j["ips"]:
            print(f"    {ip}")
    if not data["jails"]:
        core.log("warn", "fail2ban not available")
    return 0


def _cmd_firewall(a) -> int:
    cfg = core.load_config()
    if a.action == "sync":
        res = ufw.configure(cfg, enable=True)
        return 0 if res.get("ok") else 1
    if a.action == "status":
        print(json.dumps(ufw.status(), indent=2))
        return 0
    if a.action == "disable":
        ufw.disable()
        return 0
    return 1


def _cmd_notify(a) -> int:
    """Called by fail2ban actions: notify ban|unban <ip> <jail> <fails> <bantime>."""
    from . import discord
    cfg = core.load_config()
    url = cfg.get("alert_webhook", "")
    if not url:
        return 0
    action, ip, jail, failures, bantime = (list(a.args) + ["", "", "", ""])[:5]
    try:
        secs = int(float(bantime or 0))
    except ValueError:
        secs = 0
    if secs >= 604800:
        duration, color = "7 days", discord.AMBER
    elif secs >= 3600:
        duration, color = f"{secs // 3600} hour(s)", discord.RED
    elif secs > 0:
        duration, color = f"{secs // 60} minute(s)", discord.SLATE
    else:
        duration, color = "permanent", discord.RED

    if action == "ban":
        discord.send_alert(
            url, "Address banned",
            f"`{ip}` matched **{jail}** and was blocked.",
            color=color,
            fields=[("Address", f"`{ip}`", True), ("Jail", f"`{jail}`", True),
                    ("Failures", f"`{failures or 'manual'}`", True),
                    ("Duration", f"`{duration}`", True),
                    ("Host", f"`{os.uname().nodename}`", True)],
            mention=cfg.get("mention_id", ""),
            footer="VexaShield Security",
        )
        core.init_logging("security")
        core.log("info", f"banned {ip} via {jail} ({duration})")
    else:
        discord.send_alert(
            url, "Address released",
            f"`{ip}` was released from **{jail}**.",
            color=discord.GREEN,
            fields=[("Address", f"`{ip}`", True), ("Jail", f"`{jail}`", True)],
            mention=cfg.get("mention_id", ""),
            footer="VexaShield Security",
        )
    return 0


def _cmd_dashboard(a) -> int:
    cfg = core.load_config()
    from .dashboard import serve
    core.init_logging("dashboard")
    bind = cfg.get("dash_bind", "0.0.0.0")
    port = int(cfg.get("dash_port", 7890))
    if a.action == "run":
        serve(bind, port)
        return 0
    if a.action == "url":
        host = os.uname().nodename
        print(f"http://{host}:{port}")
        return 0
    return 1


def _cmd_webhook(a) -> int:
    from . import discord
    cfg = core.load_config()
    host = os.uname().nodename
    targets = {"alert": cfg.get("alert_webhook"), "backup": cfg.get("backup_webhook")}
    if a.which in targets and a.which != "all":
        targets = {a.which: targets.get(a.which)}
    rc = 0
    for label, url in targets.items():
        if not url:
            core.log("warn", f"{label}: not configured")
            rc = 1
            continue
        if discord.ping(url, label, host):
            core.log("ok", f"{label}: webhook reachable")
        else:
            core.log("err", f"{label}: delivery failed")
            rc = 1
    return rc


def _cmd_config(a) -> int:
    cfg = core.load_config()
    if a.action == "show":
        safe = {k: v for k, v in cfg.items()
                if "webhook" not in k and k != "dash_token" and k != "db_pass"}
        if a.json:
            print(json.dumps(safe, indent=2))
        else:
            for k in sorted(safe):
                print(f"{k}={safe[k]}")
        print(f"alert_webhook={'set' if cfg.get('alert_webhook') else 'unset'}")
        print(f"backup_webhook={'set' if cfg.get('backup_webhook') else 'unset'}")
        print(f"dash_token={'set' if cfg.get('dash_token') else 'unset'}")
        return 0
    if a.action == "set":
        if a.key not in core.config_defaults():
            core.die(f"unknown key {a.key!r}")
        default = core.config_defaults()[a.key]
        value: object = a.value
        if isinstance(default, int) and not isinstance(default, bool):
            try:
                value = int(a.value)
            except ValueError:
                core.die(f"{a.key} expects an integer")
        cfg[a.key] = value
        core.save_config(cfg)
        return 0
    return 1


def _cmd_doctor(a) -> int:
    cfg = core.load_config()
    checks: list[tuple[str, bool, str]] = []

    def add(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    add("root", os.geteuid() == 0, f"uid={os.geteuid()}")
    add("python>=3.10", sys.version_info >= (3, 10), sys.version.split()[0])
    for tool in ("iptables", "iptables-save", "fail2ban-client", "nginx",
                 "mysqldump", "mariadb-dump", "ufw", "journalctl"):
        found = core.have(tool)
        add(f"tool:{tool}", found, "found" if found else "missing")
    add("config", core.CONFIG_FILE.exists(), str(core.CONFIG_FILE))
    add("alert_webhook", bool(cfg.get("alert_webhook")))
    add("backup_webhook", bool(cfg.get("backup_webhook")))
    add("dash_token", bool(cfg.get("dash_token")))
    p = ddos.counters()
    add("scrubbing_chain", p["loaded"], f"{p['rules']} rules")
    add("sysctl_file", ddos.SYSCTL_FILE.exists())
    add("fail2ban_jail", Path("/etc/fail2ban/jail.d/vexashield.conf").exists())
    add("nginx_snippet", Path("/etc/nginx/snippets/vexashield-server.conf").exists())
    for unit in ("vexashield-firewall", "vexashield-dashboard",
                 "vexashield-backup.timer"):
        active = core.run(["systemctl", "is-active", unit]).stdout.strip()
        add(f"unit:{unit}", active in ("active", "waiting"), active or "inactive")
    bdir = Path(cfg.get("backup_dir", "/var/backups/vexashield"))
    add("backup_dir", bdir.is_dir() and os.access(bdir, os.W_OK), str(bdir))

    failed = 0
    for name, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"{mark}  {name:<28} {detail}")
    print(f"\n{len(checks) - failed}/{len(checks)} checks passed")
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="vexashield",
        description="Anti-DDoS protection, database backup and control dashboard.",
        epilog="docs: https://github.com/nex-devz/VexaShield",
    )
    ap.add_argument("-v", "--version", action="version",
                    version=f"{core.PRODUCT} {core.VERSION}")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("status", help="one-line health summary")
    p.add_argument("--json", action="store_true")
    p.add_argument("--full", action="store_true")
    p.set_defaults(fn=_cmd_status)

    d = sub.add_parser("ddos", help="anti-DDoS chain control")
    dsub = d.add_subparsers(dest="action")
    da = dsub.add_parser("apply")
    da.add_argument("--profile", choices=ddos.PROFILES)
    da.add_argument("--quiet", action="store_true")
    dsub.add_parser("reset")
    dsub.add_parser("status")
    dp = dsub.add_parser("profile")
    dp.add_argument("value", choices=ddos.PROFILES)
    d.set_defaults(fn=_cmd_ddos)

    b = sub.add_parser("backup", help="database backup control")
    bsub = b.add_subparsers(dest="action")
    br = bsub.add_parser("run")
    br.add_argument("--quiet", action="store_true")
    bsub.add_parser("list")
    bsub.add_parser("verify")
    b.set_defaults(fn=_cmd_backup)

    n = sub.add_parser("ban", help="manual bans via fail2ban")
    nsub = n.add_subparsers(dest="action")
    na = nsub.add_parser("add")
    na.add_argument("jail")
    na.add_argument("ip")
    nd = nsub.add_parser("del")
    nd.add_argument("jail")
    nd.add_argument("ip")
    nl = nsub.add_parser("list")
    nl.add_argument("--json", action="store_true")
    n.set_defaults(fn=_cmd_bans)

    f = sub.add_parser("firewall", help="host firewall (ufw) control")
    fsub = f.add_subparsers(dest="action")
    fsub.add_parser("sync")
    fs = fsub.add_parser("status")
    fs.add_argument("--json", action="store_true")
    fsub.add_parser("disable")
    f.set_defaults(fn=_cmd_firewall)

    nt = sub.add_parser("notify", help="fail2ban action hook")
    nt.add_argument("args", nargs="*")
    nt.set_defaults(fn=_cmd_notify)

    db = sub.add_parser("dashboard", help="control dashboard")
    dbsub = db.add_subparsers(dest="action")
    dbsub.add_parser("run")
    dbsub.add_parser("url")
    db.set_defaults(fn=_cmd_dashboard)

    w = sub.add_parser("webhook", help="test discord webhooks")
    w.add_argument("which", nargs="?", default="all",
                   choices=["alert", "backup", "all"])
    w.set_defaults(fn=_cmd_webhook)

    c = sub.add_parser("config", help="read or write configuration")
    csub = c.add_subparsers(dest="action")
    cs = csub.add_parser("show")
    cs.add_argument("--json", action="store_true")
    ct = csub.add_parser("set")
    ct.add_argument("key")
    ct.add_argument("value")
    c.set_defaults(fn=_cmd_config)

    m = sub.add_parser("monitor", help="run the attack monitor daemon")
    m.set_defaults(fn=lambda a: (ddos.watch(core.load_config()), 0)[1])

    doc = sub.add_parser("doctor", help="diagnose the installation")
    doc.set_defaults(fn=_cmd_doctor)

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "fn", None):
        ap.print_help()
        return 1
    core.ensure_dirs()
    try:
        return int(args.fn(args) or 0)
    except KeyboardInterrupt:
        return 130
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception as exc:  # noqa: BLE001
        core.log("err", f"{type(exc).__name__}: {exc}")
        if os.environ.get("VS_DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
