#!/usr/bin/env python3
"""VexaShield interactive installer.

    sudo python3 install.py

Asks for the Discord webhook endpoints, provisions the anti-DDoS chain,
host firewall, nightly backup timer and the control dashboard.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from vexashield import backup, core, ddos, ufw  # noqa: E402
from vexashield import discord  # noqa: E402

BANNER = r"""
   ██╗   ██╗██╗███████╗██╗  ██╗ █████╗ ██████╗
   ██║   ██║██║██╔════╝██║  ██║██╔══██╗██╔══██╗
   ╚██╗ ██╔╝██║█████╗  ███████║███████║██████╔╝
    ╚████╔╝ ██║██╔══╝  ██╔══██║██╔══██║██╔══██╗
     ╚═══╝  ██║███████╗██║  ██║██║  ██║██║  ██║
           ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
   installer v{v}  -  github.com/nex-devz/VexaShield
""".format(v=core.VERSION)


def rule(title: str = "") -> None:
    print("\n\x1b[2m" + "─" * 66 + "\x1b[0m")
    if title:
        print(f"\x1b[1m{title}\x1b[0m\n")


def step(msg: str) -> None:
    core.log("step", msg)


def ok(msg: str) -> None:
    core.log("ok", msg)


def warn(msg: str) -> None:
    core.log("warn", msg)


def ask_webhook(label: str, default: str = "") -> str:
    while True:
        url = core.prompt(f"Discord {label} webhook URL", default)
        if not url:
            if core.confirm("Leave empty and skip?", True):
                return ""
            continue
        if "discord.com/api/webhooks/" not in url and "discordapp.com" not in url:
            warn("that does not look like a Discord webhook "
                 "(expected discord.com/api/webhooks/...)")
            if not core.confirm("Use it anyway?", False):
                continue
        return url


def install_files() -> Path:
    dest = Path(os.environ.get("VS_ROOT", "/opt/vexashield"))
    step("copying application files to /opt/vexashield ...")
    if dest.exists() and dest.resolve() != HERE:
        shutil.rmtree(dest)
    if HERE.resolve() != dest.resolve():
        shutil.copytree(HERE, dest, symlinks=True,
                        ignore=shutil.ignore_patterns(".git", "__pycache__",
                                                      "*.pyc", ".venv"))
    else:
        dest.mkdir(parents=True, exist_ok=True)
    for p in dest.rglob("*"):
        try:
            if p.is_file():
                os.chmod(p, 0o644)
            elif p.is_dir():
                os.chmod(p, 0o755)
        except OSError:
            pass
    for name in ("install.py", "uninstall.py"):
        f = dest / name
        if f.exists():
            os.chmod(f, 0o755)

    shim = Path("/usr/local/bin/vexashield")
    shim.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.path.insert(0, '/opt/vexashield')\n"
        "from vexashield.cli import main\n"
        "raise SystemExit(main())\n",
        encoding="utf-8",
    )
    os.chmod(shim, 0o755)
    ok(f"application installed -> {dest}")
    ok(f"command installed     -> {shim}")
    return dest


def install_units(dest: Path) -> None:
    unit_dir = Path("/etc/systemd/system")
    if not unit_dir.is_dir():
        warn("systemd not found - units skipped")
        return
    cfg = core.load_config()
    for name in ("vexashield-firewall.service", "vexashield-dashboard.service",
                 "vexashield-monitor.service", "vexashield-backup.service",
                 "vexashield-backup.timer"):
        src = dest / "systemd" / name
        if not src.is_file():
            continue
        text = src.read_text(encoding="utf-8")
        if name == "vexashield-backup.timer":
            hh, mm = (cfg.get("backup_at") or "02:00").split(":")[:2]
            text = text.replace(
                "OnCalendar=*-*-* 02:00:00",
                f"OnCalendar=*-*-* {int(hh):02d}:{int(mm):02d}:00",
            )
        (unit_dir / name).write_text(text, encoding="utf-8")
    core.run(["systemctl", "daemon-reload"])
    ok("systemd units installed (firewall, dashboard, monitor, backup timer)")


def enable_units() -> None:
    units = ["vexashield-firewall", "vexashield-dashboard",
             "vexashield-backup.timer"]
    if core.load_config().get("alert_webhook"):
        units.append("vexashield-monitor")
    for u in units:
        core.run(["systemctl", "enable", "--now", u])
    core.run(["systemctl", "restart", "vexashield-dashboard"])
    for u in units:
        state = core.run(["systemctl", "is-active", u]).stdout.strip()
        (ok if state == "active" else warn)(f"{u}: {state}")


def main() -> int:
    if os.geteuid() != 0:
        print("Run as root:  sudo python3 install.py", file=sys.stderr)
        return 1
    if sys.version_info < (3, 10):
        print("Python 3.10+ required", file=sys.stderr)
        return 1

    print(BANNER)
    core.ensure_dirs()
    core.init_logging("install")
    cfg = core.config_defaults()
    if core.CONFIG_FILE.exists():
        cfg = core.load_config()
        warn(f"existing config found at {core.CONFIG_FILE} - answers pre-filled")

    rule("1 / 5   Discord endpoints")
    print("Two webhooks are used:\n"
          "  security  - attacks, bans, manual blocks\n"
          "  backup    - nightly dump result (falls back to security)\n")
    alert = ask_webhook("security / DDoS alert", cfg.get("alert_webhook", ""))
    cfg["alert_webhook"] = alert
    if alert and core.confirm("Use the same webhook for backup results?", True):
        cfg["backup_webhook"] = alert
    else:
        cfg["backup_webhook"] = ask_webhook("backup result", cfg.get("backup_webhook", ""))
    mention = core.prompt("Discord user ID to ping on events (optional)",
                          cfg.get("mention_id", ""))
    cfg["mention_id"] = mention.strip()

    if alert or cfg.get("backup_webhook"):
        step("testing webhooks ...")
        host = os.uname().nodename
        if alert:
            (ok if discord.ping(alert, "security", host) else warn)("security endpoint")
        if cfg.get("backup_webhook"):
            (ok if discord.ping(cfg["backup_webhook"], "backup", host) else warn)(
                "backup endpoint")

    rule("2 / 5   Database backup")
    cfg["db_name"] = core.prompt("Database name to dump", cfg.get("db_name", "panel"))
    cfg["backup_at"] = core.prompt("Run every day at (HH:MM)", cfg.get("backup_at", "02:00"))
    cfg["backup_retention"] = int(core.prompt(
        "Days to keep on disk", str(cfg.get("backup_retention", 7))))
    cfg["backup_dir"] = core.prompt("Backup directory", cfg.get("backup_dir"))
    db_user = core.prompt("MySQL user", cfg.get("db_user", "root"))
    cfg["db_user"] = db_user
    cfg["db_pass"] = core.prompt("MySQL password (blank = socket auth)",
                                 "", secret=True)
    step("verifying database access ...")
    probe = core.run([("mariadb-dump" if core.have("mariadb-dump") else "mysqldump"),
                      f"--user={cfg['db_user']}", "--no-data", "--databases",
                      cfg["db_name"]], timeout=60) if core.have("mysqldump") or core.have("mariadb-dump") else None
    if probe is None:
        warn("mysqldump not found - backup will fail until it is installed")
    elif probe.returncode != 0:
        warn(f"dump probe failed: {probe.stderr.strip()[:180]}")
    else:
        ok(f"database '{cfg['db_name']}' is reachable")

    rule("3 / 5   Protection profile")
    cfg["profile"] = core.choose(
        "Anti-DDoS intensity (per-source budgets)",
        ["lite       - 40 conn/s, 40 concurrent (game heavy)",
         "standard   - 80 conn/s, 60 concurrent (recommended)",
         "aggressive - 150 conn/s, 40 concurrent (attack mode)"],
        cfg.get("profile", "standard"))
    cfg["log_drops"] = 1 if core.confirm(
        "Log dropped packets for fail2ban auto-bans?", True) else 0
    cfg["nginx_enabled"] = 1 if core.confirm(
        "Enable nginx request throttling (limit_req / limit_conn)?", True) else 0

    rule("4 / 5   Host firewall (ufw)")
    print("UFW will allow: ssh, 80/tcp, 443/tcp, dashboard tcp+udp, "
          "and your game port range before it is switched on.\n")
    cfg["dash_port"] = int(core.prompt("Dashboard port", str(cfg.get("dash_port", 7890))))
    extra = core.prompt("Extra TCP ports (comma separated)",
                        cfg.get("allowed_ports", "22,80,443"))
    cfg["allowed_ports"] = extra
    extra_udp = core.prompt("Extra UDP ports (comma separated)",
                            cfg.get("allowed_ports_udp", str(cfg.get("dash_port"))))
    cfg["allowed_ports_udp"] = extra_udp
    cfg["allowed_port_ranges"] = core.prompt(
        "Game port range (tcp+udp)", cfg.get("allowed_port_ranges", "2000-2050"))
    do_fw = core.confirm("Install and enable ufw with these rules?", True)

    rule("5 / 5   Dashboard access")
    if not cfg.get("dash_token") or not core.confirm(
            "Keep the existing access token?", True):
        cfg["dash_token"] = "vs_" + secrets.token_urlsafe(24)

    # ---------------------------------------------------------- provision
    rule("Provisioning")
    core.save_config(cfg)
    dest = install_files()
    cfg = core.load_config()

    step("applying sysctl hardening ...")
    ddos.apply_sysctl(cfg)

    step("provisioning fail2ban ...")
    ddos.install_discord_action()
    if int(cfg.get("f2b_enabled", 1)):
        ddos.fail2ban_install(cfg)
    else:
        warn("fail2ban jails disabled")

    step("provisioning nginx throttle ...")
    if int(cfg.get("nginx_enabled", 1)):
        ddos.nginx_install(cfg)

    if do_fw:
        step("configuring host firewall ...")
        ufw.configure(cfg, enable=True)
    else:
        warn("ufw provisioning skipped by choice")

    step("applying anti-DDoS chain ...")
    ddos.apply(cfg)

    step("creating backup directory ...")
    bdir = Path(cfg["backup_dir"])
    bdir.mkdir(parents=True, exist_ok=True)
    os.chmod(bdir, 0o700)
    ok(f"backup directory ready -> {bdir}")

    install_units(dest)
    step("enabling services ...")
    enable_units()

    step("running self diagnosis ...")
    from vexashield import cli
    cli.main(["doctor"])

    # ------------------------------------------------------------- summary
    rule("Installation complete")
    host = os.uname().nodename
    port = cfg["dash_port"]
    print(f"""
  dashboard    http://{host}:{port}
  token        {cfg['dash_token']}
  config       {core.CONFIG_FILE}
  backups      {cfg['backup_dir']}
               daily {cfg['backup_at']}, keep {cfg['backup_retention']}d
  profile      {cfg['profile']}
  security     {'configured' if cfg['alert_webhook'] else 'not configured'}
  backup hook  {'configured' if cfg['backup_webhook'] else 'not configured'}

  commands
    vexashield status              health summary
    vexashield ddos status         chain counters
    vexashield backup run          manual backup now
    vexashield ban add <jail> <ip> manual ban
    vexashield doctor              full diagnosis

  store the token somewhere safe - it is not recoverable from the UI.
""")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
