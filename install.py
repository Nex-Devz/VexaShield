#!/usr/bin/env python3
"""VexaShield installer.

    sudo python3 install.py            # interactive
    sudo python3 install.py --yes      # unattended, every default accepted
    curl -fsSL .../install.sh | bash   # dependency bootstrap + this installer

Asks for the Discord webhook endpoints, provisions the anti-DDoS chain, the
host firewall, the nightly backup timer and the control dashboard.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from vexashield import backup, core, ddos, ufw  # noqa: E402
from vexashield import discord  # noqa: E402

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

PAL = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
}


def c(text: str, color: str) -> str:
    if not USE_COLOR:
        return str(text)
    return f"{PAL[color]}{text}{PAL['reset']}"


def rule(title: str = "") -> None:
    print()
    print(c("  " + "─" * 62, "gray"))
    if title:
        print(f"  {c(title, 'bold')}")
        print()


def section(n: int, total: int, title: str) -> None:
    print()
    print(c("  " + "─" * 62, "gray"))
    print(f"  {c(f'{n}/{total}', 'cyan')}  {c(title, 'bold')}")
    print()


def step(msg: str) -> None:
    core.log("step", msg)


def ok(msg: str) -> None:
    core.log("ok", msg)


def warn(msg: str) -> None:
    core.log("warn", msg)


def err(msg: str) -> None:
    core.log("err", msg)


def kv(label: str, value: object, color: str = "") -> None:
    text = c(str(value), color) if color else str(value)
    print(f"    {c(f'{label:<12}', 'gray')}{text}")


def header() -> None:
    print()
    print(f"  {c('VexaShield', 'blue')} {c(core.VERSION, 'gray')}"
          f"  {c('anti-DDoS · discord backups · dashboard', 'gray')}")
    print(c("  " + "─" * 62, "gray"))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="install.py",
        description="Provision VexaShield on this host.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Environment overrides (useful when running unattended):\n"
               "  VS_ALERT_WEBHOOK  VS_BACKUP_WEBHOOK  VS_MENTION_ID\n"
               "  VS_DB_PASS        password used for the dump probe\n",
    )
    p.add_argument("-y", "--yes", action="store_true",
                   help="non-interactive: accept every default")
    p.add_argument("--no-nginx", action="store_true",
                   help="skip nginx request throttling")
    p.add_argument("--no-fail2ban", action="store_true",
                   help="skip fail2ban jails")
    p.add_argument("--no-ufw", action="store_true",
                   help="do not install or enable ufw")
    p.add_argument("--no-dashboard", action="store_true",
                   help="install files but do not enable the dashboard unit")
    p.add_argument("--version", action="version",
                   version=f"vexashield {core.VERSION}")
    return p.parse_args(argv)


def ask_webhook(label: str, default: str = "", env: str = "") -> str:
    if env and os.environ.get(env):
        url = os.environ[env].strip()
        ok(f"{label} webhook from ${env}")
        return url
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
    step("copying application files to " + str(dest) + " ...")
    if dest.exists() and dest.resolve() != HERE.resolve():
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
    for name in ("install.py", "uninstall.py", "install.sh", "uninstall.sh"):
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
    ok(f"application installed  -> {dest}")
    ok(f"command installed      -> {shim}")
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
    ok("systemd units installed  firewall, dashboard, monitor, backup timer")


def enable_units(args: argparse.Namespace) -> None:
    units = ["vexashield-firewall", "vexashield-backup.timer"]
    if not args.no_dashboard:
        units.insert(1, "vexashield-dashboard")
    if core.load_config().get("alert_webhook"):
        units.append("vexashield-monitor")
    if args.no_dashboard:
        warn("dashboard unit left disabled (--no-dashboard)")
    for u in units:
        core.run(["systemctl", "enable", "--now", u])
    if not args.no_dashboard:
        core.run(["systemctl", "restart", "vexashield-dashboard"])
    for u in units:
        state = core.run(["systemctl", "is-active", u]).stdout.strip()
        (ok if state == "active" else warn)(f"{u}: {state}")


def summary(cfg: dict, do_fw: bool) -> None:
    host = os.uname().nodename
    port = cfg["dash_port"]
    rule("Installation complete")
    kv("dashboard", f"http://{host}:{port}", "cyan")
    kv("token", cfg["dash_token"], "yellow")
    kv("config", core.CONFIG_FILE)
    kv("backups", cfg["backup_dir"])
    kv("schedule", f"daily {cfg['backup_at']}, keep {cfg['backup_retention']}d")
    kv("profile", cfg["profile"])
    kv("firewall", "ufw enabled" if do_fw else "ufw skipped")
    kv("security", "configured" if cfg["alert_webhook"] else "not configured",
       "green" if cfg["alert_webhook"] else "yellow")
    kv("backup hook", "configured" if cfg["backup_webhook"] else "not configured",
       "green" if cfg["backup_webhook"] else "yellow")
    print()
    print(f"    {c('commands', 'bold')}")
    print(f"      vexashield status              health summary")
    print(f"      vexashield ddos status         chain counters")
    print(f"      vexashield backup run          manual backup now")
    print(f"      vexashield ban add <jail> <ip> manual ban")
    print(f"      vexashield doctor              full diagnosis")
    print()
    print(c("    store the token somewhere safe - it is not recoverable "
            "from the UI.", "gray"))
    print(c("  " + "─" * 62, "gray"))
    print()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if os.geteuid() != 0:
        print(c("run as root:  sudo python3 install.py", "red"), file=sys.stderr)
        return 1
    if sys.version_info < (3, 10):
        print(c("Python 3.10+ required, found %s"
                % ".".join(map(str, sys.version_info[:3])), "red"),
              file=sys.stderr)
        return 1

    core.set_non_interactive(args.yes or not sys.stdin.isatty())
    header()

    core.ensure_dirs()
    core.init_logging("install")
    cfg = core.config_defaults()
    if core.CONFIG_FILE.exists():
        cfg = core.load_config()
        warn(f"existing config found at {core.CONFIG_FILE} - answers pre-filled")

    # ----------------------------------------------------- 1. discord -----
    section(1, 5, "Discord endpoints")
    print("    Two webhooks are used:")
    print(f"      {c('security', 'cyan')}  attacks, bans, manual blocks")
    print(f"      {c('backup', 'cyan')}   nightly dump result (falls back to security)")
    print()
    alert = ask_webhook("security / DDoS alert", cfg.get("alert_webhook", ""),
                        env="VS_ALERT_WEBHOOK")
    cfg["alert_webhook"] = alert
    if os.environ.get("VS_BACKUP_WEBHOOK"):
        cfg["backup_webhook"] = os.environ["VS_BACKUP_WEBHOOK"].strip()
    elif alert and core.confirm("Use the same webhook for backup results?", True):
        cfg["backup_webhook"] = alert
    else:
        cfg["backup_webhook"] = ask_webhook("backup result",
                                            cfg.get("backup_webhook", ""))
    mention = os.environ.get("VS_MENTION_ID") or core.prompt(
        "Discord user ID to ping on events (optional)", cfg.get("mention_id", ""))
    cfg["mention_id"] = mention.strip()

    if alert or cfg.get("backup_webhook"):
        step("testing webhooks ...")
        host = os.uname().nodename
        if alert:
            (ok if discord.ping(alert, "security", host) else warn)(
                "security endpoint")
        if cfg.get("backup_webhook"):
            (ok if discord.ping(cfg["backup_webhook"], "backup", host) else warn)(
                "backup endpoint")

    # ----------------------------------------------------- 2. database ----
    section(2, 5, "Database backup")
    cfg["db_name"] = core.prompt("Database name to dump", cfg.get("db_name", "panel"))
    cfg["backup_at"] = core.prompt("Run every day at (HH:MM)",
                                   cfg.get("backup_at", "02:00"))
    cfg["backup_retention"] = int(core.prompt(
        "Days to keep on disk", str(cfg.get("backup_retention", 7))))
    cfg["backup_dir"] = core.prompt("Backup directory", cfg.get("backup_dir"))
    cfg["db_user"] = core.prompt("MySQL user", cfg.get("db_user", "root"))
    cfg["db_pass"] = os.environ.get("VS_DB_PASS") or core.prompt(
        "MySQL password (blank = socket auth)", "", secret=True)

    step("verifying database access ...")
    dump_tool = "mariadb-dump" if core.have("mariadb-dump") else "mysqldump"
    if not core.have(dump_tool):
        warn(f"{dump_tool} not found - install mariadb-client/mysql-client")
    else:
        probe = core.run([dump_tool, f"--user={cfg['db_user']}", "--no-data",
                          "--databases", cfg["db_name"]], timeout=60)
        if probe.returncode != 0:
            warn(f"dump probe failed: {probe.stderr.strip()[:180]}")
        else:
            ok(f"database '{cfg['db_name']}' is reachable")

    # ----------------------------------------------------- 3. profile -----
    section(3, 5, "Protection profile")
    cfg["profile"] = core.choose(
        "Anti-DDoS intensity (per-source budgets)",
        ["lite        40 conn/s,  40 concurrent  (game heavy)",
         "standard    80 conn/s,  60 concurrent  (recommended)",
         "aggressive 150 conn/s,  40 concurrent  (attack mode)"],
        cfg.get("profile", "standard"))
    cfg["log_drops"] = 1 if core.confirm(
        "Log dropped packets for fail2ban auto-bans?", True) else 0
    nginx_default = bool(int(cfg.get("nginx_enabled", 1))) and not args.no_nginx
    cfg["nginx_enabled"] = 1 if core.confirm(
        "Enable nginx request throttling (limit_req / limit_conn)?",
        nginx_default) else 0
    if args.no_nginx:
        cfg["nginx_enabled"] = 0

    # ----------------------------------------------------- 4. firewall ----
    section(4, 5, "Host firewall (ufw)")
    print("    Allowed before ufw is switched on:")
    print("      ssh, 80/tcp, 443/tcp, dashboard tcp+udp, game port range\n")
    cfg["dash_port"] = int(core.prompt(
        "Dashboard port", str(cfg.get("dash_port", 7890))))
    cfg["allowed_ports"] = core.prompt(
        "Extra TCP ports (comma separated)", cfg.get("allowed_ports", "22,80,443"))
    cfg["allowed_ports_udp"] = core.prompt(
        "Extra UDP ports (comma separated)",
        str(cfg.get("allowed_ports_udp", cfg["dash_port"])))
    cfg["allowed_port_ranges"] = core.prompt(
        "Game port range (tcp+udp)", cfg.get("allowed_port_ranges", "2000-2050"))
    do_fw = core.confirm("Install and enable ufw with these rules?",
                         not args.no_ufw) and not args.no_ufw

    # ----------------------------------------------------- 5. access ------
    section(5, 5, "Dashboard access")
    if not cfg.get("dash_token") or not core.confirm(
            "Keep the existing access token?", True):
        cfg["dash_token"] = "vs_" + secrets.token_urlsafe(24)

    if args.no_fail2ban:
        cfg["f2b_enabled"] = 0

    # -------------------------------------------------------- provision ---
    rule("Provisioning")
    core.save_config(cfg)
    dest = install_files()
    cfg = core.load_config()

    step("applying sysctl hardening ...")
    ddos.apply_sysctl(cfg)

    if int(cfg.get("f2b_enabled", 1)):
        step("provisioning fail2ban ...")
        ddos.install_discord_action()
        ddos.fail2ban_install(cfg)
    else:
        warn("fail2ban jails disabled")

    if int(cfg.get("nginx_enabled", 1)):
        step("provisioning nginx throttle ...")
        ddos.nginx_install(cfg)
    else:
        warn("nginx throttling disabled")

    if do_fw:
        step("configuring host firewall ...")
        ufw.configure(cfg, enable=True)
    else:
        warn("ufw provisioning skipped")

    step("applying anti-DDoS chain ...")
    ddos.apply(cfg)

    step("creating backup directory ...")
    bdir = Path(cfg["backup_dir"])
    bdir.mkdir(parents=True, exist_ok=True)
    os.chmod(bdir, 0o700)
    ok(f"backup directory ready -> {bdir}")

    install_units(dest)
    step("enabling services ...")
    enable_units(args)

    step("running self diagnosis ...")
    from vexashield import cli
    cli.main(["doctor"])

    summary(cfg, do_fw)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
