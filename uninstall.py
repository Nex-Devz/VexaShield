#!/usr/bin/env python3
"""VexaShield uninstaller.

    sudo python3 uninstall.py               # interactive
    sudo python3 uninstall.py --purge       # also delete config and backups
    sudo python3 uninstall.py --keep-data   # never touch config or backups

Stops the services, removes the systemd units, the CLI shim, the fail2ban
jails, the nginx snippet and the iptables chains. The host firewall rules are
left enabled so you keep your SSH access.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from vexashield import core, ddos  # noqa: E402

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, color: str) -> str:
    if not USE_COLOR:
        return str(text)
    return f"\033[{color}m{text}\033[0m"


def rule(title: str = "") -> None:
    print(c("  " + "─" * 60, "2"))
    if title:
        print(f"  {c(title, '1')}")
        print()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="uninstall.py",
                                description="Remove VexaShield from this host.")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--purge", action="store_true",
                      help="delete config, logs, state and local backups")
    mode.add_argument("--keep-data", action="store_true",
                      help="never touch config, logs, state or backups")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if os.geteuid() != 0:
        print(c("run as root:  sudo python3 uninstall.py", "31"), file=sys.stderr)
        return 1

    core.ensure_dirs()
    print()
    print(f"  {c('VexaShield', '34')} {c(core.VERSION, '90')}"
          f"  {c('uninstall', '90')}")
    rule()

    # ------------------------------------------------------- services ----
    units = ["vexashield-monitor", "vexashield-dashboard",
             "vexashield-backup.timer", "vexashield-backup.service",
             "vexashield-firewall"]
    for u in units:
        if core.run(["systemctl", "disable", "--now", u]).returncode == 0:
            core.log("ok", f"stopped {u}")

    # -------------------------------------------------------- engine -----
    core.log("step", "removing scrubbing chains ...")
    try:
        ddos.reset()
    except SystemExit:
        pass
    core.log("ok", "VS-DDOS / VS-SCAN / VS-FLOOD removed")

    ddos.fail2ban_uninstall()
    core.log("ok", "fail2ban jails removed")
    ddos.nginx_uninstall()
    core.log("ok", "nginx throttle removed")

    # ---------------------------------------------------------- files ----
    for p in (Path("/etc/fail2ban/action.d/discord-webhook.conf"),
              ddos.SYSCTL_FILE,
              Path("/usr/local/bin/vexashield")):
        try:
            p.unlink()
            core.log("ok", f"removed {p}")
        except OSError:
            pass

    unit_dir = Path("/etc/systemd/system")
    for name in ("vexashield-firewall.service", "vexashield-dashboard.service",
                 "vexashield-monitor.service", "vexashield-backup.service",
                 "vexashield-backup.timer"):
        try:
            (unit_dir / name).unlink()
        except OSError:
            pass
    core.run(["systemctl", "daemon-reload"])
    core.log("ok", "systemd units removed")

    root = Path(os.environ.get("VS_ROOT", "/opt/vexashield"))
    if root.exists() and HERE.resolve() != root.resolve():
        shutil.rmtree(root, ignore_errors=True)
        core.log("ok", f"removed {root}")

    # ---------------------------------------------------------- data -----
    do_purge = args.purge
    if args.keep_data:
        do_purge = False
    elif not args.purge:
        do_purge = core.confirm("Also delete config, logs, state and backups?",
                                False)
    if do_purge:
        backup_dir = Path(core.load_config().get("backup_dir",
                                                 "/var/backups/vexashield"))
        for p in (core.ETC, core.LOGDIR, core.STATE, backup_dir):
            if p.exists():
                shutil.rmtree(p, ignore_errors=True)
                core.log("ok", f"removed {p}")
    else:
        core.log("info", "config, logs and backups kept")

    core.run(["systemctl", "daemon-reload"])
    rule("Uninstalled")
    print("  UFW rules and the fail2ban sshd jail were left untouched,")
    print("  so your SSH and existing services keep working.\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
