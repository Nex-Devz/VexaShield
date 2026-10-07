#!/usr/bin/env python3
"""VexaShield uninstaller.

    sudo python3 uninstall.py [--keep-data]
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from vexashield import core, ddos  # noqa: E402


def main() -> int:
    if os.geteuid() != 0:
        print("Run as root:  sudo python3 uninstall.py", file=sys.stderr)
        return 1

    keep_data = "--keep-data" in sys.argv
    core.ensure_dirs()
    print(f"\n{core.PRODUCT} {core.VERSION} - uninstall\n" + "─" * 60)

    units = ["vexashield-monitor", "vexashield-dashboard",
             "vexashield-backup.timer", "vexashield-backup.service",
             "vexashield-firewall"]
    for u in units:
        core.run(["systemctl", "disable", "--now", u])
        core.log("ok", f"stopped {u}")

    core.log("step", "removing scrubbing chains ...")
    try:
        ddos.reset()
    except SystemExit:
        pass

    ddos.fail2ban_uninstall()
    core.log("ok", "fail2ban jails removed")
    ddos.nginx_uninstall()
    core.log("ok", "nginx throttle removed")

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

    if not keep_data:
        if core.confirm("Also delete config, logs, state and backups?", False):
            for p in (core.ETC, core.LOGDIR, core.STATE,
                      Path(core.load_config().get("backup_dir",
                                                  "/var/backups/vexashield"))):
                shutil.rmtree(p, ignore_errors=True)
                core.log("ok", f"removed {p}")
        else:
            core.log("info", "config and backups kept (--keep-data skips this prompt)")

    core.run(["systemctl", "daemon-reload"])
    print("\nUninstalled. UFW rules and fail2ban sshd jail were left untouched.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
