"""Host firewall provisioning with UFW.

Install order matters: UFW is enabled first (with the service ports allowed),
then the VexaShield scrubbing chain is inserted at the head of INPUT so it
runs before UFW's own policy verdicts.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import core

DASHBOARD_DEFAULT = 7890


def installed() -> bool:
    return core.have("ufw")


def ensure_installed() -> bool:
    if installed():
        return True
    core.log("step", "installing ufw ...")
    for cmd in (["apt-get", "update", "-qq"], ["apt-get", "install", "-y", "-qq", "ufw"]):
        res = core.run(cmd, timeout=600)
        if res.returncode != 0:
            core.log("warn", f"{cmd[-1]}: {res.stderr.strip()[:160]}")
    return installed()


def status() -> dict:
    res = core.run(["ufw", "status", "verbose"])
    active = res.returncode == 0 and "Status: active" in res.stdout
    rules = []
    for line in res.stdout.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+)\.\s+(ALLOW|DENY|REJECT)\s+(IN|OUT)\s+(\S+)\s*(.*)$",
                     line)
        if m:
            rules.append({"n": int(m.group(1)), "action": m.group(2),
                          "direction": m.group(3), "proto": m.group(4),
                          "extra": m.group(5).strip()})
    return {"active": active, "raw": res.stdout, "rules": rules,
            "default_in": _default("incoming"), "default_out": _default("outgoing")}


def _default(direction: str) -> str:
    p = Path("/etc/ufw/ufw.conf")
    if not p.exists():
        return "?"
    m = re.search(rf"DEFAULT_{direction.upper()}_POLICY=(\w+)",
                  p.read_text(encoding="utf-8"))
    return m.group(1) if m else "?"


def spec(port: str, proto: str = "tcp") -> str:
    """Render a ufw rule argument: 22/tcp, 7890/udp, 2000:2050/tcp.

    ufw wants the port first and uses a colon for ranges - tcp/22 and
    2000-2050/tcp are both rejected outright.
    """
    text = str(port).strip()
    if "/" in text:
        return text
    text = text.replace("-", ":")
    return f"{text}/{proto}"


def allow(port: str, proto: str = "tcp", comment: str = "") -> bool:
    rule = spec(port, proto)
    args = ["ufw", "allow", rule]
    if comment:
        args += ["comment", comment]
    res = core.run(args)
    if res.returncode != 0:
        core.log("warn", f"ufw allow {rule}: {res.stderr.strip()[:120]}")
        return False
    if "Skipping adding existing rule" in res.stdout:
        return True
    core.log("info", f"ufw allow {rule}")
    return True


def configure(cfg: dict, *, enable: bool = True) -> dict:
    """Build the allow-list and (optionally) switch UFW on.

    Never enables without first permitting SSH - that is the one failure mode
    that locks an operator out of a remote box.
    """
    core.need_root()
    if not ensure_installed():
        core.log("err", "ufw could not be installed")
        return {"ok": False, "allowed": []}

    allowed: list[str] = []
    seen: set[str] = set()

    def add(port: str, proto: str, note: str) -> bool:
        rule = spec(port, proto)
        if rule in seen:
            return True
        seen.add(rule)
        if not allow(port, proto, note):
            return False
        allowed.append(rule)
        return True

    # 1. ssh first, always
    ssh_port = _ssh_port()
    ssh_ok = add(ssh_port, "tcp", "vexashield: ssh")

    # 2. web
    for p in ("80", "443"):
        add(p, "tcp", "vexashield: web")

    # 3. dashboard - tcp + udp as requested
    dash = str(cfg.get("dash_port", DASHBOARD_DEFAULT))
    add(dash, "tcp", "vexashield: dashboard")
    add(dash, "udp", "vexashield: dashboard")

    # 4. explicit extras from config
    for p in str(cfg.get("allowed_ports", "")).split(","):
        p = p.strip()
        if p:
            add(p, "tcp", "vexashield: service")
    for p in str(cfg.get("allowed_ports_udp", "")).split(","):
        p = p.strip()
        if p:
            add(p, "udp", "vexashield: service")

    # 5. game port ranges (tcp + udp)
    for rng in str(cfg.get("allowed_port_ranges", "")).split(","):
        rng = rng.strip()
        if not rng:
            continue
        add(rng, "tcp", "vexashield: games")
        add(rng, "udp", "vexashield: games")

    if not enable:
        core.log("info", "rules staged, ufw left disabled")
        return {"ok": True, "allowed": allowed, "active": False}

    if not ssh_ok:
        core.log("err", f"ssh rule {ssh_port}/tcp rejected - leaving ufw "
                        "disabled so you keep access")
        return {"ok": False, "allowed": allowed, "active": False}

    # refuse new connections while staging, then flip the switch
    core.run(["ufw", "default", "deny", "incoming"])
    core.run(["ufw", "default", "allow", "outgoing"])
    res = core.run(["ufw", "--force", "enable"])
    if res.returncode != 0:
        core.log("err", f"ufw enable failed: {res.stderr.strip()[:200]}")
        return {"ok": False, "allowed": allowed}

    # docker publishes through its own chains; make sure it still bypasses ufw
    _ensure_docker_bypass()
    core.log("ok", f"ufw active - {len(allowed)} rules "
                   f"(dashboard {cfg.get('dash_port')}/tcp+udp, ssh {ssh_port})")
    return {"ok": True, "allowed": allowed, "active": True}


def _ssh_port() -> str:
    for path in ("/etc/ssh/sshd_config", "/etc/ssh/ssh_config.d/20-ipv6only.conf"):
        p = Path(path)
        if not p.exists():
            continue
        m = re.search(r"^\s*Port\s+(\d+)", p.read_text(encoding="utf-8"), re.M)
        if m:
            return m.group(1)
    return "22"


def _ensure_docker_bypass() -> None:
    """ufw must not filter traffic docker already published."""
    rules = Path("/etc/ufw/after.rules")
    if not rules.exists():
        return
    text = rules.read_text(encoding="utf-8")
    if "DOCKER-USER" in text:
        return
    block = """
# VexaShield - let docker published ports bypass ufw
*nat
:DOCKER-USER - [0:0]
-A DOCKER-USER -j RETURN
COMMIT
"""
    rules.write_text(text.rstrip() + "\n" + block, encoding="utf-8")
    core.run(["ufw", "reload"])


def disable() -> None:
    if installed():
        core.run(["ufw", "--force", "disable"])
        core.log("ok", "ufw disabled")


def apply_chain_after(caller) -> None:
    """Helper for callers that need ufw settled before inserting the chain."""
    if installed():
        core.run(["ufw", "status"], timeout=30)
    caller()
