"""Anti-DDoS engine: iptables scrubbing chains, sysctl hardening,
nginx request throttling and the fail2ban jails that act on it."""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path

from . import core

PROFILES = ("lite", "standard", "aggressive")

_LIMITS = {
    #          rate/s burst conn  udp/s icmp/s
    "lite":       (40,   60,  40,  150,  5),
    "standard":   (80,  120,  60,  250,  3),
    "aggressive": (150, 200,  40,  400,  2),
}

SYSCTL_FILE = Path("/etc/sysctl.d/99-vexashield.conf")

SYSCTL = """# VexaShield - network stack hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_invalid_ratelimit = 500
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 8192
net.netfilter.nf_conntrack_max = 524288
"""


# ------------------------------------------------------------------ helpers
def _ipt(*args: str, v6: bool = False) -> "subprocess.CompletedProcess[str]":
    binary = "ip6tables" if v6 else "iptables"
    return core.run([binary, "-w", "5", *args])


def _jump_exists(chain: str, target: str, v6: bool = False) -> bool:
    return _ipt("-C", "INPUT", "-j", target, v6=v6).returncode == 0


def _delete_jump(target: str, v6: bool = False) -> None:
    while _jump_exists("INPUT", target, v6=v6):
        _ipt("-D", "INPUT", "-j", target, v6=v6)


def limits(profile: str) -> tuple[int, int, int, int, int]:
    return _LIMITS.get(profile, _LIMITS["standard"])


def apply_sysctl(cfg: dict) -> None:
    core.need_root()
    SYSCTL_FILE.write_text(SYSCTL, encoding="utf-8")
    res = core.run(["sysctl", "-p", str(SYSCTL_FILE)])
    if res.returncode != 0:
        core.log("warn", f"sysctl partial: {res.stderr.strip()[:160]}")
    core.log("ok", f"sysctl hardening active -> {SYSCTL_FILE}")


# ------------------------------------------------------------- iptables
def apply(cfg: dict, *, quiet: bool = False) -> None:
    core.need_root()
    profile = cfg.get("profile", "standard")
    rate, burst, conn, udp, icmp = limits(profile)
    log_drops = int(cfg.get("log_drops", 1))
    say = (lambda *_: None) if quiet else lambda m: core.log("ok", m)

    _delete_jump("VS-DDOS")
    _delete_jump("VS-DDOS6", v6=True)

    for chain in ("VS-DDOS", "VS-SCAN", "VS-FLOOD"):
        _ipt("-N", chain)
        _ipt("-F", chain)

    # logging stubs - each keeps its own token bucket
    if log_drops:
        _ipt("-A", "VS-SCAN", "-m", "limit", "--limit", "60/min",
             "--limit-burst", "120", "-j", "LOG", "--log-prefix",
             "VS-SCAN: ", "--log-level", "4")
        _ipt("-A", "VS-FLOOD", "-m", "limit", "--limit", "60/min",
             "--limit-burst", "120", "-j", "LOG", "--log-prefix",
             "VS-FLOOD: ", "--log-level", "4")
    _ipt("-A", "VS-SCAN", "-j", "DROP")
    _ipt("-A", "VS-FLOOD", "-j", "DROP")

    scan, flood = "VS-SCAN", "VS-FLOOD"
    a = ["-A", "VS-DDOS"]

    # fast path
    _ipt(*a, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN")
    _ipt(*a, "-i", "lo", "-j", "RETURN")

    # malformed / spoofed sources
    _ipt(*a, "-f", "-j", flood)
    _ipt(*a, "-m", "conntrack", "--ctstate", "INVALID", "-j", flood)
    _ipt(*a, "-s", "0.0.0.0/8", "-j", scan)
    _ipt(*a, "-s", "127.0.0.0/8", "-j", scan)
    _ipt(*a, "-s", "255.255.255.255/32", "-j", scan)

    # illegal TCP flag combinations (NULL / XMAS / SYN+FIN / SYN+RST)
    for flags in ("ALL NONE", "ALL ALL", "ALL FIN,URG,PSH",
                  "SYN,FIN SYN,FIN", "SYN,RST SYN,RST", "ACK,FIN FIN"):
        mask, comp = flags.split()
        _ipt(*a, "-p", "tcp", "--tcp-flags", mask, comp, "-j", scan)

    # connection floods
    _ipt(*a, "-p", "tcp", "-m", "conntrack", "--ctstate", "NEW",
         "-m", "hashlimit", "--hashlimit-above", f"{rate}/sec",
         "--hashlimit-burst", str(burst), "--hashlimit-mode", "srcip",
         "--hashlimit-name", "vs_syn", "--hashlimit-htable-expire", "60000",
         "-j", flood)
    _ipt(*a, "-p", "tcp", "-m", "conntrack", "--ctstate", "NEW",
         "-m", "connlimit", "--connlimit-above", str(conn),
         "--connlimit-mask", "32", "-j", flood)

    # ssh sanity clamp
    _ipt(*a, "-p", "tcp", "--dport", "22", "-m", "conntrack",
         "--ctstate", "NEW", "-m", "connlimit", "--connlimit-above", "8",
         "--connlimit-mask", "32", "-j", flood)

    # udp flood guard (host-side; container traffic traverses FORWARD)
    _ipt(*a, "-p", "udp", "-m", "hashlimit", "--hashlimit-above", f"{udp}/sec",
         "--hashlimit-burst", str(udp * 2), "--hashlimit-mode", "srcip",
         "--hashlimit-name", "vs_udp", "--hashlimit-htable-expire", "10000",
         "-j", flood)

    # icmp budget
    _ipt(*a, "-p", "icmp", "--icmp-type", "echo-request", "-m", "limit",
         "--limit", f"{icmp}/sec", "--limit-burst", str(icmp * 2), "-j", "RETURN")
    _ipt(*a, "-p", "icmp", "-j", flood)

    _ipt(*a, "-j", "RETURN")
    _ipt("-I", "INPUT", "1", "-j", "VS-DDOS")

    # ---- ipv6 mirror ----
    _ipt("-N", "VS-DDOS6", v6=True)
    _ipt("-F", "VS-DDOS6", v6=True)
    b = ["-A", "VS-DDOS6"]
    _ipt(*b, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
         "-j", "RETURN", v6=True)
    _ipt(*b, "-i", "lo", "-j", "RETURN", v6=True)
    _ipt(*b, "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP", v6=True)
    _ipt(*b, "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP", v6=True)
    _ipt(*b, "-p", "tcp", "--tcp-flags", "ALL", "ALL", "-j", "DROP", v6=True)
    _ipt(*b, "-p", "tcp", "-m", "conntrack", "--ctstate", "NEW",
         "-m", "hashlimit", "--hashlimit-above", f"{rate}/sec",
         "--hashlimit-burst", str(burst), "--hashlimit-mode", "srcip",
         "--hashlimit-name", "vs6_syn", "--hashlimit-htable-expire", "60000",
         "-j", "DROP", v6=True)
    _ipt(*b, "-p", "ipv6-icmp", "-m", "limit", "--limit", f"{icmp}/sec",
         "-j", "RETURN", v6=True)
    _ipt(*b, "-p", "ipv6-icmp", "-j", "DROP", v6=True)
    _ipt(*b, "-j", "RETURN", v6=True)
    _ipt("-I", "INPUT", "1", "-j", "VS-DDOS6", v6=True)

    core.write_json(core.STATE / "ddos.json", {
        "profile": profile,
        "applied": core.utc_iso(),
        "rate": f"{rate}/s", "burst": burst, "conn": conn,
        "udp": f"{udp}/s", "icmp": f"{icmp}/s", "log_drops": log_drops,
        "chain_packets": 0, "chain_bytes": 0,
    })

    save_rules()
    say(f"protection active - profile={profile} "
        f"({rate} conn/s, {conn} concurrent/IP, {udp} udp/s, {icmp} icmp/s)")


def save_rules() -> None:
    out_dir = core.STATE / "rules"
    out_dir.mkdir(parents=True, exist_ok=True)
    for binary, name in (("iptables-save", "v4.rules"),
                         ("ip6tables-save", "v6.rules")):
        res = core.run([binary])
        if res.returncode == 0 and res.stdout.strip():
            (out_dir / name).write_text(res.stdout, encoding="utf-8")


def reset() -> None:
    core.need_root()
    for target in ("VS-DDOS", "VS-DDOS6"):
        _delete_jump(target, v6=target.endswith("6"))
    for chain in ("VS-DDOS", "VS-SCAN", "VS-FLOOD"):
        if _ipt("-L", chain).returncode == 0:
            _ipt("-F", chain)
            _ipt("-X", chain)
    core.log("ok", "VexaShield chains removed (other rules untouched)")


def counters() -> dict:
    out = {"loaded": False, "profile": "", "applied": "",
           "packets": 0, "bytes": 0, "rules": 0, "dropped": 0}
    res = core.run(["iptables", "-L", "VS-DDOS", "-v", "-n", "-x"])
    if res.returncode == 0:
        lines = [l for l in res.stdout.splitlines() if l.strip()]
        out["loaded"] = True
        out["rules"] = max(0, len(lines) - 1)
        m = re.match(r"\s*(\d+)\s+(\d+)\s+", lines[0]) if lines else None
        if m:
            out["packets"], out["bytes"] = int(m.group(1)), int(m.group(2))
        for chain in ("VS-SCAN", "VS-FLOOD"):
            r = core.run(["iptables", "-L", chain, "-v", "-n", "-x"])
            if r.returncode == 0:
                first = [l for l in r.stdout.splitlines() if l.strip()][:1]
                m2 = re.match(r"\s*(\d+)\s+", first[0]) if first else None
                if m2:
                    out["dropped"] += int(m2.group(1))
    meta = core.read_json(core.STATE / "ddos.json", {}) or {}
    out["profile"] = meta.get("profile", "")
    out["applied"] = meta.get("applied", "")
    return out


def health(cfg: dict) -> dict:
    c = counters()
    c["sysctl"] = SYSCTL_FILE.exists()
    c["nginx"] = bool(cfg.get("nginx_enabled")) and Path(
        "/etc/nginx/conf.d/00-vexashield.conf").exists()
    c["fail2ban"] = bool(cfg.get("f2b_enabled"))
    c["ufw"] = core.run(["ufw", "status"]).returncode == 0 and shutil.which("ufw")
    c["uptime_days"] = _uptime()
    return c


def _uptime() -> float:
    try:
        return float(Path("/proc/uptime").read_text().split()[0]) / 86400
    except Exception:  # noqa: BLE001
        return 0.0


# ------------------------------------------------------------------- nginx
NGINX_HTTP = """# VexaShield - installed by the installer (http context)
# Whitelisted addresses bypass the request limiter entirely.

map $binary_remote_addr $vs_limit_key {{
    default  $binary_remote_addr;
{whitelist}
}}

limit_req_zone  $vs_limit_key zone=vs_req:10m  rate={rate};
limit_conn_zone $vs_limit_key zone=vs_conn:10m;
"""

NGINX_SERVER = """# VexaShield - include inside every terminating server {{ }} block
    limit_req  zone=vs_req burst={burst} nodelay;
    limit_req_status 429;
    limit_conn vs_conn {conn};
    limit_conn_status 429;
    client_body_timeout   15s;
    client_header_timeout 15s;
    keepalive_timeout     30s;
    send_timeout          20s;
    client_max_body_size  64m;
"""


def nginx_render(cfg: dict) -> tuple[Path, Path]:
    wl = ""
    for cidr in str(cfg.get("nginx_whitelist", "")).split():
        cidr = cidr.strip()
        if cidr:
            wl += f"    {cidr}  \"\";\n"
    http = Path("/etc/nginx/conf.d/00-vexashield.conf")
    snippet = Path("/etc/nginx/snippets/vexashield-server.conf")
    if http.parent.is_dir():
        http.write_text(NGINX_HTTP.format(whitelist=wl.rstrip("\n"),
                                          rate=cfg.get("nginx_rate", "10r/s")),
                        encoding="utf-8")
    if snippet.parent.is_dir() or snippet.parent.mkdir(parents=True, exist_ok=True):
        snippet.write_text(
            NGINX_SERVER.format(burst=cfg.get("nginx_burst", 30),
                                conn=cfg.get("nginx_conn", 25)),
            encoding="utf-8")
    return http, snippet


def nginx_install(cfg: dict) -> bool:
    """Transactional: every file we touch is restored if `nginx -t` fails."""
    if not int(cfg.get("nginx_enabled", 1)) or not core.have("nginx"):
        core.log("info", "nginx throttling skipped")
        return False
    http, snippet = nginx_render(cfg)
    if not http.parent.is_dir():
        core.log("warn", "nginx not present - skipping http limits")
        return False

    originals: dict[Path, str] = {}
    wired = _wire_server_blocks(snippet, originals=originals)
    test = core.run(["nginx", "-t"])
    if test.returncode != 0:
        core.log("err", f"nginx -t failed: {test.stderr.strip()[:200]}")
        _rollback(http, snippet, originals)
        core.run(["nginx", "-t"])
        return False

    core.run(["systemctl", "reload", "nginx"])
    core.log("ok", f"http throttle active ({cfg.get('nginx_rate')}, "
                   f"burst {cfg.get('nginx_burst')}, {wired} server block(s))")
    return True


def _rollback(http: Path, snippet: Path,
              originals: dict[Path, str]) -> None:
    """Undo everything nginx_install changed."""
    for path, text in originals.items():
        try:
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            core.log("err", f"could not restore {path}: {exc}")
    http.unlink(missing_ok=True)
    snippet.unlink(missing_ok=True)
    core.log("warn", "nginx changes rolled back - live config left untouched")


def _wire_server_blocks(snippet: Path,
                        originals: dict[Path, str] | None = None,
                        sites: tuple[Path, ...] | None = None) -> int:
    """Insert the VexaShield include right after every `server {` line.

    `originals` receives the pre-edit contents of every file we rewrite so a
    failed validation can be rolled back byte-for-byte.
    """
    originals = originals if originals is not None else {}
    marker = f"    include {snippet};"
    bases = sites if sites is not None else (
        Path("/etc/nginx/sites-enabled"), Path("/etc/nginx/sites-available"))
    wired = 0
    seen: set[Path] = set()
    for base in bases:
        if not base.is_dir():
            continue
        for conf in sorted(base.iterdir()):
            real = conf.resolve() if conf.is_symlink() else conf
            if real in seen or conf.is_symlink() or not conf.is_file():
                continue
            seen.add(real)
            try:
                text = conf.read_text(encoding="utf-8")
            except OSError:
                continue
            if "server {" not in text or "vexashield-server.conf" in text:
                continue
            out, changed = [], False
            for line in text.splitlines():
                out.append(line)
                if re.match(r"^\s*server\s*\{\s*$", line):
                    out.append(marker)
                    changed = True
            if changed:
                originals[conf] = text
                conf.write_text("\n".join(out) + "\n", encoding="utf-8")
                wired += 1
    return wired


def nginx_uninstall() -> None:
    Path("/etc/nginx/conf.d/00-vexashield.conf").unlink(missing_ok=True)
    snippet = Path("/etc/nginx/snippets/vexashield-server.conf")
    snippet.unlink(missing_ok=True)
    if core.have("nginx"):
        core.run(["nginx", "-t"])
        core.run(["systemctl", "reload", "nginx"])


# ---------------------------------------------------------------- fail2ban
def fail2ban_install(cfg: dict) -> bool:
    if not int(cfg.get("f2b_enabled", 1)) or not core.have("fail2ban-client"):
        core.log("info", "fail2ban jails skipped")
        return False
    src = Path(__file__).resolve().parent.parent / "config" / "fail2ban"
    dst_filters = Path("/etc/fail2ban/filter.d")
    dst_jails = Path("/etc/fail2ban/jail.d")
    if not src.is_dir() or not dst_jails.is_dir():
        core.log("warn", "fail2ban layout not found")
        return False

    for f in src.glob("vs-*.conf"):
        shutil.copy2(f, dst_filters / f.name)

    # discover where nginx writes the messages we match on
    error_log = _nginx_error_log()
    jails = _render_jails(cfg, error_log)
    (dst_jails / "vexashield.conf").write_text(jails, encoding="utf-8")

    res = core.run(["fail2ban-client", "reload"])
    if res.returncode != 0:
        core.log("warn", f"fail2ban reload: {res.stderr.strip()[:200]}")
        res = core.run(["fail2ban-client", "reload", "vexashield"])
    active = core.run(["fail2ban-client", "status"])
    core.log("ok", "fail2ban jails installed: "
                   + ", ".join(_jail_names(active.stdout)))
    return True


def _jail_names(out: str) -> list[str]:
    for line in out.splitlines():
        if "Jail list" in line:
            return [x.strip() for x in line.split(":", 1)[-1].split(",") if x.strip()]
    return []


def _nginx_error_log() -> str:
    for candidate in ("/etc/nginx/sites-enabled/", "/etc/nginx/sites-available/"):
        base = Path(candidate)
        if not base.is_dir():
            continue
        for f in base.iterdir():
            try:
                text = f.read_text(encoding="utf-8")
            except OSError:
                continue
            m = re.search(r"^\s*error_log\s+([^;]+);", text, re.M)
            if m:
                return m.group(1).split()[0]
    return "/var/log/nginx/error.log"


def _render_jails(cfg: dict, error_log: str) -> str:
    return f"""# VexaShield - generated by the installer. Do not edit by hand.
# HTTP flood -> nginx limit_req/limit_conn hits
[vs-http-limit]
enabled  = true
filter   = vs-http-limit
logpath  = {error_log}
backend  = auto
maxretry = {cfg.get('f2b_http_retry', 12)}
findtime = {cfg.get('f2b_http_find', 60)}
bantime  = {cfg.get('f2b_http_ban', 600)}
action   = iptables-multiport[name=vs-http-limit, port="http,https"]
           discord-webhook[name=vs-http-limit]

# Illegal TCP flag combinations logged by the VS-SCAN chain
[vs-portscan]
enabled  = true
filter   = vs-portscan
backend  = systemd
maxretry = {cfg.get('f2b_scan_retry', 5)}
findtime = {cfg.get('f2b_scan_find', 600)}
bantime  = {cfg.get('f2b_scan_ban', 86400)}
action   = iptables-allports[name=vs-portscan]
           discord-webhook[name=vs-portscan]

# Rate-based drops logged by the VS-FLOOD chain
[vs-flood]
enabled  = {1 if int(cfg.get('f2b_flood_enabled', 1)) else 0}
filter   = vs-flood
backend  = systemd
maxretry = {cfg.get('f2b_flood_retry', 15)}
findtime = {cfg.get('f2b_flood_find', 60)}
bantime  = {cfg.get('f2b_flood_ban', 1800)}
action   = iptables-multiport[name=vs-flood, port="http,https,2000:2050"]
           discord-webhook[name=vs-flood]
"""


def fail2ban_uninstall() -> None:
    Path("/etc/fail2ban/jail.d/vexashield.conf").unlink(missing_ok=True)
    for f in Path("/etc/fail2ban/filter.d").glob("vs-*.conf"):
        f.unlink(missing_ok=True)
    if core.have("fail2ban-client"):
        core.run(["fail2ban-client", "reload"])


def install_discord_action() -> None:
    """Register the discord-webhook ban action used by every jail."""
    src = Path(__file__).resolve().parent.parent / "config" / "fail2ban" / "discord-webhook.conf"
    dst = Path("/etc/fail2ban/action.d/discord-webhook.conf")
    if src.is_file() and dst.parent.is_dir():
        shutil.copy2(src, dst)


# ------------------------------------------------------------------ monitor
def watch(cfg: dict, interval: float = 10.0) -> None:
    """Long-running sampler. Raises a Discord alert when packets/sec spikes."""
    core.init_logging("monitor")
    url = cfg.get("alert_webhook", "")
    from . import discord
    last = 0
    prev_packets = 0
    cooldown_until = 0.0
    peak = int(cfg.get("attack_pps_alert", 500))
    core.log("info", f"attack monitor started (interval={interval}s, "
                     f"threshold={peak} pkt/s)")
    while True:
        time.sleep(interval)
        c = counters()
        now = time.time()
        if not c["loaded"]:
            continue
        delta = c["packets"] - prev_packets
        prev_packets = c["packets"]
        pps = int(delta / interval) if last else 0
        last = now
        if pps >= peak and now > cooldown_until and url:
            cooldown_until = now + 300
            discord.send_alert(
                url,
                "Elevated ingress traffic",
                f"Scrubbing chain is processing **{pps} pkt/s** "
                f"(threshold {peak}).",
                color=discord.AMBER,
                fields=[("Rate", f"`{pps} pkt/s`", True),
                        ("Profile", f"`{c['profile']}`", True),
                        ("Blocked", f"`{c['dropped']}`", True)],
                mention=cfg.get("mention_id", ""),
            )
