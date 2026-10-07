#!/usr/bin/env python3
"""Isolated smoke test for VexaShield.

Everything runs inside a temporary directory with VS_* environment overrides,
so it never touches the host firewall, fail2ban, nginx or systemd.

    python3 tests/smoke.py
    python3 tests/smoke.py --keep      # keep the temporary directory
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from http import cookiejar
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BASE = ""
T = ""
ENV: dict[str, str] = {}
JAR = cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(JAR))
RESULTS: list[tuple[str, bool, str]] = []

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))
    tag = paint("PASS", "32") if ok else paint("FAIL", "31")
    print(f"{tag} {name}" + (f"  {detail}" if detail else ""))


def skip(name: str, why: str) -> None:
    check(name, True, paint("SKIPPED", "90") + " " + why)


def sh(args: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "vexashield", *args],
                          cwd=REPO, env=ENV, capture_output=True, text=True,
                          timeout=timeout)


def api(method: str, path: str, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with OPENER.open(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except Exception as e:                       # connection refused etc.
        return 0, {"error": str(e)}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def python_help(script: str, needle: str) -> bool:
    r = subprocess.run([sys.executable, str(REPO / script), "--help"],
                       capture_output=True, text=True, timeout=60)
    return r.returncode == 0 and needle in r.stdout


def main() -> int:
    global T, ENV, BASE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="keep the temporary directory for inspection")
    args = ap.parse_args()

    T = tempfile.mkdtemp(prefix="vstest-")
    for d in ("etc", "state", "log", "backups"):
        os.makedirs(f"{T}/{d}", exist_ok=True)

    ENV = dict(os.environ)
    ENV.pop("VS_ALERT_WEBHOOK", None)
    ENV.pop("VS_BACKUP_WEBHOOK", None)
    ENV.update(VS_ETC=f"{T}/etc", VS_STATE=f"{T}/state",
               VS_LOGDIR=f"{T}/log", VS_ROOT=str(REPO))

    port = free_port()
    BASE = f"http://127.0.0.1:{port}"

    # ------------------------------------------------------------- CLI ----
    r = sh(["--version"])
    check("cli version", "1.0.0" in r.stdout, r.stdout.strip())

    r = sh(["config", "set", "profile", "standard"])
    check("config set", r.returncode == 0, r.stderr.strip()[:80])

    sh(["config", "set", "backup_dir", f"{T}/backups"])
    sh(["config", "set", "nginx_enabled", "0"])       # never touch live nginx
    sh(["config", "set", "dash_port", str(port)])
    sh(["config", "set", "backup_webhook", ""])
    sh(["config", "set", "alert_webhook", ""])
    r = sh(["config", "show"])
    check("config show", r.returncode == 0 and "profile=standard" in r.stdout)

    conf = f"{T}/etc/vexashield.conf"
    mode = os.stat(conf).st_mode & 0o777
    check("config file mode 0600", mode == 0o600, oct(mode))

    # --------------------------------------------------------- installer --
    r = subprocess.run(["bash", "-n", str(REPO / "install.sh")],
                       capture_output=True, text=True, timeout=60)
    check("install.sh parses", r.returncode == 0, r.stderr.strip()[:80])

    r = subprocess.run(["bash", str(REPO / "install.sh"), "--help"],
                       capture_output=True, text=True, timeout=60)
    check("install.sh --help", r.returncode == 0 and "USAGE" in r.stdout,
          f"rc={r.returncode}")

    if os.geteuid() == 0:
        r = subprocess.run(["bash", str(REPO / "install.sh"), "--dry-run"],
                           capture_output=True, text=True, timeout=120)
        check("install.sh --dry-run",
              r.returncode == 0 and "package manager" in r.stdout,
              [l.strip() for l in r.stdout.splitlines()
               if "package manager" in l][:1])
    else:
        skip("install.sh --dry-run", "needs root")

    r = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(REPO)!r}); import install; "
         "a = install.parse_args(['--yes','--no-nginx','--no-ufw']); "
         "print('ARGS_OK' if (a.yes and a.no_nginx and a.no_ufw) "
         "else 'ARGS_BAD')"],
        capture_output=True, text=True, timeout=60)
    check("install.py flags parse", "ARGS_OK" in r.stdout,
          r.stderr.strip()[:80])

    check("install.py --help", python_help("install.py", "--no-nginx"))
    check("uninstall.py --help", python_help("uninstall.py", "--purge"))

    banner_txt = (REPO / "install.py").read_text(encoding="utf-8")
    block = "".join(chr(x) for x in (0x2588, 0x2554, 0x255A, 0x2551))
    check("no block-art banner", all(ch not in banner_txt for ch in block))

    # ----------------------------------------------------------- backup ---
    r = sh(["backup", "run"], timeout=600)
    tail = (r.stdout + r.stderr).strip().splitlines()
    check("backup run", r.returncode == 0, tail[-1][:90] if tail else "")

    files = sorted(os.listdir(f"{T}/backups"))
    check("archive created", any(f.endswith(".zip") for f in files),
          ",".join(files))

    r = sh(["backup", "verify"])
    check("backup verify", r.returncode == 0 and "ok " in r.stdout,
          r.stdout.strip()[:70])

    r = sh(["backup", "list"])
    check("backup list", r.returncode == 0 and ".zip" in r.stdout)

    hist = json.load(open(f"{T}/state/backups.json"))
    check("history recorded", hist["last"]["ok"] is True,
          f"zip={hist['last']['zip']} {hist['last']['duration']}s")

    # ---------------------------------------------------- ddos (netns) ----
    if not shutil.which("unshare") or not shutil.which("iptables"):
        skip("ddos apply (netns)", "unshare/iptables unavailable")
        skip("ddos status json", "unshare/iptables unavailable")
    else:
        envstr = (f"VS_ETC={T}/etc VS_STATE={T}/state VS_LOGDIR={T}/log "
                  f"VS_ROOT={REPO}")
        ns = subprocess.run(
            ["unshare", "-rn", "bash", "-c",
             f"cd {REPO} && {envstr} {sys.executable} -m vexashield ddos apply"
             f" --profile standard 2>&1; A=$?; "
             f"iptables -S | grep -c '^-A VS-DDOS'; "
             f"iptables -S | grep -c 'INPUT -j VS-DDOS'; "
             f"{envstr} {sys.executable} -m vexashield ddos status "
             f"> {T}/ddos.json 2>&1; "
             f"echo APPLY_RC=$A"],
            capture_output=True, text=True, timeout=120)
        lines = [l for l in ns.stdout.splitlines() if l.strip()]
        check("ddos apply (netns)", "APPLY_RC=0" in ns.stdout and len(lines) >= 4,
              " | ".join(lines[:4])[:130])

        status = {}
        if os.path.exists(f"{T}/ddos.json"):
            status = json.load(open(f"{T}/ddos.json"))
        check("ddos status json", status.get("loaded") is True
              and status.get("profile") == "standard",
              f"rules={status.get('rules')} profile={status.get('profile')}")

    # ------------------------------------------------- nginx rendering ----
    code = (
        "import sys; sys.path.insert(0, r'%s');"
        "from vexashield import ddos;"
        "h = ddos.NGINX_HTTP.format(rate='10r/s', whitelist='10.0.0.0/8  \"\";');"
        "s = ddos.NGINX_SERVER.format(burst=30, conn=25);"
        "ok = ('rate=10r/s' in h) and ('limit_key {' in h) and (h.count('{') == 1);"
        "ok = ok and ('burst=30 nodelay' in s) and ('limit_conn vs_conn 25' in s);"
        "print('NGINX_OK' if ok else 'NGINX_BAD')" % REPO
    )
    r = subprocess.run([sys.executable, "-c", code], env=ENV,
                       capture_output=True, text=True)
    check("nginx templates render", "NGINX_OK" in r.stdout,
          r.stdout.strip() or r.stderr.strip()[:80])

    wire_py = f"""
import sys, tempfile
sys.path.insert(0, {str(REPO)!r})
from pathlib import Path
from vexashield import ddos
d = Path(tempfile.mkdtemp())
sites = d / 'sites'; sites.mkdir()
NL = chr(10)
original = NL.join(['server {{', '    listen 80;', '}}', '', 'server {{',
                    '    listen 443;', '}}', ''])
f = sites / 'site.conf'; f.write_text(original)
snip = d / 'vexashield-server.conf'; snip.write_text('# snippet')
store = {{}}
n = ddos._wire_server_blocks(snip, originals=store, sites=(sites,))
wired = n == 1 and f.read_text().count('vexashield-server.conf') == 2
ddos._rollback(d / '00-void.conf', snip, store)
rolled = f.read_text() == original and not snip.exists()
print('WIRE_OK' if (wired and rolled) else 'WIRE_BAD', n, len(store))
"""
    wf = Path(tempfile.gettempdir()) / "vs_wire_test.py"
    wf.write_text(wire_py, encoding="utf-8")
    r = subprocess.run([sys.executable, str(wf)], capture_output=True,
                       text=True, timeout=60)
    wf.unlink(missing_ok=True)
    check("nginx wiring rolls back", "WIRE_OK" in r.stdout,
          (r.stdout.strip() or r.stderr.strip())[:90])

    # -------------------------------------------------------- fail2ban ----
    code = ("import sys;sys.path.insert(0,r'%s');"
            "from vexashield import ddos;"
            "cfg={'f2b_http_retry':12,'f2b_http_find':60,'f2b_http_ban':600,"
            "'f2b_scan_retry':5,'f2b_scan_find':600,'f2b_scan_ban':86400,"
            "'f2b_flood_enabled':1,'f2b_flood_retry':15,'f2b_flood_find':60,"
            "'f2b_flood_ban':1800};"
            "t=ddos._render_jails(cfg,'/var/log/nginx/error.log');"
            "print('JAILS' if all(x in t for x in ['[vs-http-limit]',"
            "'[vs-portscan]','[vs-flood]','discord-webhook']) else 'BAD')"
            % REPO)
    r = subprocess.run([sys.executable, "-c", code], env=ENV,
                       capture_output=True, text=True)
    check("fail2ban jails render", "JAILS" in r.stdout, r.stderr.strip()[:80])

    # ------------------------------------------------------- dashboard ----
    proc = subprocess.Popen(
        [sys.executable, "-m", "vexashield", "dashboard", "run"],
        cwd=REPO, env=ENV, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, start_new_session=True)
    try:
        status, body = (0, {})
        for _ in range(40):
            time.sleep(0.25)
            status, body = api("GET", "/api/health")
            if status == 200:
                break
        else:
            check("dashboard start", False, "never answered /api/health")
            raise SystemExit(1)

        check("health endpoint", status == 200 and body.get("version") == "1.0.0")
        check("unauth overview blocked", api("GET", "/api/overview")[0] == 401)
        check("unauth csrf blocked",
              api("POST", "/api/config", {"backup_retention": 7})[0] == 401)
        check("bad token rejected",
              api("POST", "/api/login", {"token": "wrong"})[0] == 401)

        tok = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0,r'%s');"
             "from vexashield import core;"
             "print(core.load_config()['dash_token'])" % REPO],
            env=ENV, capture_output=True, text=True).stdout.strip()

        s, login = api("POST", "/api/login", {"token": tok})
        csrf = login.get("csrf", "")
        check("login issues csrf", s == 200 and bool(csrf), csrf[:10] + "...")
        check("session cookie set", any(c.name == "vs_sid" for c in JAR))

        s, sess = api("GET", "/api/session")
        check("session endpoint", s == 200 and sess.get("csrf") == csrf)

        s, ov = api("GET", "/api/overview")
        check("overview payload",
              s == 200 and all(k in ov for k in ("cpu", "memory", "disks", "bans",
                                                 "services", "protection",
                                                 "config", "ufw")),
              "keys=" + str(len(ov)))

        s, b = api("POST", "/api/config", {"backup_retention": 9},
                   {"X-VS-CSRF": csrf})
        check("csrf accepted", s == 200 and b.get("ok") is True)
        s, b = api("POST", "/api/config", {"backup_retention": 7})
        check("csrf enforced", s == 403)

        s, b = api("POST", "/api/backup/run", {}, {"X-VS-CSRF": csrf})
        check("backup trigger", s == 200 and b.get("ok") is True)
        bk = {}
        for _ in range(60):
            time.sleep(1)
            s, bk = api("GET", "/api/backups")
            if not bk.get("running"):
                break
        last = (bk.get("history") or {}).get("last") or {}
        check("async backup finished", bk.get("running") is False
              and last.get("ok") is True,
              f"parts={last.get('chunks')} err={str(last.get('error', ''))[:40]}")

        s, cf = api("GET", "/api/config")
        redacted = ("webhook_alert" in cf and "webhook_backup" in cf
                    and "dash_token" not in cf
                    and not str(cf.get("webhook_alert", "")).startswith("http"))
        check("config redaction", redacted, str(cf.get("webhook_alert")))

        for asset in ("/static/css/app.css", "/static/js/app.js",
                      "/static/js/login.js", "/static/login.html", "/"):
            try:
                with urllib.request.urlopen(BASE + asset, timeout=15) as r2:
                    check("asset " + asset, r2.status == 200, f"{len(r2.read())}B")
            except Exception as e:
                check("asset " + asset, False, str(e))
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=10)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass

    # ---------------------------------------------------------- doctor ----
    r = sh(["doctor"])
    print("\n--- doctor ---")
    print(r.stdout)
    check("doctor runs", r.returncode in (0, 1), f"rc={r.returncode}")

    if Path("/etc/nginx").is_dir():
        live = subprocess.run(["grep", "-rIl", "vexashield", "/etc/nginx/"],
                              capture_output=True, text=True)
        check("live nginx untouched", live.returncode != 0,
              live.stdout.strip()[:80] or "no references")
    else:
        skip("live nginx untouched", "no /etc/nginx on this host")

    # ------------------------------------------------------------ README --
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    block = "".join(chr(x) for x in (0x2588, 0x2554, 0x255A, 0x2551))
    check("README free of block-art", all(ch not in readme for ch in block))
    fences = len(re.findall(r"^```", readme, re.M))
    check("README code fences balanced", fences % 2 == 0, f"{fences} fences")
    check("README dropdowns balanced",
          readme.count("<details>") == readme.count("</details>")
          and readme.count("<summary>") == readme.count("</summary>"),
          f"{readme.count('<details>')} <details>")
    anchors = re.findall(r'href="#([^"]+)"', readme)
    slugs = []
    for _, txt in re.findall(r"^(#{2}) (.+)$", readme, re.M):
        flat = "".join(ch for ch in txt.lower() if ch.isalnum() or ch in "-_ ")
        slugs.append(flat.replace(" ", "-"))
    check("README anchors resolve",
          bool(anchors) and all(a in slugs for a in anchors),
          " ".join(anchors))

    # must stay last: it counts the checks above plus itself
    m = re.search(r"badge/tests-(\d+)%2F(\d+)", readme)
    total = len(RESULTS) + 1
    check("README test badge accurate",
          bool(m) and int(m.group(1)) == int(m.group(2)) == total,
          f"badge={m.group(1)}/{m.group(2)} actual={total}" if m else "no badge")

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n==== {passed}/{len(RESULTS)} checks passed ====")
    for name, ok, detail in RESULTS:
        if not ok:
            print(f"  FAILED: {name} {detail}")

    if args.keep:
        print(f"temporary dir kept: {T}")
    else:
        shutil.rmtree(T, ignore_errors=True)
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
