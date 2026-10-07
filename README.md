# VexaShield

Anti-DDoS engine, Discord-delivered database backups and a control dashboard
for small production VPSes. One Python package, stdlib only, zero runtime
dependencies.

| | |
| --- | --- |
| **Version** | 1.0.0 |
| **License** | MIT |
| **Requires** | Linux, root, Python 3.10+ |
| **Tested on** | Debian 12 · Ubuntu 22.04/24.04 · RHEL/CentOS 8+ · Fedora · openSUSE · Arch · Alpine |
| **Packages** | none (optional: nginx, fail2ban, ufw, mariadb-client) |

---

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/Nex-Devz/VexaShield/main/install.sh | bash
```

Or from a clone:

```bash
git clone https://github.com/Nex-Devz/VexaShield.git
cd VexaShield
bash install.sh            # interactive
bash install.sh -y         # every default accepted, CI-friendly
```

`install.sh` detects your distribution, installs the runtime dependencies
(python3, curl, ca-certificates, git, gzip, iptables, cron, mariadb-client,
fail2ban, nginx, ufw — whichever your package manager ships), verifies Python
3.10+, fetches the source if needed, then runs the interactive installer.

### Installer options

| Option | Effect |
| --- | --- |
| `-y`, `--yes` | unattended: accept every default |
| `--no-deps` | skip package installation entirely |
| `--minimal` | only python3, curl, ca-certificates, git, gzip, iptables, cron |
| `--no-nginx` | do not install or provision nginx throttling |
| `--no-fail2ban` | do not install the fail2ban jails |
| `--no-ufw` | do not install or enable the host firewall |
| `--no-dashboard` | install the files but leave the dashboard unit off |
| `--dry-run` | print the detected platform and package plan, change nothing |
| `--branch <name>` | fetch a different branch when installing from GitHub |
| `-- <args>` | forward extra flags straight to `install.py` |

`python3 install.py` accepts the same `--no-*` flags and honours
`NO_COLOR`, `VS_ALERT_WEBHOOK`, `VS_BACKUP_WEBHOOK`, `VS_MENTION_ID` and
`VS_DB_PASS` for scripted installs.

### What the wizard asks

| Step | Prompt | Purpose |
| --- | --- | --- |
| 1 | Discord security webhook | attacks, bans, manual blocks |
| 1 | Discord backup webhook | nightly dump result (can mirror security) |
| 1 | Discord user ID | optional `@mention` on every event |
| 2 | Database, schedule, retention | what to dump and when |
| 3 | Protection profile | `lite` / `standard` / `aggressive` |
| 4 | UFW allow-list | ssh, 80/443, dashboard `7890/tcp+udp`, game range |
| 5 | Dashboard port + access token | control panel login |

Every answer is validated before the next step: webhooks are pinged,
`mysqldump` is probed, `nginx -t` must pass before a reload, and UFW is only
enabled once SSH has an allow rule. Any file the installer touches is
snapshotted and rolled back if validation fails.

---

## What it does

### Anti-DDoS

A dedicated `VS-DDOS` chain sits at the head of `INPUT`. It scrubs and
returns — it never owns your policy, so a bad rule cannot lock you out.

| Layer | Behaviour |
| --- | --- |
| Malformed | fragments, `INVALID` conntrack, spoofed sources (`0/8`, `127/8`, broadcast) |
| Port scans | `NULL`, `XMAS`, `FIN`, `SYN+FIN`, `SYN+RST` → drop + log |
| Connection floods | `hashlimit` per source — 40 / 80 / 150 conn/s by profile |
| Concurrency | `connlimit` per source — 40 / 60 / 40 open connections |
| SSH clamp | max 8 concurrent new connections to port 22 |
| UDP floods | per-source datagram budget, tuned for game panels |
| ICMP | echo budget of 2–5/sec, everything else dropped |
| IPv6 | mirrored chain for flags, rate and ICMPv6 |
| sysctl | syncookies, backlog, `rp_filter`, redirect/source-route off, martian logging |

Profiles: `lite` (game heavy), `standard` (recommended), `aggressive`
(attack mode).

### HTTP flood (nginx)

`limit_req_zone` + `limit_conn_zone` are rendered into
`/etc/nginx/conf.d/00-vexashield.conf` and a snippet is included in every
`server { }` block. Over-limit requests receive `429`, and the matching
`vs-http-limit` jail bans repeat offenders with a Discord message.

### Fail2ban jails

| Jail | Trigger | Default ban |
| --- | --- | --- |
| `vs-http-limit` | nginx `limiting requests / connections` | 10 min |
| `vs-portscan` | `VS-SCAN:` kernel log lines | 24 h, all ports |
| `vs-flood` | `VS-FLOOD:` kernel log lines | 30 min |

Bans and unbans are pushed to Discord through
`vexashield notify ban|unban …` — there is no shell helper anywhere.

### Database backups

```
mysqldump  →  deflated .zip  →  Discord (split parts)  →  7-day retention
```

- Archives are split into parts below the Discord attachment limit and
  uploaded in batches, with a rejoin command printed in the embed.
- Success and failure both post an embed with size, duration and part count.
- `vexashield-backup.timer` runs daily and is `Persistent=true`, so a box
  that was powered off still catches up.
- `vexashield backup verify` integrity-checks every archive.

### Host firewall (UFW)

The allow-list is staged **before** ufw is switched on:

```
ssh (detected port)   tcp
80, 443               tcp
7890                  tcp + udp     # dashboard
extra ports           tcp / udp
2000-2050             tcp + udp     # game range
```

Docker-published ports keep bypassing UFW (a `DOCKER-USER` passthrough is
appended to `/etc/ufw/after.rules`).

---

## Dashboard

Runs on **`http://<host>:7890`** — `ThreadingHTTPServer`, stdlib only.

- Token sign-in, HttpOnly + `SameSite=Strict` session cookie, per-session CSRF
  token, constant-time token comparison, login rate limiting, strict CSP and
  `X-Frame-Options: DENY`.
- Views: Overview, Blocked, Protection, Bans, Backups, Settings.
- Live actions: switch profile, re-apply the stack, ban/unban addresses,
  trigger a backup, edit schedules and throttle limits, re-sync UFW.
- Polling only (5 s / 12 s) — no websockets, no framework, `MemoryMax=192M`.

```bash
vexashield dashboard url     # print the URL
```

---

## Commands

```
vexashield status                    health summary
vexashield status --json             full machine-readable state
vexashield ddos apply [--profile P]  rebuild the scrubbing chain
vexashield ddos reset                remove VexaShield chains
vexashield ddos profile aggressive   switch budget profile
vexashield backup run|list|verify    manual backup operations
vexashield ban add <jail> <ip>       manual ban
vexashield ban del <jail> <ip>       manual unban
vexashield ban list                  show every jail and address
vexashield firewall sync|status      UFW allow-list control
vexashield webhook test [alert|backup|all]
vexashield config show|set KEY VALUE
vexashield doctor                    full diagnosis
vexashield monitor                   attack-rate daemon (Discord alerts)
```

---

## Configuration

Written to `/etc/vexashield/vexashield.conf` (mode `0600`).

| Key | Default | Meaning |
| --- | --- | --- |
| `profile` | `standard` | `lite` / `standard` / `aggressive` |
| `log_drops` | `1` | log dropped packets for fail2ban |
| `allowed_ports` | `22,80,443,7890` | extra TCP allows |
| `allowed_ports_udp` | `7890` | extra UDP allows |
| `allowed_port_ranges` | `2000-2050` | game range, tcp+udp |
| `alert_webhook` / `backup_webhook` | – | Discord endpoints |
| `mention_id` | – | user to ping on events |
| `db_name` / `db_user` | `panel` / `root` | dump target |
| `backup_dir` | `/var/backups/vexashield` | archives (mode `0700`) |
| `backup_at` | `02:00` | daily schedule |
| `backup_retention` | `7` | days kept on disk |
| `backup_chunk_mb` | `8` | Discord part size |
| `nginx_rate` / `nginx_burst` / `nginx_conn` | `10r/s` / `30` / `25` | HTTP throttle |
| `f2b_*` | see file | jail thresholds, seconds |
| `dash_port` / `dash_bind` | `7890` / `0.0.0.0` | dashboard listener |
| `attack_pps_alert` | `500` | monitor alert threshold |

```bash
vexashield config show
vexashield config set profile aggressive
```

---

## Testing

The suite runs in a temporary directory with `VS_*` environment overrides —
it never touches your host firewall, fail2ban, nginx or systemd.

```bash
python3 tests/smoke.py
python3 tests/smoke.py --keep   # keep the temp dir for inspection
```

Covers the CLI, the installer entry points (`--help`, `--dry-run`, flag
parsing), config permissions, a real dump → zip → verify → history cycle, the
iptables chain inside a network namespace, nginx template rendering and
rollback, fail2ban jail rendering, and the whole dashboard auth/CSRF flow,
plus a final assertion that `/etc/nginx` was never modified.

---

## Layout

```
VexaShield/
├── install.sh                dependency bootstrap + installer launcher
├── install.py                interactive installer
├── uninstall.sh              bootstrap removal
├── uninstall.py              clean removal
├── vexashield/
│   ├── core.py               paths, config, logging, prompts
│   ├── ddos.py               iptables chain, sysctl, nginx, fail2ban
│   ├── ufw.py                host firewall provisioning
│   ├── backup.py             dump, zip, Discord delivery, retention
│   ├── discord.py            embeds + multipart chunked upload
│   ├── state.py              collectors for the dashboard
│   ├── cli.py                command line
│   └── dashboard/            server, auth, static UI
├── config/
│   ├── fail2ban/             filters, jails, Discord action
│   └── nginx/                throttle templates
├── systemd/                  firewall, dashboard, monitor, backup timer
└── tests/smoke.py            isolated end-to-end suite
```

Runtime paths:

```
/etc/vexashield/vexashield.conf   config (0600)
/var/lib/vexashield/              state, sessions, rule snapshots
/var/log/vexashield/              per-component logs
/var/backups/vexashield/          archives (0700)
```

---

## Security notes

- The config holds webhook URLs and DB credentials and is written `0600`.
- The dashboard never returns webhook URLs or the access token — only masked
  tail characters.
- `vexashield ddos reset` removes only VexaShield's own chains; UFW, Docker
  and any pre-existing rules stay untouched.
- On a remote host, keep your SSH session open until `vexashield doctor`
  reports `scrubbing_chain PASS`.

---

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/Nex-Devz/VexaShield/main/uninstall.sh | bash
# or
bash uninstall.sh --keep-data     # leave config and backups alone
bash uninstall.sh --purge         # also delete config, logs, state, backups
```

Services, units, the CLI shim, fail2ban jails, the nginx snippet and the
iptables chains are removed. UFW rules and the `sshd` jail are left alone so
your SSH session survives.

---

## License

MIT © [Nex-Devz](https://github.com/Nex-Devz)
