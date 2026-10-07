# VexaShield

Anti-DDoS engine, nightly database backup and a control dashboard for small
production VPSes. One Python package, zero runtime dependencies, no shell
scripts.

```
   ██╗   ██╗██╗███████╗██╗  ██╗ █████╗ ██████╗
   ██║   ██║██║██╔════╝██║  ██║██╔══██╗██╔══██╗
   ╚██╗ ██╔╝██║█████╗  ███████║███████║██████╔╝
    ╚████╔╝ ██║██╔══╝  ██╔══██║██╔══██║██╔══██╗
     ╚═══╝  ██║███████╗██║  ██║██║  ██║██║  ██║
           ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

---

## Install

```bash
git clone https://github.com/nex-devz/VexaShield.git
cd VexaShield
sudo python3 install.py
```

The installer is interactive. It asks for:

| Prompt | Purpose |
| --- | --- |
| Discord security webhook | DDoS / ban alerts |
| Discord backup webhook | nightly dump result (can mirror security) |
| Discord user ID | optional `@mention` on every event |
| Database name, schedule, retention | what to dump and when |
| Protection profile | per-source connection budgets |
| UFW allow-list | ssh, web, dashboard `7890/tcp+udp`, game range |
| Dashboard port + access token | control panel login |

Everything it writes is validated before the next step: webhooks are pinged,
`mysqldump` is probed, `nginx -t` must pass before reload, and UFW only
enables after SSH has an allow rule.

**Requirements:** Python 3.10+, Linux with iptables. `nginx`, `fail2ban`,
`mariadb` and `ufw` are used when present and skipped cleanly when not.

---

## What it does

### Anti-DDoS

A dedicated `VS-DDOS` chain is inserted at the head of `INPUT`. It scrubs and
returns; it never owns your policy, so a bad rule cannot lock you out.

| Layer | Behaviour |
| --- | --- |
| Malformed | fragments, `INVALID` conntrack, spoofed sources (`0/8`, `127/8`, broadcast) |
| Port scans | `NULL`, `XMAS`, `FIN`, `SYN+FIN`, `SYN+RST` flag sets → drop + log |
| Connection floods | `hashlimit` per source (40/80/150 conn/s by profile) |
| Concurrency | `connlimit` per source (40/60/40 open connections) |
| SSH clamp | max 8 concurrent new connections to port 22 |
| UDP floods | per-source datagram budget, tuned for game panels |
| ICMP | echo budget of 2-5/sec, everything else dropped |
| IPv6 | mirrored chain for flags, rate and ICMPv6 |
| sysctl | syncookies, backlog, rp_filter, redirect/source-route off, martian logging |

Profiles: `lite`, `standard`, `aggressive`.

### HTTP flood (nginx)

`limit_req_zone` + `limit_conn_zone` are generated into
`/etc/nginx/conf.d/00-vexashield.conf`, and a snippet is included in every
`server { }` block. Over-limit requests get `429`, and the matching
`vs-http-limit` fail2ban jail bans repeat offenders with a Discord message.

### Fail2ban jails

| Jail | Trigger | Default ban |
| --- | --- | --- |
| `vs-http-limit` | nginx `limiting requests / connections` | 10 min |
| `vs-portscan` | `VS-SCAN:` kernel log lines | 24 h, all ports |
| `vs-flood` | `VS-FLOOD:` kernel log lines | 30 min |

Every ban and unban is pushed to Discord through
`vexashield notify ban|unban ...` - there is no shell helper anywhere.

### Backup

`mysqldump` → deflated `.zip` → Discord upload → 7-day retention.

- Archive is split into parts smaller than the Discord attachment limit and
  uploaded in batches, with a rejoin command printed in the embed.
- Success and failure both post an embed with size, duration and part count.
- Runs through `vexashield-backup.timer` (`Persistent=true`, so a powered-off
  box still catches up).
- `vexashield backup verify` integrity-checks every archive.

### Host firewall (UFW)

The installer stages the allow-list **before** enabling:

```
ssh (detected port)      tcp
80, 443                  tcp
7890                     tcp + udp      # dashboard
extra ports              tcp / udp
2000-2050                tcp + udp      # game range
```

Docker-published ports keep bypassing UFW (a `DOCKER-USER` passthrough is
appended to `/etc/ufw/after.rules`).

---

## Dashboard

Runs on **`http://<host>:7890`** (`ThreadingHTTPServer`, stdlib only).

- Token sign-in, HttpOnly + `SameSite=Strict` session cookie, per-session CSRF
  token, constant-time token comparison, login rate limiting, strict CSP and
  `X-Frame-Options: DENY`.
- Views: Overview, Blocked, Protection, Bans, Backups, Settings.
- Live actions: switch protection profile, re-apply the whole stack, ban and
  unban addresses, trigger a backup, edit schedules and throttle limits, re-sync
  UFW.
- Polling only (5s / 12s), no websockets, no framework, `MemoryMax=192M`.

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
vexashield doctor                    20-point diagnosis
vexashield monitor                   attack-rate daemon (Discord alerts)
```

---

## Layout

```
VexaShield/
├── install.py                  interactive installer
├── uninstall.py                clean removal
├── vexashield/
│   ├── core.py                 paths, config, logging, prompts
│   ├── ddos.py                 iptables chain, sysctl, nginx, fail2ban
│   ├── ufw.py                  host firewall provisioning
│   ├── backup.py               dump, zip, Discord delivery, retention
│   ├── discord.py              embeds + multipart chunked upload
│   ├── state.py                collectors for the dashboard
│   ├── cli.py                  command line
│   └── dashboard/              server, auth, static UI
├── config/
│   ├── fail2ban/               filters, jails, Discord action
│   └── nginx/                  throttle templates
└── systemd/                    firewall, dashboard, monitor, backup timer
```

Runtime paths:

```
/etc/vexashield/vexashield.conf   config (mode 0600)
/var/lib/vexashield/              state, sessions, rule snapshots
/var/log/vexashield/              per-component logs
/var/backups/vexashield/          archives (mode 0700)
```

---

## Security notes

- The config holds webhook URLs and DB credentials and is written `0600`.
- The dashboard never returns webhook URLs or the access token - only masked
  tail characters.
- `vexashield reset` removes only VexaShield's own chains; UFW, Docker and any
  pre-existing rules are untouched.
- On a remote host, keep your SSH session open until `vexashield doctor`
  reports `scrubbing_chain PASS`.

---

## Uninstall

```bash
sudo python3 uninstall.py [--keep-data]
```

---

MIT © [Nex-Devz](https://github.com/nex-devz)
