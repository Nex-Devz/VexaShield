# VexaShield - product requirements

Status: approved, in progress. Every item below came out of the first install on a
real host (Ubuntu 24.04, Pterodactyl panel, game ports 2000-2050, SSH 22).

## 1. Problem

The first `curl | bash` install did not produce a usable host:

1. Package output flooded the console - `apt-get` install logs, `needrestart`
   chatter and Python warnings from fail2ban's triggers were printed between the
   installer's own step lines. Nobody can read the result of an install like that.
2. The installer never asked for anything. `install.py` disabled prompts when
   stdin was not a tty, which is always the case under `curl ... | bash`, so the
   Discord webhooks were left empty and two doctor checks failed. The console run
   showed the questions it was supposed to ask and then skipped them.
3. Every `ufw allow` failed. The rules were built as `tcp/22` and `tcp/2000-2050`
   instead of `22/tcp` and `2000:2050/tcp`, ufw rejected them with `Bad port`,
   and the install still reported success with `0 rules`. UFW was left enabled
   with its default deny-incoming policy and no allow rules.
4. Secrets lived only in a flat `vexashield.conf`. There is no place for the
   dashboard account, its password hash, or per-setting history.
5. The dashboard had one view and one credential - a token printed at the end of
   the install. A public, read-only status page is not possible, and there is no
   admin password to hand to whoever operates the box afterwards.

## 2. Goals

- An install log that contains the detail and a console that contains the answer.
- Prompts that work when stdin is a pipe, when stdin is a tty, and when neither
  exists (unattended).
- Configuration that survives losing the conf file and that can hold an admin
  account.
- Two dashboard surfaces: a public read-only status page and an admin console
  behind a password (the access token keeps working as a second credential).
- Firewall rules that are verified syntax before ufw is switched on, with SSH
  allowed first and an abort if that rule does not land.

## 3. Non-goals

- No rewrite of the scrubbing chain in nftables (iptables backend stays).
- No WAF / ModSecurity integration in this round.
- No remote multi-host management, no agent.
- No password reset flow by mail. The admin email is stored for alerts and
  operators, it is not a recovery channel.

## 4. Requirements

Each requirement has an acceptance check that lands in `tests/smoke.py`.

### R1 - quiet package installation

Package manager output is appended to `/var/log/vexashield-install.log`.
The console prints one step line per operation. On failure the last 40 lines of
the log are printed and the install continues only if the failed packages were
optional. `needrestart` runs in non-interactive mode so it prints nothing.

Accept: `bash install.sh --dry-run` and a real `apt-get` run print no
`Preconfiguring packages`, `Setting up` or `SyntaxWarning` lines; the log file
exists and contains them.

### R2 - verified source fetch

The branch tarball is downloaded with a retry, and the archive is checked for
`install.py` and `vexashield/cli.py` before it is used. On failure the installer
falls back to `git clone --depth 1`. The branch and resolved version are printed.

Accept: `acquire_source` rejects an archive without `install.py`, falls back to
git when the tarball 404s, and prints `source ready (vX.Y.Z)`.

### R3 - prompts through a pipe

`core.prompt`, `core.choose` and `core.confirm` read from stdin when it is a tty
and from `/dev/tty` otherwise. `--yes` (or `VS_NONINTERACTIVE=1`) keeps the old
behaviour: every prompt returns its default without blocking. When no tty exists
at all, prompts return their defaults instead of hanging the install.

Accept: with stdin redirected from `/dev/null` and no `/dev/tty`, `install.py`
completes and `core.prompt("x", "d") == "d"`; with `--yes` the same holds with a
tty present.

### R4 - ufw rules that ufw accepts

`ufw.allow` builds `22/tcp`, `80/tcp`, `2000:2050/udp`. Port ranges given as
`2000-2050` are normalised to `2000:2050`. Duplicate specs are added once. The
SSH rule is added first and if it fails, ufw is not enabled - the function
returns `ok: false` instead of locking the operator out. The rule count in the
summary is the number of rules that were accepted.

Accept: spec builder returns `22/tcp`, `2000:2050/tcp`, `7890/udp`; a failed SSH
allow sets `ok=false` and leaves ufw disabled.

### R5 - configuration in a database

`/var/lib/vexashield/vexashield.db` (sqlite3, stdlib) holds `config(key, value,
updated)` and `admin(id, password_hash, salt, email, created)`. `save_config`
writes the conf file (0600) and mirrors every key into the database.
`load_config` reads the conf file and falls back to the database when the file is
missing or when a key is empty. Losing the conf file must not lose the webhooks.

Accept: save + delete the conf file + load returns the same webhook values; the
database file is mode 0600.

### R6 - admin account

The installer asks for an admin password (twice, hidden) and an email address.
The password is stored as `pbkdf2_sha256$<iterations>$<salt>$<hexdigest>` with
200000 iterations. An empty answer is allowed - the dashboard then only accepts
the access token. Changing the password from the admin console rewrites the same
row.

Accept: `set_admin` / `check_password` round-trip; wrong password fails; the hash
column never contains the plaintext.

### R7 - public view and admin view

| route       | auth        | content                                        |
|-------------|-------------|------------------------------------------------|
| `/`         | none        | read-only status: version, profile, counters, backup state, link to admin |
| `/admin`    | session     | existing control panel                         |
| `/login`    | none        | one field: admin password or `vs_` access token |
| `/api/public` | none      | the JSON behind `/`, stripped of webhooks, tokens, paths and host details beyond the profile |
| `/api/*`    | session     | unchanged                                      |

`POST /api/login` accepts `{"password": ...}` or `{"token": ...}`. Failed
attempts are rate-limited as they are today.

Accept: `GET /` and `GET /api/public` return 200 with no session and no webhook,
token or password material in the body; `GET /admin` without a session returns
the login page; password login issues the same session cookie as token login.

### R8 - anti-DDoS follow-up (next round)

- raw-table `NOTRACK` for the game UDP range, ordered after a game-port
  hashlimit rule and before the `INVALID` drop.
- conntrack headroom sysctls (`nf_conntrack_buckets`, syn-receive and UDP
  timeouts), skipped when `/proc/sys/...` does not exist.
- fail2ban `iptables-ipset-proto6-allports` banaction where `ipset` is present.
- doctor checks: conntrack utilisation, log rules carry `-m limit`, filters
  compile with `fail2ban-regex`.

## 5. Test plan

`tests/smoke.py` runs everything in a temporary `VS_*` sandbox with no host
mutation. New checks for this round: ufw spec normalisation, prompt fallback
without a tty, config round-trip through the database after the conf file is
removed, admin password hash round-trip, public routes without a session,
password login, and the invariant that `/api/public` never contains
`webhook`/`token`/`db_pass`.

The README badge must carry the exact number of checks.

## 6. Rollout

1. This branch: R1-R7, tests green, pushed in small commits.
2. Hosts that already installed: re-run `curl -fsSL .../install.sh | bash`, then
   check `ufw status verbose` shows the allow rules. Until then ufw is enabled
   with no rules and inbound traffic is denied by policy.
3. R8 lands as a separate change with a two-namespace flood test.
