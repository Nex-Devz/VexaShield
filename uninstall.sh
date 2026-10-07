#!/usr/bin/env bash
#
# VexaShield - bootstrap uninstaller
#
#   curl -fsSL https://raw.githubusercontent.com/Nex-Devz/VexaShield/main/uninstall.sh | bash
#   bash uninstall.sh --keep-data
#
set -Eeuo pipefail

R="" B="" D="" RED="" GRN="" YLW="" BLU="" CYN="" GRY=""
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  R=$'\033[0m' B=$'\033[1m' D=$'\033[2m'
  RED=$'\033[31m' GRN=$'\033[32m' YLW=$'\033[33m'
  BLU=$'\033[34m' CYN=$'\033[36m' GRY=$'\033[90m'
fi

_rule() { printf '%s%s%s\n' "$GRY" "$(printf '─%.0s' $(seq 1 66))" "$R"; }
ok()    { printf '%s %s %s\n' "${GRN}ok ${R}" "$*" ""; }
warn()  { printf '%s %s %s\n' "${YLW}warn${R}" "$*" ""; }
err()   { printf '%s %s %s\n' "${RED}fail${R}" "$*" >&2; }

usage() {
  cat <<EOF
${B}VexaShield uninstaller${R}

${B}USAGE${R}
  bash uninstall.sh [--keep-data] [--purge]

${B}OPTIONS${R}
  --keep-data   leave /opt/vexashield and the backup directory in place
  --purge       also delete the config, state, logs and local backups
  -h, --help    show this help

Stops the services, removes the systemd units, the CLI shim, the fail2ban
jails, the nginx snippet and the iptables chains. The host firewall (ufw)
rules are left enabled so you keep your SSH access.
EOF
}

PURGE=0 KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)     PURGE=1; shift ;;
    --keep-data) KEEP=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           err "unknown option: $1"; usage; exit 2 ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { err "root required"; exit 1; }

printf '%s   VexaShield%s uninstaller\n' "$B$BLU" "$R"
_rule

# where is it installed?
if [[ -x /usr/local/bin/vexashield || -d /opt/vexashield ]]; then
  SRC="/opt/vexashield"
elif [[ -f "$(dirname "${BASH_SOURCE[0]:-$0}")/uninstall.py" ]]; then
  SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
else
  warn "no installation found - nothing to do"
  exit 0
fi

ARGS=()
if [[ $KEEP -eq 1 ]]; then ARGS+=(--keep-data); fi
if [[ $PURGE -eq 1 ]]; then ARGS+=(--purge); fi

python3 "$SRC/uninstall.py" "${ARGS[@]+"${ARGS[@]}"}"
rc=$?

_rule
if [[ $rc -eq 0 ]]; then ok "removal finished"; else err "exited with code $rc"; fi
exit "$rc"
