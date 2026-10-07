#!/usr/bin/env bash
#
# VexaShield - bootstrap installer
#
#   curl -fsSL https://raw.githubusercontent.com/Nex-Devz/VexaShield/main/install.sh | bash
#   bash install.sh [options] [-- <args for install.py>]
#
# Detects the distribution, installs every runtime dependency, then hands over
# to the interactive Python installer.
#
set -Eeuo pipefail

VERSION="1.0.0"
REPO="Nex-Devz/VexaShield"
BRANCH="${VEXASHIELD_BRANCH:-main}"
NO_DEPS=0
ASSUME_YES=0
WITH_NGINX=1
WITH_FAIL2BAN=1
WITH_UFW=1
WITH_DASHBOARD=1
MINIMAL=0
DRY_RUN=0
PY_ARGS=()

# ---------------------------------------------------------------- output ---
if [[ -d /var/log && -w /var/log ]]; then
  PM_LOG="${VEXASHIELD_PM_LOG:-/var/log/vexashield-install.log}"
else
  PM_LOG="${VEXASHIELD_PM_LOG:-${TMPDIR:-/tmp}/vexashield-install.log}"
fi

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  R=$'\033[0m' B=$'\033[1m' D=$'\033[2m'
  RED=$'\033[31m' GRN=$'\033[32m' YLW=$'\033[33m'
  BLU=$'\033[34m' CYN=$'\033[36m' GRY=$'\033[90m'
else
  R= B= D= RED= GRN= YLW= BLU= CYN= GRY=
fi

_rule() { printf '%s%s%s\n' "$GRY" "$(printf '─%.0s' $(seq 1 66))" "$R"; }
info()  { printf '%s %s %s%s\n' "${BLU} info${R}" "$*" "" ""; }
step()  { printf '%s %s %s\n'   "${CYN} .  ${R}" "$*" ""; }
ok()    { printf '%s %s %s\n'   "${GRN} ok ${R}"   "$*" ""; }
warn()  { printf '%s %s %s\n'   "${YLW}warn${R}"   "$*" ""; }
err()   { printf '%s %s %s\n'   "${RED}fail${R}"   "$*" >&2; }
die()   { err "$*"; exit 1; }

usage() {
  cat <<EOF
${B}VexaShield bootstrap installer${R}  v${VERSION}

${B}USAGE${R}
  bash install.sh [options] [-- <extra args passed to install.py>]

${B}OPTIONS${R}
  -y, --yes             non-interactive: accept every default
      --no-deps         skip package installation
      --minimal         core packages only (python3, curl, ca-certificates)
      --no-nginx        do not install or provision nginx
      --no-fail2ban     do not install fail2ban
      --no-ufw          do not install or enable ufw
      --no-dashboard    install files but leave the dashboard unit off
      --dry-run         show the detected platform and packages, then exit
      --branch <name>   git branch to fetch when installing from GitHub
  -h, --help            show this help

${B}EXAMPLES${R}
  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash
  bash install.sh -y --no-nginx
  bash install.sh -- --backup-at 03:30        # forward flags to install.py

${B}SUPPORTED${R}
  Debian/Ubuntu, RHEL/CentOS/Fedora/Alma/Rocky, openSUSE, Arch, Alpine
  Requires root and Python 3.10+.
EOF
}

# ------------------------------------------------------------- arguments ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)          ASSUME_YES=1; shift ;;
    --no-deps)         NO_DEPS=1; shift ;;
    --minimal)         MINIMAL=1; shift ;;
    --no-nginx)        WITH_NGINX=0; shift ;;
    --no-fail2ban)     WITH_FAIL2BAN=0; shift ;;
    --no-ufw)          WITH_UFW=0; shift ;;
    --branch)          BRANCH="${2:?--branch needs a value}"; shift 2 ;;
    --dry-run)         DRY_RUN=1; shift ;;
    -h|--help)         usage; exit 0 ;;
    --)                shift; PY_ARGS+=("$@"); break ;;
    *)                 PY_ARGS+=("$1"); shift ;;
  esac
done

# ---------------------------------------------------------------- banner ---
banner() {
  printf '%s\n' ""
  printf '%s   VexaShield%s %sv%s%s  %s%s%s\n' \
         "$B$BLU" "$R" "$B" "$VERSION" "$R" "$GRY" "anti-DDoS / backups / dashboard" "$R"
  _rule
}

# ------------------------------------------------------------------ root ---
require_root() {
  [[ ${EUID} -eq 0 ]] || die "root required - rerun with: curl -fsSL ... | sudo bash"
}

# --------------------------------------------------------------- platform ---
detect_os() {
  OS_ID=unknown OS_FAMILY=unknown OS_PRETTY="unknown"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
    local like="${ID_LIKE:-}"
    case "$OS_ID" in
      debian|ubuntu|raspbian|linuxmint|pop|kali) OS_FAMILY=debian ;;
      rhel|centos|rocky|almalinux|fedora|amzn|ol) OS_FAMILY=rhel ;;
      opensuse*|sles)                             OS_FAMILY=suse ;;
      arch|manjaro|endeavouros|artix)             OS_FAMILY=arch ;;
      alpine)                                     OS_FAMILY=alpine ;;
      *)
        case " $like " in
          *debian*|*ubuntu*)  OS_FAMILY=debian ;;
          *rhel*|*fedora*|*centos*) OS_FAMILY=rhel ;;
          *suse*)             OS_FAMILY=suse ;;
          *arch*)             OS_FAMILY=arch ;;
          *alpine*)           OS_FAMILY=alpine ;;
        esac ;;
    esac
  fi
}

detect_pm() {
  PM=""
  local cand
  for cand in apt-get dnf yum zypper pacman apk; do
    if command -v "$cand" >/dev/null 2>&1; then PM="$cand"; break; fi
  done
  [[ -n "$PM" ]] || PM=""
}

# ----------------------------------------------------------- dependencies ---
pkg_exists() {
  case "$PM" in
    apt-get) [[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" == \
                "install ok installed" ]] ;;
    dnf|yum) rpm -q "$1"  >/dev/null 2>&1 ;;
    zypper)  rpm -q "$1"  >/dev/null 2>&1 ;;
    pacman)  pacman -Qi "$1" >/dev/null 2>&1 ;;
    apk)     apk info -e "$1" >/dev/null 2>&1 ;;
    *)       return 1 ;;
  esac
}

# translate a logical component into this distribution's package name
resolve_pkg() {
  local want="$1"
  case "$want" in
    python)
      case "$OS_FAMILY" in
        debian) echo python3 ;;
        rhel)   echo python3 ;;
        suse)   echo python3 ;;
        arch)   echo python ;;
        alpine) echo python3 ;;
        *)      echo python3 ;;
      esac ;;
    curl)      echo curl ;;
    ca)        case "$OS_FAMILY" in
                 debian) echo ca-certificates ;;
                 arch)   echo ca-certificates ;;
                 alpine) echo ca-certificates ;;
                 *)      echo ca-certificates ;;
               esac ;;
    git)       echo git ;;
    gzip)      case "$OS_FAMILY" in
                 rhel) echo gzip ;;
                 *)    echo gzip ;;
               esac ;;
    iptables)
      case "$OS_FAMILY" in
        rhel)   echo iptables-nft ;;
        *)      echo iptables ;;
      esac ;;
    iptables_persist)
      case "$OS_FAMILY" in
        debian) echo iptables-persistent ;;
        rhel)   echo iptables-services ;;
        arch)   echo iptables ;;
        *)      echo iptables ;;
      esac ;;
    fail2ban)  echo fail2ban ;;
    nginx)     echo nginx ;;
    ufw)
      case "$OS_FAMILY" in
        rhel)   echo "" ;;           # not packaged on RHEL
        *)      echo ufw ;;
      esac ;;
    mysql_client)
      case "$OS_FAMILY" in
        debian) echo mariadb-client ;;
        rhel)   echo mariadb ;;
        suse)   echo mariadb-client ;;
        arch)   echo mariadb ;;
        alpine) echo mariadb-client ;;
        *)      echo mariadb-client ;;
      esac ;;
    cron)
      case "$OS_FAMILY" in
        debian) echo cron ;;
        rhel)   echo cronie ;;
        alpine) echo dcron ;;
        *)      echo cron ;;
      esac ;;
    *)         echo "$want" ;;
  esac
}

install_packages() {
  local logical=() missing=() p r

  logical=(python curl ca git gzip iptables iptables_persist cron)
  if [[ $MINIMAL -eq 0 ]]; then
    logical+=(mysql_client)
    if [[ $WITH_FAIL2BAN -eq 1 ]]; then logical+=(fail2ban); fi
    if [[ $WITH_NGINX -eq 1 ]]; then logical+=(nginx); fi
    if [[ $WITH_UFW -eq 1 ]]; then logical+=(ufw); fi
  fi

  for p in "${logical[@]}"; do
    r="$(resolve_pkg "$p")"
    if [[ -z "$r" ]]; then continue; fi
    # a logical component may map to several packages
    for r in $r; do
      if [[ -z "$r" ]]; then continue; fi
      if ! pkg_exists "$r"; then missing+=("$r"); fi
    done
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "all dependencies already present"
    return 0
  fi

  step "installing: ${missing[*]}"
  : >"$PM_LOG" 2>/dev/null || PM_LOG="${TMPDIR:-/tmp}/vexashield-install.log"
  local rc=0
  case "$PM" in
    apt-get)
      export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
      apt-get update -qq >>"$PM_LOG" 2>&1 || rc=$?
      apt-get install -y -qq \
        -o Dpkg::Options::=--force-confold \
        -o Dpkg::Use-Pty=0 \
        -o APT::Color=0 \
        "${missing[@]}" >>"$PM_LOG" 2>&1 || rc=$?
      ;;
    dnf)     dnf install -y -q "${missing[@]}" >>"$PM_LOG" 2>&1 || rc=$? ;;
    yum)     yum install -y -q "${missing[@]}" >>"$PM_LOG" 2>&1 || rc=$? ;;
    zypper)  zypper --non-interactive install -q "${missing[@]}" >>"$PM_LOG" 2>&1 || rc=$? ;;
    pacman)  pacman -Sy --noconfirm --needed "${missing[@]}" >>"$PM_LOG" 2>&1 || rc=$? ;;
    apk)     apk add --quiet "${missing[@]}" >>"$PM_LOG" 2>&1 || rc=$? ;;
    *)       warn "no supported package manager found - install manually:" \
                  " ${missing[*]}"; rc=0 ;;
  esac

  # optional packages are best-effort: never abort the install for them
  if [[ $rc -ne 0 ]]; then
    local fatal=0
    for r in python3 python curl ca-certificates; do
      command -v "$r" >/dev/null 2>&1 || fatal=1
    done
    if [[ $fatal -eq 1 ]]; then
      tail -n 40 "$PM_LOG" 2>/dev/null || true
      die "could not install required packages (pm=$PM)"
    fi
    warn "some optional packages failed - continuing"
    tail -n 20 "$PM_LOG" 2>/dev/null || true
    rc=0
  fi
  ok "dependencies ready (log $PM_LOG)"
}

verify_python() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found after install"
  local ver major minor
  ver="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
  major="${ver%%.*}"; minor="${ver##*.}"
  if (( major < 3 || (major == 3 && minor < 10) )); then
    die "Python 3.10+ required, found $ver"
  fi
  ok "python $ver"
}

# ---------------------------------------------------------------- source ---
archive_ok() {
  # only trust an archive that carries both entry points, at the root or
  # inside the GitHub prefix directory
  local entry list="" found_install="" found_cli=""
  if ! list="$(tar -tzf "$1" 2>/dev/null)"; then
    return 1
  fi
  while IFS= read -r entry; do
    case "$entry" in
      */install.py|install.py)        found_install=1 ;;
      */vexashield/cli.py)            found_cli=1 ;;
    esac
  done <<<"$list"
  [[ -n "$found_install" && -n "$found_cli" ]]
}

source_version() {
  local f="$1/vexashield/core.py"
  [[ -r "$f" ]] || { echo "unknown"; return 0; }
  sed -n 's/^VERSION = "\(.*\)"/\1/p' "$f" | head -1
}

acquire_source() {
  local here script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"

  if [[ -n "$script_dir" && -f "$script_dir/vexashield/cli.py" && -f "$script_dir/install.py" ]]; then
    SRC="$script_dir"
    info "using local checkout: $SRC"
    return 0
  fi

  SRC="$(mktemp -d /tmp/vexashield.XXXXXX)"
  trap 'rm -rf "$SRC" >/dev/null 2>&1 || true' EXIT
  step "fetching ${REPO}@${BRANCH}"

  local url="https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
  local got="" tarball="$SRC/src.tar.gz"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 1 -o "$tarball" "$url" 2>>"$PM_LOG" && got=tar
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tarball" "$url" 2>>"$PM_LOG" && got=tar
  else
    die "curl or wget required to fetch the source"
  fi

  if [[ "$got" == "tar" ]] && archive_ok "$tarball"; then
    tar -xzf "$tarball" -C "$SRC" || die "extract failed"
    local inner
    inner="$(find "$SRC" -maxdepth 2 -name install.py -type f 2>/dev/null | head -1)"
    [[ -n "$inner" ]] || die "unexpected archive layout"
    SRC="$(dirname "$inner")"
  else
    got=""
    [[ -f "$tarball" ]] && { warn "archive rejected - falling back to git clone"; rm -f "$tarball"; }
    if command -v git >/dev/null 2>&1 &&
       git clone --depth 1 --quiet -b "$BRANCH" "https://github.com/${REPO}.git" \
                 "$SRC/git" 2>>"$PM_LOG"; then
      SRC="$SRC/git"
      got=git
    fi
  fi

  if [[ -z "$got" || ! -f "$SRC/install.py" || ! -f "$SRC/vexashield/cli.py" ]]; then
    die "could not fetch ${REPO}@${BRANCH} (see $PM_LOG)"
  fi
  ok "source ready ($(source_version "$SRC") on $BRANCH)"
}

# ------------------------------------------------------------------- run ---
main() {
  banner
  require_root
  detect_os
  detect_pm
  printf '%s   %-12s %s%s\n' "$GRY" "host" "$OS_PRETTY" "$R"
  printf '%s   %-12s %s%s\n' "$GRY" "package manager" "${PM:-not detected}" "$R"
  _rule

  if [[ $DRY_RUN -eq 1 ]]; then
    step "dry run - no changes will be made"
    local logical=() p r
    logical=(python curl ca git gzip iptables iptables_persist cron)
    if [[ $MINIMAL -eq 0 ]]; then
      logical+=(mysql_client)
      if [[ $WITH_FAIL2BAN -eq 1 ]]; then logical+=(fail2ban); fi
      if [[ $WITH_NGINX -eq 1 ]]; then logical+=(nginx); fi
      if [[ $WITH_UFW -eq 1 ]]; then logical+=(ufw); fi
    fi
    for p in "${logical[@]}"; do
      r="$(resolve_pkg "$p")"
      if [[ -z "$r" ]]; then
        printf '      %-20s %s\n' "$p" "${YLW}not packaged here${R}"
        continue
      fi
      if pkg_exists "$r"; then
        printf '      %-20s %s\n' "$r" "${GRY}installed${R}"
      else
        printf '      %-20s %s\n' "$r" "${CYN}would install${R}"
      fi
    done
    verify_python
    ok "dry run complete"
    return 0
  fi

  if [[ $NO_DEPS -eq 0 ]]; then
    install_packages
  else
    info "dependency installation skipped (--no-deps)"
  fi

  verify_python
  acquire_source

  local -a args=()
  if [[ $ASSUME_YES -eq 1 ]]; then args+=(--yes); fi
  if [[ $WITH_NGINX -eq 0 ]]; then args+=(--no-nginx); fi
  if [[ $WITH_FAIL2BAN -eq 0 ]]; then args+=(--no-fail2ban); fi
  if [[ $WITH_UFW -eq 0 ]]; then args+=(--no-ufw); fi
  if [[ $WITH_DASHBOARD -eq 0 ]]; then args+=(--no-dashboard); fi
  if [[ ${#PY_ARGS[@]} -gt 0 ]]; then args+=("${PY_ARGS[@]}"); fi

  _rule
  step "starting VexaShield installer"
  local rc=0
  python3 "$SRC/install.py" "${args[@]+"${args[@]}"}" || rc=$?
  _rule
  if [[ $rc -eq 0 ]]; then
    ok "bootstrap finished"
  else
    err "installer exited with code $rc"
  fi
  return "$rc"
}

rc=0
trap 'err "line ${LINENO} - aborting"' ERR
main "$@" || rc=$?
trap - ERR
exit "$rc"
