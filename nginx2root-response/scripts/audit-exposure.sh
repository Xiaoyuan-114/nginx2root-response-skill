#!/usr/bin/env bash
# Read-only nginx2root exposure audit.
# It never edits configuration, reloads nginx, installs packages, or changes services.
set -u
LC_ALL=C
export LC_ALL

DOMAIN=""

usage() {
  cat <<'EOF'
Usage: sudo bash audit-exposure.sh [--domain example.com]

--domain  Optional public hostname for an external TLS ALPN h2 check.
          Leave blank to skip network checks.

Read-only. Run on the nginx host. See references/detection.md for interpretation.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain)
      [ "$#" -ge 2 ] || { echo "--domain needs a value" >&2; exit 2; }
      DOMAIN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

say() { printf '%s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1; }

version_ge() {
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" = "$1" ]
}

section "Host"
say "TIME=$(date -Is 2>/dev/null || date)"
say "KERNEL=$(uname -sr)"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  say "OS=${PRETTY_NAME:-unknown}"
fi
say "USER=$(id -un 2>/dev/null || echo unknown) UID=$(id -u 2>/dev/null || echo unknown)"

NGINX_VERSION=""
H2_MODULE="unknown"
PATCH_ASSESSMENT="unknown"
H2_CONFIG="unknown"
ALPN="not_checked"
WORKER_CRASHES=0
SCTP_MODULE="not_loaded"
SCTP_CONFIG="unknown"
SCTP_BLOCK="none"
AUDITD="unknown"
ACCT="unknown"

if ! need nginx; then
  say "NGINX=absent"
  say "EXPOSURE=NOT_APPLICABLE_NO_NGINX_BINARY"
  exit 0
fi

section "Nginx version and package"
say "NGINX_BINARY=$(command -v nginx)"
NGINX_V=$(nginx -v 2>&1 || true)
say "NGINX_VERSION_STRING=$NGINX_V"
NGINX_VERSION=$(printf '%s' "$NGINX_V" | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p' | head -n 1)
say "NGINX_VERSION=${NGINX_VERSION:-unknown}"

if need dpkg-query; then
  dpkg-query -W -f='PACKAGE=${Package} FULL_VERSION=${Version} STATUS=${db:Status-Abbrev}\n' nginx nginx-common 2>/dev/null || true
elif need rpm; then
  rpm -q nginx 2>/dev/null || true
fi

NGINX_FLAGS=$(nginx -V 2>&1 || true)
case "$NGINX_FLAGS" in
  *--with-http_v2_module*) H2_MODULE="present" ;;
  *) H2_MODULE="absent" ;;
esac
say "HTTP2_MODULE=$H2_MODULE"

section "Configuration test and HTTP/2 directives"
NGINX_T=$(nginx -t 2>&1 || true)
say "NGINX_T_TAIL=$(printf '%s' "$NGINX_T" | tail -n 2 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"

H2_LINES=$(nginx -T 2>/dev/null | sed 's/#.*//' | grep -nE 'listen[[:space:]].*http2|^[[:space:]]*http2[[:space:]]+on[[:space:]]*;' | head -n 15 || true)
if [ -n "$H2_LINES" ]; then
  H2_CONFIG="enabled"
  say "HTTP2_CONFIG=enabled"
  printf '%s\n' "$H2_LINES" | sed 's/^/  /'
else
  if printf '%s' "$NGINX_T" | grep -qiE 'permission denied|could not open'; then
    H2_CONFIG="unknown_permission_denied"
    say "HTTP2_CONFIG=unknown (nginx -T could not read configuration; run as root)"
  else
    H2_CONFIG="disabled_or_not_found"
    say "HTTP2_CONFIG=disabled_or_not_found"
  fi
fi

section "External ALPN check"
if [ -n "$DOMAIN" ]; then
  if need openssl; then
    ALPN_RAW=$(timeout 10 openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" -alpn h2 </dev/null 2>&1 | grep -m1 -E 'ALPN protocol:|No ALPN negotiated|handshake failure|Connection refused|connect:errno' || true)
    case "$ALPN_RAW" in
      *"ALPN protocol: h2"*) ALPN="yes" ;;
      *"No ALPN negotiated"*) ALPN="no" ;;
      "") ALPN="no_result" ;;
      *) ALPN="failure" ;;
    esac
    say "ALPN_H2=$ALPN"
    [ -n "$ALPN_RAW" ] && say "ALPN_DETAIL=$ALPN_RAW"
  else
    ALPN="openssl_unavailable"
    say "ALPN_H2=not_checked_openssl_unavailable"
  fi
else
  say "ALPN_H2=not_checked (no --domain)"
fi

section "Patch assessment (must be confirmed against advisory)"
if [ -n "$NGINX_VERSION" ]; then
  case "$NGINX_VERSION" in
    1.30.*)
      if version_ge "$NGINX_VERSION" "1.30.7"; then
        PATCH_ASSESSMENT="likely_fixed_1.30.7_plus"
      else
        PATCH_ASSESSMENT="likely_vulnerable_or_distro_backport_unknown"
      fi
      ;;
    1.31.*)
      if version_ge "$NGINX_VERSION" "1.31.9"; then
        PATCH_ASSESSMENT="likely_fixed_1.31.9_plus"
      else
        PATCH_ASSESSMENT="likely_vulnerable_or_distro_backport_unknown"
      fi
      ;;
    *)
      if version_ge "$NGINX_VERSION" "1.9.5"; then
        PATCH_ASSESSMENT="likely_vulnerable_or_distro_backport_unknown"
      else
        PATCH_ASSESSMENT="before_http2_range"
      fi
      ;;
  esac
fi
say "PATCH_ASSESSMENT=$PATCH_ASSESSMENT"
say "FIXED_REFERENCE=official advisory: 1.30.7+ stable and 1.31.9+ mainline"
say "BACKPORT_CAVEAT=compare full distro package version to distro advisory"

section "Worker crash evidence"
if need zgrep; then
  for f in /var/log/nginx/error.log*; do
    [ -e "$f" ] || continue
    n=$(zgrep -Eic 'worker process .*exited|signal 11|segfault|core dumped|SIGSEGV|SIGBUS|SIGABRT|SIGILL' "$f" 2>/dev/null || true)
    WORKER_CRASHES=$((WORKER_CRASHES + ${n:-0}))
    say "WORKER_CRASH_FILE=$(basename "$f") MATCHES=${n:-0}"
  done
else
  say "ZGREP=unavailable; check /var/log/nginx/error.log manually"
fi
say "WORKER_CRASH_TOTAL=$WORKER_CRASHES"

if need coredumpctl; then
  coredumpctl list nginx --no-pager 2>&1 | tail -n 10 || true
else
  say "COREDUMPCTL=unavailable"
  if [ -d /var/lib/systemd/coredump ]; then
    c=$(find /var/lib/systemd/coredump -maxdepth 1 -type f 2>/dev/null | wc -l)
    say "SYSTEMD_COREDUMP_FILES=$c"
    find /var/lib/systemd/coredump -maxdepth 1 -type f -printf '  %f\n' 2>/dev/null | head -n 10 || true
  fi
  if [ -d /var/crash ]; then
    say "VAR_CRASH_FILES:"
    find /var/crash -maxdepth 1 -type f -printf '  %f\n' 2>/dev/null | head -n 10 || true
  fi
fi

section "Workers and listeners"
ps -eo pid,ppid,user,uid,args 2>/dev/null | grep '[n]ginx' || true
for p in $(pgrep -f 'nginx: worker process' 2>/dev/null || true); do
  kids=$(pgrep -a -P "$p" 2>/dev/null || true)
  if [ -n "$kids" ]; then
    say "WORKER_CHILD pid=$p"
    printf '%s\n' "$kids" | sed 's/^/  /'
  fi
done
if need ss; then
  ss -lntup 2>/dev/null | grep -E ':(80|443)[[:space:]]' || true
fi

section "SCTP and kernel"
if grep -qiE '^sctp[[:space:]]' /proc/modules 2>/dev/null; then
  SCTP_MODULE="loaded"
else
  SCTP_MODULE="not_loaded"
fi
say "SCTP_MODULE=$SCTP_MODULE"
if [ -d /proc/net/sctp ]; then
  say "SCTP_PROC=present"
else
  say "SCTP_PROC=absent"
fi
SCTP_CONFIG=$(grep -E '^CONFIG_IP_SCTP=' "/boot/config-$(uname -r)" 2>/dev/null | head -n 1 || true)
[ -n "$SCTP_CONFIG" ] && say "$SCTP_CONFIG"
SCTP_BLOCK=$(grep -RhsE '^[[:space:]]*install[[:space:]]+sctp[[:space:]]' /etc/modprobe.d 2>/dev/null | head -n 1 || true)
if [ -n "$SCTP_BLOCK" ]; then
  say "SCTP_BLOCK=present"
else
  say "SCTP_BLOCK=none"
fi

if need journalctl; then
  say "KERNEL_LOG_MATCHES=$(journalctl -k --no-pager 2>/dev/null | grep -icE 'sctp|KASAN|double.free|use.after.free|general protection|BUG:|Oops|segfault|kernel panic' || true)"
fi

section "Observability"
AUDITD=$(systemctl is-active auditd 2>/dev/null || true)
ACCT=$(systemctl is-active acct 2>/dev/null || true)
say "AUDITD=${AUDITD:-unknown}"
say "ACCT=${ACCT:-unknown}"
if need lastcomm; then
  say "LASTCOMM=available"
else
  say "LASTCOMM=unavailable"
fi
say "AUDIT_NOTE=missing historical execve data cannot be reconstructed from current state"

section "Summary"
if [ "$H2_MODULE" = "absent" ]; then
  EXPOSURE="NOT_AFFECTED_BY_CVE_2026_123007_HTTP2_MODULE_ABSENT"
elif [ "$PATCH_ASSESSMENT" = "likely_fixed_1.30.7_plus" ] || [ "$PATCH_ASSESSMENT" = "likely_fixed_1.31.9_plus" ]; then
  EXPOSURE="LIKELY_PATCHED_CONFIRM_FULL_PACKAGE_AND_ADVISORY"
elif [ "$H2_CONFIG" = "enabled" ] && [ "$ALPN" != "no" ]; then
  EXPOSURE="LIKELY_EXPOSED_IF_UNPATCHED_HTTP2_REACHABLE"
elif [ "$H2_CONFIG" = "disabled_or_not_found" ]; then
  EXPOSURE="HTTP2_PATH_DISABLED_OTHER_CVES_AND_BACKPORTS_REVIEW"
else
  EXPOSURE="REVIEW_INSUFFICIENT_DATA"
fi

say "EXPOSURE_STATUS=$EXPOSURE"
say "NGINX_VERSION=${NGINX_VERSION:-unknown}"
say "FULL_PACKAGE_VERSION=see PACKAGE lines above"
say "HTTP2_MODULE=$H2_MODULE"
say "HTTP2_CONFIG=$H2_CONFIG"
say "ALPN_H2=$ALPN"
say "PATCH_ASSESSMENT=$PATCH_ASSESSMENT"
say "WORKER_CRASH_TOTAL=$WORKER_CRASHES"
say "SCTP_MODULE=$SCTP_MODULE"
say "AUDITD=${AUDITD:-unknown}"
say "ACCT=${ACCT:-unknown}"
say "NEXT=read references/detection.md; produce a plan and obtain explicit approval before changing anything"
