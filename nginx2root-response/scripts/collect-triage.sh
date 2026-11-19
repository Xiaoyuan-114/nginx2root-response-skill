#!/usr/bin/env bash
# Read-only compromise-evidence collector for an exposed nginx host.
# It does not delete logs, change configuration, block traffic, restart services,
# read .env files, query databases, or print private keys or request bodies.
set -u
LC_ALL=C
export LC_ALL

DOMAIN=""

usage() {
  cat <<'EOF'
Usage: sudo bash collect-triage.sh [--domain example.com]

Collects read-only evidence for nginx2root / HTTP/2 exposure triage.
--domain is optional and only used for a public TLS/HTTP/2 check.

This is triage, not full forensics. Preserve original logs; do not clean up a
suspected compromise before deciding on isolation and forensic preservation.
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

section "Host and service"
say "TIME=$(date -Is 2>/dev/null || date)"
say "HOST=$(hostname 2>/dev/null || echo unknown)"
say "KERNEL=$(uname -sr)"
say "UPTIME=$(uptime 2>/dev/null || true)"
if need systemctl; then
  say "NGINX_SERVICE=$(systemctl is-active nginx 2>/dev/null || true)"
  say "AUDITD_SERVICE=$(systemctl is-active auditd 2>/dev/null || true)"
  say "ACCT_SERVICE=$(systemctl is-active acct 2>/dev/null || true)"
fi
if need nginx; then
  nginx -v 2>&1 || true
  if need dpkg-query; then
    dpkg-query -W -f='PACKAGE=${Package} FULL_VERSION=${Version} STATUS=${db:Status-Abbrev}\n' nginx nginx-common 2>/dev/null || true
  elif need rpm; then
    rpm -q nginx 2>/dev/null || true
  fi
else
  say "NGINX=absent"
fi

section "Worker crashes and cores"
CRASH=0
if need zgrep; then
  for f in /var/log/nginx/error.log*; do
    [ -e "$f" ] || continue
    n=$(zgrep -Eic 'worker process .*exited|signal 11|segfault|core dumped|SIGSEGV|SIGBUS|SIGABRT|SIGILL' "$f" 2>/dev/null || true)
    CRASH=$((CRASH + ${n:-0}))
    say "CRASH_FILE=$(basename "$f") MATCHES=${n:-0}"
  done
fi
say "WORKER_CRASH_TOTAL=$CRASH"
if need coredumpctl; then
  coredumpctl list nginx --no-pager 2>&1 | tail -n 10 || true
else
  say "COREDUMPCTL=unavailable"
fi
if [ -d /var/lib/systemd/coredump ]; then
  say "SYSTEMD_COREDUMP_FILES=$(find /var/lib/systemd/coredump -maxdepth 1 -type f 2>/dev/null | wc -l)"
  find /var/lib/systemd/coredump -maxdepth 1 -type f -printf '  %f\n' 2>/dev/null | head -n 10 || true
fi
if [ -d /var/crash ]; then
  say "VAR_CRASH_FILES:"
  find /var/crash -maxdepth 1 -type f -printf '  %f\n' 2>/dev/null | head -n 10 || true
fi

section "Current workers and www-data processes"
ps -eo pid,ppid,user,uid,args 2>/dev/null | grep '[n]ginx' || true
for p in $(pgrep -f 'nginx: worker process' 2>/dev/null || true); do
  kids=$(pgrep -a -P "$p" 2>/dev/null || true)
  if [ -n "$kids" ]; then
    say "WORKER_CHILD pid=$p"
    printf '%s\n' "$kids" | sed 's/^/  /'
  fi
done
ps -u www-data -o pid,ppid,etime,args 2>/dev/null | head -n 20 || true

section "Connections"
if need ss; then
  say "-- listening --"
  ss -lntup 2>/dev/null | head -n 30 || true
  say "-- established 443 --"
  ss -tinp state established '( sport = :443 )' 2>/dev/null | head -n 40 || true
  say "-- all established (first 30) --"
  ss -tnp state established 2>/dev/null | head -n 30 || true
fi

section "Access-log summary (retained logs; counts only)"
ACCESS=$(zcat -f /var/log/nginx/access.log* 2>/dev/null | tail -n 200000 || true)
if [ -n "$ACCESS" ]; then
  printf '%s\n' "$ACCESS" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 15 | sed 's/^/TOP_IP /'
  say "-- status --"
  printf '%s\n' "$ACCESS" | awk '{print $9}' | sort | uniq -c | sort -rn | head -n 15 | sed 's/^/STATUS /'
  say "-- top IP/minute --"
  printf '%s\n' "$ACCESS" | awk '{print $1, substr($4,2,17)}' | sort | uniq -c | sort -rn | head -n 15 | sed 's/^/IP_MINUTE /'
  say "-- sensitive-path probes --"
  printf '%s\n' "$ACCESS" | grep -Eio '(/[^" ]*(\.env|\.git|etc/passwd|wp-config|phpinfo|xmlrpc|hnap|actuator|\.vscode|\.claude|\.cursor)[^" ]*)' | sort | uniq -c | sort -rn | head -n 25 | sed 's/^/PROBE /' || true
  say "-- sensitive-path probes with 200 --"
  printf '%s\n' "$ACCESS" | grep -Ei '(\.env|wp-config|phpinfo|xmlrpc|hnap|etc/passwd)' | grep ' 200 ' | wc -l | sed 's/^/SENSITIVE_200_COUNT /' || true
  say "-- HTTP protocol mix --"
  printf '%s\n' "$ACCESS" | grep -oE 'HTTP/[0-9.]+' | sort | uniq -c | sort -rn | head -n 10 | sed 's/^/PROTO /' || true
else
  say "ACCESS_LOG=unavailable"
fi

section "Authentication and SSH"
if need journalctl; then
  say "-- successful SSH logins by user/key type --"
  journalctl --no-pager 2>/dev/null | grep 'Accepted ' | sed -E 's/.*Accepted (password|publickey) for ([^ ]+) from ([^ ]+) port.*ssh2: ([A-Z]+) (SHA256:[^ ]+).*/\2 \3 \4 \5/' | sort | uniq -c | sort -rn | head -n 20 || true
fi
say "-- authorized_keys metadata (public fingerprints only) --"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -e "$f" ] || continue
  stat -c '%n mtime=%y size=%s' "$f" 2>/dev/null || true
  say "lines=$(wc -l < "$f" 2>/dev/null || echo unknown)"
  if need ssh-keygen; then
    ssh-keygen -lf "$f" 2>&1 | sed 's/^/  /' || true
  fi
done
say "-- accounts with a login shell --"
awk -F: '$7 ~ /(bash|sh)$/ {print $1 " uid=" $3 " home=" $6 " shell=" $7}' /etc/passwd 2>/dev/null || true
say "-- sudo NOPASSWD rules --"
grep -RInE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 20 || true

section "Persistence and unusual files"
say "-- root crontab --"
crontab -l 2>&1 | head -n 20 || true
say "-- cron directories --"
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs 2>/dev/null | head -n 60 || true
say "-- custom systemd units --"
find /etc/systemd/system -maxdepth 2 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -r | head -n 30 || true
say "-- suspicious unit/cron references --"
grep -RInE '(/tmp|/dev/shm|/var/tmp|curl|wget|base64|nc |socat|python|perl|bash -i)' /etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null | head -n 30 || true
say "-- startup hooks --"
ls -l /etc/ld.so.preload /etc/rc.local 2>/dev/null || true
say "-- setuid/setgid outside standard package paths --"
find /tmp /var/tmp /dev/shm /home /opt /var/www -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m %u %g %p\n' 2>/dev/null | head -n 40 || true
say "-- web-root executable/script files --"
for d in /var/www /usr/share/nginx/html /srv; do
  [ -d "$d" ] || continue
  find "$d" -xdev -type f \( -perm -111 -o -iname '*.php' -o -iname '*.phtml' -o -iname '*.jsp' -o -iname '*.cgi' -o -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' \) -printf '%TY-%Tm-%Td %TH:%TM %m %u %p\n' 2>/dev/null | head -n 30 || true
done

section "Containers and packages"
if need docker; then
  docker ps -a --format '{{.Names}}	{{.Image}}	{{.Status}}	{{.Ports}}' 2>/dev/null | head -n 20 || true
  docker images --format '{{.Repository}}:{{.Tag}}	{{.CreatedSince}}' 2>/dev/null | head -n 20 || true
else
  say "DOCKER=unavailable"
fi
if [ -r /var/log/dpkg.log ]; then
  say "-- recent dpkg actions --"
  grep -E ' (install|upgrade|remove|purge) ' /var/log/dpkg.log 2>/dev/null | tail -n 15 || true
elif [ -r /var/log/dnf.log ]; then
  say "-- recent dnf actions --"
  tail -n 20 /var/log/dnf.log 2>/dev/null || true
fi

section "Kernel and SCTP"
if grep -qiE '^sctp[[:space:]]' /proc/modules 2>/dev/null; then
  say "SCTP_MODULE=loaded"
else
  say "SCTP_MODULE=not_loaded"
fi
[ -d /proc/net/sctp ] && say "SCTP_PROC=present" || say "SCTP_PROC=absent"
grep -E '^CONFIG_IP_SCTP=' "/boot/config-$(uname -r)" 2>/dev/null || true
if need journalctl; then
  say "-- kernel error/SCTP matches --"
  journalctl -k --no-pager 2>/dev/null | grep -iE 'sctp|KASAN|double.free|use.after.free|general protection|BUG:|Oops|segfault|kernel panic' | tail -n 30 || true
fi
if need openssl && [ -n "$DOMAIN" ]; then
  say "-- external ALPN --"
  timeout 10 openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" -alpn h2 </dev/null 2>&1 | grep -m1 -E 'ALPN protocol:|No ALPN negotiated|handshake failure|Connection refused' || true
fi

section "Evidence gaps to report"
say "AUDITD_OR_ACCT_MISSING=if inactive, historical worker execve evidence may be unavailable"
say "ACCESS_LOG_FORMAT=default combined may lack connection IDs and request_length"
say "HTTP2_CONTROL_FRAMES=not logged as requests"
say "NO_SECRETS_READ=collector did not read .env, database rows, private keys, or request bodies"
say "PRESERVE_LOGS=copy retained logs to restricted storage before rotation if compromise is suspected"
