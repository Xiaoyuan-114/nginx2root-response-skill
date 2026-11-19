#!/usr/bin/env bash
# Read-only post-remediation verification. Does not restart or reload anything.
set -u
LC_ALL=C
export LC_ALL

DOMAIN=""
CHECK_PATH="/"

usage() {
  cat <<'EOF'
Usage: sudo bash verify-remediation.sh [--domain example.com] [--path /]

Checks nginx version, configuration syntax, service state, HTTP/2/TLS reachability,
public HTTP status, workers, and recent nginx errors. Read-only.

--domain  Public hostname to test over HTTPS.
--path    Path to request; default /.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain)
      [ "$#" -ge 2 ] || { echo "--domain needs a value" >&2; exit 2; }
      DOMAIN="$2"
      shift 2
      ;;
    --path)
      [ "$#" -ge 2 ] || { echo "--path needs a value" >&2; exit 2; }
      CHECK_PATH="$2"
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

section "Nginx binary and package"
if ! need nginx; then
  say "NGINX=absent"
  exit 1
fi
nginx -v 2>&1 || true
if need dpkg-query; then
  dpkg-query -W -f='PACKAGE=${Package} FULL_VERSION=${Version} STATUS=${db:Status-Abbrev}\n' nginx nginx-common 2>/dev/null || true
elif need rpm; then
  rpm -q nginx 2>/dev/null || true
fi

section "Configuration and service"
NGINX_T=$(nginx -t 2>&1 || true)
printf '%s\n' "$NGINX_T"
if printf '%s' "$NGINX_T" | grep -qiE 'syntax is ok|test is successful'; then
  say "NGINX_T=PASS"
else
  say "NGINX_T=FAIL"
fi
if need systemctl; then
  say "NGINX_ACTIVE=$(systemctl is-active nginx 2>/dev/null || true)"
  say "NGINX_ENABLED=$(systemctl is-enabled nginx 2>/dev/null || true)"
fi
ps -eo pid,ppid,user,uid,args 2>/dev/null | grep '[n]ginx' || true

section "Loaded HTTP/2 directives"
nginx -T 2>/dev/null | sed 's/#.*//' | grep -nE 'listen[[:space:]].*http2|^[[:space:]]*http2[[:space:]]+on[[:space:]]*;' | head -n 15 || true

section "Public checks"
if [ -n "$DOMAIN" ]; then
  if need openssl; then
    say "-- ALPN --"
    timeout 10 openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" -alpn h2 </dev/null 2>&1 | grep -m1 -E 'ALPN protocol:|No ALPN negotiated|handshake failure|Connection refused' || true
  fi
  if need curl; then
    say "-- HTTP/2 request --"
    curl -sS --http2 -o /dev/null -w 'URL=%{url_effective} HTTP=%{http_code} VERSION=%{http_version} TIME=%{time_total}s\n' "https://${DOMAIN}${CHECK_PATH}" 2>&1 || true
    say "-- HTTP/1.1 control request --"
    curl -sS --http1.1 -o /dev/null -w 'URL=%{url_effective} HTTP=%{http_code} VERSION=%{http_version} TIME=%{time_total}s\n' "https://${DOMAIN}${CHECK_PATH}" 2>&1 || true
  else
    say "CURL=unavailable"
  fi
else
  say "PUBLIC_CHECK=skipped_no_domain"
fi

section "Listeners and recent errors"
if need ss; then
  ss -lntup 2>/dev/null | grep -E ':(80|443)[[:space:]]' || true
fi
if need journalctl; then
  journalctl -u nginx --since "30 min ago" --no-pager 2>/dev/null | tail -n 20 || true
fi

section "Verification summary"
say "VERIFY=review the fields above; do not declare success unless config, service, public status, and application checks pass"
say "ROLLBACK=use the pre-change config/package backup if any check fails"
