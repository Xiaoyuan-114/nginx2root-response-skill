# Intrusion triage reference — nginx2root exposure

This is a read-only triage guide, not a full forensic or incident-response engagement. Preserve original evidence. Do not delete logs, kill processes, block traffic, rotate credentials, or rebuild a host without explicit user authorization and a preservation plan.

## What a successful exploit may leave

CVE-2026-123007 can execute commands with the nginx worker's privileges. A successful attempt may therefore look like:

- a worker process starting `/bin/sh`, `/bin/bash`, a downloader, or another binary;
- one unusually long-lived HTTP/2 connection with a large inbound volume and little outbound data;
- many short-lived TLS connections from the same source while the long connection is active;
- a worker crash or core dump from a failed attempt;
- later root behavior if the SCTP kernel chain succeeds;
- no request-log entry for the HTTP/2 control frames themselves.

None of these is conclusive alone. Correlate time, source, process ancestry, and host changes.

## 1. Worker execution — the strongest historical signal

A normal nginx worker does not start arbitrary external programs. Check current workers:

```bash
ps -eo pid,ppid,user,uid,args | grep '[n]ginx'
for p in $(pgrep -f 'nginx: worker process'); do
  echo "worker $p"; pgrep -a -P "$p" || true
done
```

If auditd was already running with an `execve` rule, search for worker UID events. Run this only if such a rule existed **before** the suspected event:

```bash
auditctl -l | grep nginx_worker_exec || true
ausearch -k nginx_worker_exec -ts recent -i
```

An empty result from a newly installed rule proves nothing about earlier activity. Process accounting can help only if it was enabled before the event:

```bash
systemctl is-active acct
lastcomm --user www-data | head -50
```

Record whether auditd/acct were active; missing telemetry is a stated limitation, not a clean result.

## 2. Worker crashes and cores

A failed exploit can crash a worker, but crashes have benign causes too:

```bash
for f in /var/log/nginx/error.log*; do
  [ -e "$f" ] || continue
  echo "== $f"
  zgrep -Ei 'worker process.*exited|signal 11|segfault|core dumped|SIGSEGV|SIGBUS|SIGABRT' "$f" | tail -20
done
coredumpctl list nginx 2>&1 | tail -20
ls -la /var/lib/systemd/coredump /var/crash 2>/dev/null
```

Correlate crashes with scan bursts, unusual source IPs, and application errors. A clean error log does not prove no successful exploit.

## 3. Connection anomalies

Inspect live connections while the exposure is still active:

```bash
ss -tinp state established '( sport = :443 )'
```

Look for:

- one source holding a connection open for minutes;
- `bytes_received` growing quickly while `bytes_sent` is much smaller;
- the same source making many short TLS connections at the same time;
- a long-lived HTTP/2 connection with no business explanation.

A restart closes these connections; current `ss` output cannot reconstruct pre-restart history. Say so in the report.

## 4. Access logs

Default access logs are request-level. HTTP/2 `WINDOW_UPDATE` and `RST_STREAM` control frames are not logged. Useful checks:

```bash
# Top sources and status codes
zcat -f /var/log/nginx/access.log* | awk '{print $1}' | sort | uniq -c | sort -rn | head
zcat -f /var/log/nginx/access.log* | awk '{print $9}' | sort | uniq -c | sort -rn

# Sensitive-file probes; none may have returned 200
zcat -f /var/log/nginx/access.log* \
  | grep -Ei '(\.env|wp-config|phpinfo|xmlrpc|HNAP|etc/passwd)' | tail -50
zcat -f /var/log/nginx/access.log* \
  | grep -Ei '(\.env|wp-config|phpinfo|xmlrpc|HNAP|etc/passwd)' | grep ' 200 '

# HTTP/2 request mix
zcat -f /var/log/nginx/access.log* | grep -oE 'HTTP/[0-9.]+' | sort | uniq -c
```

If the user approves a logging change, add connection-level fields such as `$connection`, `$connection_requests`, `$request_length`, `$server_protocol`, and `$request_time` to a dedicated log format and reload nginx. Do not make this change during initial triage, and do not overwrite existing evidence.

## 5. Root and persistence checks

Check for changes that would survive a worker process:

```bash
# Successful SSH logins (journal usually retains more than auth.log rotation)
journalctl --no-pager | grep 'Accepted ' | tail -50

# Public key metadata only; do not print private keys
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -e "$f" ] && stat -c '%n %y %s' "$f" && wc -l < "$f" && ssh-keygen -lf "$f"
done

# Accounts, sudo, cron, systemd, loader hooks
awk -F: '$7 ~ /(bash|sh)$/ {print $1, $3, $7}' /etc/passwd
grep -RInE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null
crontab -l 2>/dev/null
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron/crontabs 2>/dev/null
systemctl list-timers --all
find /etc/systemd/system -maxdepth 2 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort -r
ls -l /etc/ld.so.preload /etc/rc.local 2>/dev/null
```

Also check:

- setuid/setgid files outside standard package paths;
- recently modified files in web roots and upload directories;
- executable/script/webshell-like files in web roots;
- unknown listening ports and outbound connections;
- unexpected Docker containers/images;
- package-manager history for unexpected installs;
- web application framework probes (for example invalid Next.js Server Action IDs) and whether they returned success.

Do not read `.env` files, database contents, private keys, or request bodies as part of routine triage. If secrets exposure is suspected, handle it as a separate approved incident step.

## 6. Kernel and SCTP

The kernel privilege-escalation path is separate from nginx:

```bash
lsmod | grep -i '^sctp' || true
ls -ld /proc/net/sctp 2>/dev/null || true
grep -E '^CONFIG_IP_SCTP=' /boot/config-$(uname -r)
grep -RInE '^[[:space:]]*install[[:space:]]+sctp[[:space:]]' /etc/modprobe.d

journalctl -k --no-pager \
  | grep -iE 'sctp|KASAN|double.free|use.after.free|general protection|BUG:|Oops|segfault|kernel panic'
zgrep -hEi 'sctp|KASAN|double.free|use.after.free|general protection|BUG:|Oops|segfault|kernel panic' \
  /var/log/kern.log* /var/log/syslog* 2>/dev/null | tail -50
```

An absent module now does not prove it was never loaded. Kernel logs may not record every module load. If a compromise is suspected, treat the host kernel as potentially affected and plan isolation/rebuild with the user.

## Evidence grading

- **Strong:** worker starts an unexpected external process; new root key/account/unit; anomalous command execution with corroborating timing.
- **Moderate:** repeated worker crashes during a plausible scan; long-lived high-inbound HTTP/2 connection; sensitive-path request returning 200.
- **Weak:** a scanner source alone; a single worker crash; a 404 probe; a missing log (unless logging was proven enabled).
- **Inconclusive:** no auditd/acct, logs rotated, nginx restarted, or no connection-level records.

State the evidence grade and the gaps. Do not turn "no evidence" into "not compromised."

## If compromise is suspected

1. Stop the remediation/cleanup work; do not delete files or logs.
2. Ask the user about isolation and evidence preservation; preserve disk/logs and, if appropriate, a snapshot.
3. Preserve Nginx/app/auth/kernel logs and process/network state before rebooting.
4. Treat credentials reachable by the worker or root as potentially exposed.
5. Plan rebuild from a trusted image/media, patched nginx, patched kernel, and rotated credentials; validate before restoring service.
6. Document the timeline, evidence gaps, and residual uncertainty.
