---
name: nginx2root-response
description: Detect nginx2root/nginx HTTP/2 RCE exposure on Linux servers, produce a user-approved remediation plan, apply the fix only after explicit approval, and perform read-only intrusion triage. Use when asked to check a server for nginx2root/CVE-2026-123007, plan or execute an nginx security upgrade, or investigate whether an exposed server was compromised.
---

# nginx2root response

## Overview

Run a controlled four-stage response for nginx2root exposure:

1. **Detect** — read-only exposure and evidence check.
2. **Plan** — produce an exact remediation plan and obtain explicit user approval.
3. **Fix** — back up, patch, verify, and retain a rollback path.
4. **Triage** — collect read-only compromise evidence and report confidence limits.

This skill is for defensive operations on systems the user is authorized to administer. It contains no exploit code and does not replace a professional incident-response or forensic engagement.

## Non-negotiable safety contract

- **Read-only by default.** Detection and intrusion-triage scripts must not modify the target, reload nginx, block traffic, delete logs, or rotate credentials.
- **No repair without explicit approval.** Present the remediation plan and ask the user to approve it. A request to "check" is not permission to patch. Approval for one server, one scope, or one maintenance window is not permission for another.
- **No unattended mode.** Do not add `--yes`, `--force`, or non-interactive approval to package-manager or service commands unless the user explicitly authorized that exact action and window.
- **No blind one-click scripts.** Never run `curl | sh`, vendor "root fix" scripts, or copied exploit tools. Use the target's package manager and the official nginx security advisory.
- **Back up before changing.** Capture config, installed package versions, loaded configuration, and a rollback path before stopping or replacing nginx.
- **No secrets in output.** Do not print private keys, `.env` contents, database URLs, passwords, tokens, full phone numbers, request bodies, or full customer records. Prefer counts, paths, timestamps, and public key fingerprints.
- **Do not clean up an intrusion.** If compromise evidence appears, preserve logs and disk state, stop making changes, and ask the user about isolation or escalation. Do not delete files, kill processes, or rebuild silently.
- **Do not overclaim.** Absence of log evidence is not proof of safety. State the retention window, missing telemetry, and whether fileless or log-tampering scenarios remain possible.

## Required inputs

Ask only for what is needed (one or two questions at a time):

- Target host or SSH alias and how to reach it; never request that credentials be pasted into chat. Use a local SSH config or agent.
- Domain(s) and ports to test from outside, if public exposure must be confirmed.
- Whether HTTP/2, HTTP/3, mail proxy, resolver, mirror, or request-derived `proxy_pass` are intentionally used.
- Maintenance window, downtime tolerance, and whether the user has a preferred fixed package source.
- Whether the user wants detection only, approved remediation, intrusion triage, or all three.

Do not invent the target's OS, package manager, service manager, or public DNS. Read them from the host.

## Phase 1 — Detect (read-only)

Run the bundled audit on the target:

```bash
sudo bash scripts/audit-exposure.sh --domain example.com
```

Omit `--domain` when no external ALPN check is wanted. The script reports:

- nginx binary version, full package version, and compiled HTTP/2 module;
- whether `http2` is enabled in the loaded configuration;
- optional external `ALPN protocol: h2` result;
- worker crash/signal counts across retained error logs;
- nginx core-dump presence, current workers, and child processes;
- SCTP module/built-in/config state and whether it is blocked;
- auditd/process-accounting availability;
- a summary suitable for the plan.

Also read `references/detection.md` for the CVE applicability matrix and backport caveat. Do not decide from `nginx -v` alone:

- Official nginx 1.30.7+ stable and 1.31.9+ mainline are listed as not vulnerable to the nginx2root set in the official advisory.
- Distribution packages may backport fixes without changing the nginx version. Compare the full package version with the distro advisory.
- CVE-2026-123007 and CVE-2026-123633 require HTTP/2. CVE-2026-123634 needs `resolver` plus request-derived `proxy_pass` plus `mirror`; CVE-2026-121810 needs HTTP/3; CVE-2026-113425 needs the mail proxy. CVE-2026-118899 affects TLS 1.3 request-body handling.
- The kernel SCTP privilege-escalation chain is separate from nginx. Check `CONFIG_IP_SCTP`, the loaded module, and whether the host actually needs SCTP.

For a CDN or reverse proxy in front of nginx, test the actual nginx listener, not only the CDN edge.

## Phase 2 — Remediation plan (no changes yet)

Use `assets/remediation-plan.md` and fill it with observed facts. The plan must include:

- exact target, current nginx version/full package version, OS, service manager, and public DNS;
- exposure conclusion and which CVE paths are applicable;
- proposed fixed version/package source and how it was verified against the official/distro advisory;
- files and package state to back up;
- exact commands, including whether nginx will be stopped, and expected downtime;
- configuration compatibility checks (`listen ... http2`, `http2 on`, cache paths, certbot, modules, default server);
- verification checks for HTTP/2, TLS, public pages, application health, and error logs;
- rollback commands and the person/condition that triggers them;
- post-fix intrusion-triage scope and any logging/audit improvements proposed separately;
- explicit approval line: target, scope, window, and approver.

Present the plan to the user and ask for explicit approval. If the user hesitates, answer questions and stop. Do not start package changes or service stops in the same message as the request for approval.

## Phase 3 — Fix (only after approval)

Follow `references/remediation.md` for the target platform. The minimum safe sequence is:

1. Record start time, current version, package versions, `nginx -T`, service state, and worker state.
2. Back up `/etc/nginx` (or the target's config tree), package list, and rollback packages/artifacts. Store backups with restrictive permissions.
3. Use the distro's fixed package or the official nginx repository. Do not install an unverified third-party binary.
4. If replacing packages, preserve existing configuration deliberately (for example `--force-confold` on Debian/Ubuntu after reviewing prompts). Ensure required runtime directories such as `/var/cache/nginx` exist.
5. Run `nginx -t` before starting the new binary.
6. Restart nginx; a reload is not enough to replace a running binary.
7. Run `scripts/verify-remediation.sh --domain example.com` and the application's own checks.
8. If verification fails, execute the rollback path immediately and report; do not stack more fixes on a failing deployment.

For containers and Kubernetes, update the image/controller and roll out; do not treat a manual patch inside a running container as a permanent fix. For managed nginx services, use the provider's supported upgrade path.

Only after approval, and only if the host does not use SCTP, consider blocking auto-load as defense in depth:

```conf
# /etc/modprobe.d/disable-sctp.conf
install sctp /bin/false
```

This does not remove an already-loaded module, does not disable SCTP built into the kernel, and does not replace a kernel update. Verify the host's requirements first.

## Phase 4 — Verify

Run the bundled verifier:

```bash
sudo bash scripts/verify-remediation.sh --domain example.com
```

Confirm, at minimum:

- `nginx -v` and the full package version are the intended fixed build;
- `nginx -t` passes; the service is active and enabled;
- HTTP/2 is reachable if it was intentionally enabled, or intentionally disabled;
- TLS and the main public paths return the expected status;
- application health and authentication still work;
- nginx error logs do not show worker crashes or new critical errors;
- no unrelated configuration or certificate material was lost.

## Phase 5 — Intrusion triage (read-only)

Run the collector on the target:

```bash
sudo bash scripts/collect-triage.sh --domain example.com
```

Use `references/forensics.md` for interpretation and manual checks. Collect evidence in this order:

1. **Worker execution and crashes** — auditd worker `execve` records (if enabled), process accounting, current worker children, error-log worker exits, core dumps.
2. **Connection anomalies** — long-lived HTTP/2 connections with high received bytes and little sent, many short TLS connections from one source, current listeners/outbound connections.
3. **Access logs** — secret-file probes, unusual methods, status distribution, high-rate sources, HTTP/2 request mix, and whether sensitive paths ever returned 200.
4. **Root persistence** — successful SSH logins and key fingerprints, account changes, `authorized_keys` mtimes, sudoers, cron/systemd/rc.local/ld.so.preload, setuid files, web shells, packages, containers.
5. **Kernel/SCTP** — module load state, `/proc/net/sctp`, kernel Oops/KASAN/double-free logs, core dumps.
6. **Application-layer probes** — invalid Server Action IDs or framework exploit probes; distinguish failed probes from successful execution.

Interpretation rules:

- A worker crash alone is not proof of exploit; correlate time, source, and other evidence.
- A worker starting an external program is a strong signal, but only auditd/process accounting installed before the event can prove it historically.
- Missing auditd, missing connection-level logs, log rotation, and a restart that closed old connections are evidence gaps. Say so.
- If evidence suggests a successful compromise, stop remediation/cleanup and recommend isolation, credential rotation, forensic preservation, and rebuild from trusted media. Do not make that decision silently.

## Phase 6 — Report

Return a short report to the user with:

- exposure status and fixed-version evidence;
- exact change performed, downtime, and verification results;
- intrusion-triage findings and confidence;
- evidence limitations and retention windows;
- residual risks and recommended follow-ups (auditd, SCTP block, kernel update, h2 connection logging, credential rotation only if justified).

Never include secrets or raw sensitive logs. Preserve original evidence; do not overwrite it with a generated report.

## Resources

- `scripts/audit-exposure.sh` — read-only exposure audit.
- `scripts/verify-remediation.sh` — read-only post-fix verification.
- `scripts/collect-triage.sh` — read-only compromise-evidence collector.
- `assets/remediation-plan.md` — plan template to fill before approval.
- `references/detection.md` — CVE matrix, applicability, and detection details.
- `references/remediation.md` — platform-specific patch and rollback runbook.
- `references/forensics.md` — evidence sources, commands, and interpretation limits.
