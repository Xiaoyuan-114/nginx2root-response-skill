# Remediation Plan — <server / environment>

> Fill this before making changes. Do not begin remediation until the user explicitly approves this plan.

## 1. Target and contact

- Target / SSH alias: `<host or alias>`
- Environment: `<production | staging | other>`
- OS / package manager / service manager: `<observed facts>`
- Public DNS / ports: `<domain and port>`
- Owner and approval contact: `<name/team>`
- Maintenance window and downtime tolerance: `<window / expected downtime>`

## 2. Exposure assessment

- nginx binary version: `<nginx -v>`
- Full package version: `<dpkg/rpm/container image>`
- HTTP/2 module: `<present | absent>`
- HTTP/2 enabled in loaded config: `<yes | no | unknown>`
- External ALPN h2: `<yes | no | not tested>`
- Applicable CVE paths: `<CVE-2026-123007 / 123633 / 123634 / 121810 / 113425 / 118899>`
- SCTP: `<module loaded | not loaded | built-in | unknown>`
- Evidence gaps: `<auditd/acct/connection logs/etc.>`

## 3. Proposed fix

- Fixed version/package: `<full package version or image tag>`
- Fix source and verification: `<official nginx repository | distro advisory | vendor>`
- Why this version is believed fixed: `<official advisory quote/full version>`
- Configuration changes required: `<none | http2 syntax | cache dirs | modules | other>`
- Security changes requiring separate approval: `<SCTP block | kernel update | auditd | log format>`

## 4. Backups and rollback

- Config backup path: `<path with restrictive permissions>`
- Package/artifact backup: `<old package or image>`
- Current `nginx -T` snapshot: `<path>`
- Rollback command and owner: `<exact commands>`
- Rollback trigger: `<failed nginx -t, failed service start, failed smoke>`

## 5. Execution steps

1. `<record start time and current state>`
2. `<backup>`
3. `<stop or prepare service>`
4. `<install fixed package/image>`
5. `<preserve config and ensure runtime dirs>`
6. `<nginx -t>`
7. `<start/restart>`
8. `<verify>`

## 6. Verification

- [ ] `nginx -t` passes
- [ ] nginx is active and enabled
- [ ] intended fixed binary/package is running
- [ ] HTTP/2 and TLS behave as intended
- [ ] main public paths return expected status
- [ ] application health and authentication pass
- [ ] no new worker crashes or critical errors
- [ ] certificates and unrelated config remain intact

## 7. Post-fix intrusion triage

- Evidence window: `<dates / log retention>`
- Collector run: `<timestamp / operator>`
- Findings and confidence: `<summary>`
- Preserve logs / snapshot decision: `<yes/no and path>`
- Follow-ups: `<auditd, SCTP block, kernel update, credential rotation only if justified>`

## 8. Approval

- Approved by: `<name>`
- Scope approved: `<targets, exact changes, window>`
- Approval evidence: `<message/issue/ticket reference>`
- Date/time: `<timestamp>`

**Status: NOT APPROVED** until the user explicitly confirms this plan.
