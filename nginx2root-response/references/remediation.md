# Remediation runbook — nginx2root

Use only after the user has approved the filled `assets/remediation-plan.md`, including the target, exact changes, window, and downtime. Detection and verification are read-only; this page describes the approved change phase.

## Principles

- Prefer a distro package that the distribution advisory says contains the fix. If the distro has no fixed build, use the official nginx repository for the target OS.
- Do not install random binaries, `curl | sh` installers, or "nginx2root root fix" scripts.
- Back up configuration and the current package/image before stopping or replacing nginx.
- Replace the running binary with a **restart**, not a reload. A reload does not replace the executable.
- Keep only the minimum downtime and always retain a tested rollback.
- Do not change unrelated TLS, firewall, application, database, or certificate settings.

## Pre-change evidence and backup

Record and store with restrictive permissions:

```bash
date -Is
nginx -v 2>&1
dpkg-query -W -f='${Package} ${Version}\n' nginx nginx-common 2>/dev/null || rpm -q nginx
nginx -T > /root/nginx-before-<timestamp>.conf 2>/root/nginx-before-<timestamp>.err
systemctl status nginx --no-pager
```

Back up the configuration tree and capture a rollback package/image:

```bash
umask 077
tar -C / -czf /root/nginx-config-before-<timestamp>.tar.gz etc/nginx
# Debian/Ubuntu: keep the current .deb files or record the exact old version.
apt-get download nginx=<old-version> nginx-common=<old-version>  # if available
```

For containers, record the current image digest and deployment revision; for Kubernetes, record the rollout revision. Do not rely on a running container as a backup.

## Debian / Ubuntu

1. Confirm whether the distro advisory already provides a fixed **full package version**. If yes, prefer it.
2. If the distro has no fixed build, configure the official nginx stable repository according to nginx.org's documented key and source instructions. Do not pipe a remote script into a shell.
3. Review the proposed package operation before executing it:

```bash
apt-get update
apt-get -s install nginx=<fixed-full-version>
```

4. Stop nginx only in the approved window, then install. Preserve local configuration deliberately; review any prompt rather than blindly accepting a new default server:

```bash
systemctl stop nginx
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  -o Dpkg::Options::="--force-confold" nginx=<fixed-full-version>
```

`--force-confold` keeps existing conffiles, but you must still inspect the result. A package transition can remove `nginx-common`; verify that required runtime files and directories remain. If `/var/cache/nginx` or an included module directory is missing, create the expected directory rather than changing unrelated config.

5. Validate and start:

```bash
nginx -t
systemctl start nginx
systemctl is-active nginx
```

6. If `nginx -t` or startup fails, stop and roll back before trying more changes.

## RHEL / Fedora / Rocky / AlmaLinux

Use the vendor's fixed package and release notes:

```bash
dnf check-update nginx
dnf info nginx
dnf update nginx
nginx -t
systemctl restart nginx
```

If the vendor's current package is still affected, use the vendor's supported repository or a documented nginx.org package path; do not replace the system package with an unverified binary.

## Containers and Kubernetes

- **Recommended:** build or pull a fixed image tag/digest (official nginx 1.31.9+ or a vendor image with a fixed full version), update the deployment, and roll out.
- Verify the **running** image digest and version after rollout.
- Do not treat `docker exec` patching of a running container as remediation; it is lost on replacement and may leave inconsistent workers.
- If the container shares a host kernel that is exposed to the SCTP chain, coordinate host kernel treatment separately.
- Preserve the old image digest for rollback.

## Configuration compatibility

- Old `listen 443 ssl http2;` syntax may produce a deprecation warning on newer nginx. It is not the security fix and can remain temporarily; if migrating, use `listen 443 ssl;` plus `http2 on;` in the intended server scope and test every site.
- Verify certbot/ACME hooks, `sites-enabled`, `conf.d`, module includes, default server behavior, temporary paths, log permissions, and service user.
- Do not disable HTTP/2 permanently unless the user chooses that as a documented interim measure; verify the actual listener afterward.
- Check application health through nginx, not only the nginx welcome page.

## Rollback

Use the exact approved rollback:

```bash
systemctl stop nginx
# restore the backed-up etc/nginx tree
tar -C / -xzf /root/nginx-config-before-<timestamp>.tar.gz
# Debian/Ubuntu example: reinstall the recorded old package versions
apt-get install -y --allow-downgrades nginx=<old-version> nginx-common=<old-version>
nginx -t
systemctl start nginx
```

For containers/Kubernetes, roll back to the prior image digest/revision and verify the running digest. A rollback should be immediate on failed configuration, failed startup, or failed public/application checks; do not stack speculative fixes.

## SCTP and kernel defense in depth

After separate approval, if the host does not use SCTP:

```conf
# /etc/modprobe.d/disable-sctp.conf
install sctp /bin/false
```

Check that no application requires SCTP first. This only blocks module loading; it does not unload an existing module and does not disable a built-in SCTP implementation. Track the kernel vendor for a fixed kernel and plan a reboot window separately.

## Post-fix verification

Run `scripts/verify-remediation.sh --domain <host>` and add application-specific checks. Record the actual version, service state, HTTP/2/TLS result, public status codes, application health, and any error-log changes. Then run the read-only intrusion triage if the server was exposed before the fix.
