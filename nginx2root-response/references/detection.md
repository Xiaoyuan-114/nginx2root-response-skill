# Detection reference — nginx2root

## What nginx2root covers

`nginx2root` is a set of nginx vulnerabilities plus a Linux kernel SCTP privilege-escalation chain. The most widely applicable nginx issue, CVE-2026-123007, is an HTTP/2 flow-control memory-corruption bug that can execute commands with the nginx worker's privileges without authentication. The kernel chain can turn worker code execution into host root, including from a container on a shared kernel.

This is a defensive detection and patch guide. Do not use exploit code or untrusted one-click tools.

## Official fixed releases

The official nginx security advisory lists **1.30.7+ (stable)** and **1.31.9+ (mainline)** as not vulnerable for the nginx2root CVEs covered below. A blog post may mention only 1.31.9; check the official advisory, not only the blog headline.

- Official advisory: <https://nginx.org/en/security_advisories.html>
- Xint research write-up: <https://xint.io/blog/nginx2root-remote-code-execution>
- nginx releases: <https://github.com/nginx/nginx/releases>

## Applicability matrix

| CVE | Affected feature | Fixed reference | Notes |
| --- | --- | --- | --- |
| CVE-2026-123007 | HTTP/2 enabled | 1.30.7+ / 1.31.9+ | Unauthenticated worker RCE; disabling HTTP/2 blocks this path |
| CVE-2026-123633 | HTTP/2 to an upstream | 1.30.7+ / 1.31.9+ | Disabling HTTP/2 blocks this path |
| CVE-2026-123634 | `resolver` + request-derived `proxy_pass` + `mirror` | 1.30.7+ / 1.31.9+ | Other subrequest features may reach the same bug |
| CVE-2026-121810 | HTTP/3 / QUIC | 1.30.7+ / 1.31.9+ | Not applicable if HTTP/3 is not configured |
| CVE-2026-113425 | Mail proxy with `proxy on` + `auth_http` | 1.30.7+ / 1.31.9+ | Not applicable if no mail proxy |
| CVE-2026-118899 | TLS 1.3 request-body handling | 1.30.7+ / 1.31.9+ | Major DoS; do not treat as only an HTTP/2 issue |

## Detection rules

1. **Do not rely on the version string alone.** A distro can backport fixes without changing `nginx -v`. Compare the full package version (for example `dpkg-query -W` or `rpm -q`) with the distribution's advisory.
2. **Confirm the module and configuration.** HTTP/2 code must be compiled in and enabled on an affected listener. `nginx -T` reads the on-disk configuration; verify the running configuration and restart semantics.
3. **Confirm external reachability.** From outside the network, request ALPN `h2`; if a CDN sits in front, test the actual nginx listener. A CDN check alone can produce a false negative.
4. **Check every listener/server block.** One HTTP/2 listener can be enough even if another is HTTP/1.1-only.
5. **Check the other features.** A server not using HTTP/2 can still be affected by the resolver/mirror, HTTP/3, mail-proxy, or TLS 1.3 issues. A full fixed release is the safest outcome.

## Read-only commands

```bash
nginx -v 2>&1
nginx -V 2>&1 | grep -q -- '--with-http_v2_module' \
  && echo 'HTTP2_MODULE=present' || echo 'HTTP2_MODULE=absent'
nginx -T 2>&1 | sed 's/#.*//' \
  | grep -nE 'listen[[:space:]].*http2|^[[:space:]]*http2[[:space:]]+on[[:space:]]*;'
openssl s_client -connect example.com:443 -servername example.com -alpn h2 </dev/null 2>&1 \
  | grep -E 'ALPN protocol:|No ALPN negotiated|handshake failure|Connection refused'
```

Package and kernel checks:

```bash
dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' nginx nginx-common 2>/dev/null
# or: rpm -q nginx
lsmod | grep -i '^sctp'
grep -E '^CONFIG_IP_SCTP=' /boot/config-$(uname -r)
grep -RInE '^[[:space:]]*install[[:space:]]+sctp[[:space:]]' /etc/modprobe.d
```

## Kernel SCTP chain

The kernel SCTP bug can be reached by a process that can open an SCTP socket; the module may auto-load. If the host does not use SCTP:

- Block auto-load with `install sctp /bin/false` in `/etc/modprobe.d/` **after approval**.
- This does not remove an already-loaded module and does not disable SCTP built into the kernel.
- Track the kernel vendor for a fixed kernel; blocking the module is defense in depth, not a kernel fix.
- If SCTP is required, do not block it; isolate the need and prioritize a patched kernel.

## Server-exposure decision

- **HTTP/2 module absent:** CVE-2026-123007's HTTP/2 path is not present, but review the other CVEs and the full package.
- **HTTP/2 enabled and unpatched/full version unknown:** treat as exposed until the advisory and full package version prove otherwise.
- **HTTP/2 disabled, unpatched:** the main HTTP/2 path is blocked, but the package is still not a full fix; other paths remain.
- **Fixed full package/release:** verify the actual running binary and service, not just the package on disk.
- **Inconclusive:** do not downgrade to "safe"; collect more evidence and patch from a trusted source.
