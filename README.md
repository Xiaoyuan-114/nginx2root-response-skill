# nginx2root-response-skill

一个给 AI Agent 使用的**服务器安全响应 skill**：用于 nginx2root / nginx HTTP/2 RCE 暴露检测、修复计划、用户批准后的修复，以及只读入侵排查。

> 防御性用途，仅用于你拥有或已获授权管理的服务器。仓库不包含 exploit、PoC 或任何针对真实目标的攻击代码。

## 它解决什么问题

当 nginx2root / CVE-2026-123007 这类漏洞公开后，运维人员通常需要同时回答三个问题：

1. 这台服务器是否真的受影响、是否对公网暴露？
2. 应该怎么修，备份、验证和回滚怎么做？
3. 在修补前后，是否有成功入侵、提权或持久化的证据？

本 skill 把流程固定为：

```text
只读检测  ->  输出修复计划  ->  等待用户明确批准  ->  修复 + 验证  ->  只读入侵排查  ->  报告
```

最重要的安全边界：**检测和排查只读；没有用户明确批准，不停止服务、不安装包、不改配置、不封 IP、不清理日志。**

## 安装

### Qoder（用户级）

```bash
git clone https://github.com/Xiaoyuan-114/nginx2root-response-skill.git
cp -R nginx2root-response-skill/nginx2root-response ~/.qoder/skills/
```

Windows PowerShell：

```powershell
git clone https://github.com/Xiaoyuan-114/nginx2root-response-skill.git
Copy-Item -Recurse .\nginx2root-response-skill\nginx2root-response "$env:USERPROFILE\.qoder\skills\"
```

### 项目级

把 `nginx2root-response/` 复制到项目的 `.qoder/skills/` 下即可。

安装后重启会话或重新加载 skills，然后使用 `/nginx2root-response`。

## 使用示例

先只读检测并出计划：

```text
检查 server-a 是否受 nginx2root / CVE-2026-123007 影响。
先只做只读检测，输出修复计划、备份/回滚方案和预计停机时间，暂时不要改动服务器。
```

用户确认计划后再修复：

```text
我批准上述计划：目标 server-a，维护窗口 10 分钟，按计划升级 nginx。
完成修复后做只读入侵排查，不要清理日志。
```

只做入侵排查：

```text
对 server-a 做一次只读入侵排查，重点看 nginx worker 崩溃、worker 执行外部程序、
HTTP/2 连接异常、SSH 新增 key、cron/systemd 持久化、SCTP 和内核日志。
不要修改或清理任何东西。
```

## 包含内容

```text
nginx2root-response/
├── SKILL.md
├── assets/
│   └── remediation-plan.md       # 修复计划模板（必须先填再审批）
├── references/
│   ├── detection.md              # CVE 适用矩阵、版本/backport、检测判据
│   ├── remediation.md            # Debian/Ubuntu、RHEL、容器/K8s 修复与回滚
│   └── forensics.md              # 只读入侵排查、证据分级和限制
└── scripts/
    ├── audit-exposure.sh         # 只读暴露检测
    ├── verify-remediation.sh     # 只读修复后验证
    └── collect-triage.sh         # 只读入侵排查采集器
```

## 快速检测

在目标服务器上以 root 运行（只读）：

```bash
sudo bash scripts/audit-exposure.sh --domain example.com
```

它会检查：

- nginx 版本、完整包版本、是否编译 HTTP/2 模块；
- 实际加载配置中的 HTTP/2 指令；
- 外部 DNS 的 TLS ALPN 是否协商 `h2`；
- 保留的 nginx error log 中的 worker 崩溃/信号次数；
- core dump、当前 worker 和子进程；
- SCTP 模块、内核配置、modprobe 屏蔽状态；
- auditd / 进程记账是否可用；
- 汇总 `EXPOSURE_STATUS`，供后续计划使用。

> 不要只看 `nginx -v`。发行版可能 backport 修复而不改版本号；必须对照完整包版本和官方/发行版安全公告。

## 修复后验证

```bash
sudo bash scripts/verify-remediation.sh --domain example.com --path /
```

只读检查 `nginx -t`、服务状态、实际运行的包版本、HTTP/2/TLS、公开路径状态、worker 和近期错误。

## 入侵排查

```bash
sudo bash scripts/collect-triage.sh --domain example.com
```

采集范围包括：

- worker 崩溃、core、当前 worker 子进程；
- 443 长连接和异常连接；
- access log 的高频来源、敏感文件探测、协议分布、敏感路径是否返回 200；
- SSH 成功登录与公钥指纹、账户、sudo、cron、systemd、loader hooks；
- setuid、web root 可执行文件、容器、近期包操作；
- SCTP、内核 Oops/KASAN 日志；
- 明确列出审计盲区。

排查脚本**不读取** `.env`、数据库记录、私钥或请求正文。

## 检测矩阵（简表）

| CVE | 受影响条件 | 修复参考 |
| --- | --- | --- |
| CVE-2026-123007 | HTTP/2 启用 | 1.30.7+ stable / 1.31.9+ mainline |
| CVE-2026-123633 | HTTP/2 + upstream | 1.30.7+ / 1.31.9+ |
| CVE-2026-123634 | resolver + 请求派生 proxy_pass + mirror | 1.30.7+ / 1.31.9+ |
| CVE-2026-121810 | HTTP/3 | 1.30.7+ / 1.31.9+ |
| CVE-2026-113425 | mail proxy + auth_http | 1.30.7+ / 1.31.9+ |
| CVE-2026-118899 | TLS 1.3 请求体 | 1.30.7+ / 1.31.9+ |

官方公告：<https://nginx.org/en/security_advisories.html>  
Xint 研究说明：<https://xint.io/blog/nginx2root-remote-code-execution>

发行版 backport 时，以发行版公告的**完整包版本**为准。nginx2root 的内核 SCTP 提权链是独立问题；不用 SCTP 的机器可在批准后考虑 `install sctp /bin/false`，但这不能替代内核更新。

## 关键安全规则

- **默认只读**：检测/排查脚本不修改目标。
- **先计划后修改**：必须展示修复计划并取得用户明确批准；"检查一下"不等于"可以修复"。
- **备份和回滚**：修改前保存配置、包版本和回滚路径；验证失败立即回滚。
- **不使用一键脚本**：不运行 `curl | sh`、来源不明的二进制或 "root fix" 脚本。
- **不自动清理入侵**：发现异常先保留证据、停止变更，再和用户决定隔离/取证/重建。
- **不泄露敏感信息**：不输出私钥、`.env`、数据库连接串、密码、token、完整手机号或请求正文。
- **不夸大结论**：没有日志不等于没被入侵；必须说明日志保留期、auditd/连接级日志缺口和内存驻留/日志篡改风险。

## 目标平台

- 主机：Linux + systemd；Debian/Ubuntu 和 RHEL 系有明确的包管理示例。
- 容器/Kubernetes：更新镜像/控制器，不把运行中容器的手工修补当作永久修复。
- 需要 `bash`、`nginx`、root 权限读取配置/日志；外部检查可选 `openssl`、`curl`。
- SSH 连接使用本地 SSH config/agent；不要把主机密码或私钥写进 repo、prompt 或日志。

## 已知限制

- 默认 access log 不记录 HTTP/2 控制帧，也没有 connection/request_length；不能完整复现博客里的按连接字节分析。
- 未启用 auditd/进程记账时，无法回查 worker 是否曾短暂执行外部程序。
- 日志会轮转；nginx 重启会关闭升级前的长连接；当前 `ss` 不能重建历史。
- 本 skill 不做取证镜像、内存分析或恶意样本分析；疑似真实入侵应升级为正式 IR。

## 验证与测试

- 所有脚本以只读方式运行，使用 `bash -n` 做语法检查。
- 在 Ubuntu 24.04 + nginx 1.30.7 环境做过只读 smoke test。
- 在任何生产环境使用前，先在 staging/lab 验证包源、停机窗口和回滚步骤。

## 许可

MIT，见 [LICENSE](LICENSE)。nginx 与 nginx2root 相关名称归其各自权利人；本仓库与 nginx/F5/Xint 无隶属关系。
