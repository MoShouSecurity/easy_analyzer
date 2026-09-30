# 默认日志规则

日志导入后自动运行完整规则集，无需配置 AI 或自行编写关键词。当前共 53 项日志规则：16 项高危、26 项中危、11 项低危。进程和 PCAP 的现有规则另计。

```sh
./easy-analyzer logs /path/to/Security.evtx /path/to/auth.log /path/to/access.log -s
./easy-analyzer logs /path/to/access.log -s -q '.env'
./easy-analyzer logs /path/to/access.log -s -j logs.json -H logs.html
```

`-s` / `--suspicious` 查询全部分级规则命中；与 `-q` 同用取交集。没有 `-s` 时，仍运行全部规则并显示发现，同时保留普通日志展示。终端关键词查询仅展示与匹配记录相关的发现。JSON/HTML 保留完整证据和发现，`query_matches` 标识查询结果。

同一规则在同一来源的命中汇总成一项发现，包含全部证据 ID、规则 ID、级别、说明、置信度和核查建议。终端默认按风险分组显示对齐的“命中记录数 + 规则名称”列表，隐藏零项级别、解释和证据位置；登录关联等发现保留简短上下文。记录区域只显示重要字段摘要；`-n 0` 显示全部记录摘要。使用 `-R` / `--raw` 显示发现解释、规则 ID、置信度、证据引用及原始记录，`-R -n 0` 显示全部详情。JSON/HTML 始终保留完整证据。概览计数是发现项数，列表中的“条”是当前查询范围内该项发现引用的记录数；它们都不是确认的攻击次数。多条规则可命中同一记录；该记录标注其中最高级别。

## 规则清单

### 高危

| 规则 ID | 名称 | 条件 / 核查线索 |
| --- | --- | --- |
| `login-failures` | 重复失败登录 | 同一来源、目标主机、来源地址与账号，5 分钟内至少 5 次失败；时间不完整时至少 10 次，仅提示累计失败。 |
| `success-after-failures` | 多次失败后登录成功 | 同一来源、目标主机、来源地址与账号，成功前 10 分钟内至少 5 次失败，要求可解析时间。 |
| `event-log-clear` | 事件日志清除 | Windows 审计或事件日志被清除。 |
| `system-log-clear` | 系统事件日志清除 | Eventlog 提供者报告日志清除事件 104。 |
| `audit-policy-change` | 审计策略或审计权限变更 | 审计策略或对象审计配置发生变更（4719/4907/4912）。 |
| `privileged-group-member` | 高权限组新增成员 | 管理员组或域高权限组 SID 对应的组新增成员。 |
| `account-hash-access` | 账号密码哈希被访问 | 审计事件 4782 表示账号密码哈希被访问，迁移工具也可能产生。 |
| `sid-history-added` | 账号新增 SID History | 审计事件 4765 表示账号 SID History 被添加。 |
| `security-package-change` | 安全认证组件或受信登录进程加载 | 认证包、受信登录进程或安全包注册（4610/4611/4622）。 |
| `windows-risk-command` | Windows 日志包含高风险执行特征 | 进程创建或 PowerShell 脚本日志出现编码执行、下载执行或凭据访问特征。 |
| `web-sql-injection` | Web SQL 注入特征 | URI 出现 UNION SELECT、布尔注入或时间延迟函数特征。 |
| `web-command-injection` | Web 命令执行特征 | URI 出现命令拼接、下载执行或反向连接特征。 |
| `web-jndi` | Web JNDI 查找特征 | URI 出现 JNDI LDAP/RMI/DNS 等查找表达式。 |
| `web-include` | Web 文件包含或代码执行特征 | URI 出现 PHP 过滤/输入流、数据流或 expect 执行包装器。 |
| `linux-risk-command` | Linux 日志包含高风险命令 | 文本日志出现下载执行、反向连接或编码执行特征。 |
| `linux-evidence-clear` | Linux 日志或审计停用特征 | 文本日志出现清空日志、清除历史或关闭审计的命令特征。 |

### 中危

| 规则 ID | 名称 | 条件 / 核查线索 |
| --- | --- | --- |
| `audit-service-stop` | 事件日志服务停止 | Eventlog 提供者报告事件日志服务停止（1100）。 |
| `account-created` | Windows 新建账号 | 审计事件 4720 表示账号创建。 |
| `account-enabled` | Windows 账号启用 | 审计事件 4722 表示账号被启用。 |
| `account-changed` | Windows 账号属性或名称变更 | 账号属性修改或重命名（4738/4781）。 |
| `password-reset` | Windows 密码重置尝试 | 审计事件 4724 表示尝试重置账号密码；需查看事件结果。 |
| `security-group-member` | 安全组新增成员 | 安全组成员新增（4728/4732/4756）。 |
| `account-locked` | Windows 账号锁定 | 审计事件 4740 表示账号被锁定。 |
| `service-installed` | Windows 服务安装 | 审计事件 4697 表示安装服务，可能用于持久化。 |
| `system-service-installed` | 系统日志记录新服务 | Service Control Manager 事件 7045 表示安装服务。 |
| `scheduled-task-change` | Windows 计划任务新增、启用或修改 | 计划任务创建、启用或更新（4698/4700/4702）。 |
| `user-right-change` | Windows 用户权限分配变更 | 用户权限分配或撤销（4704/4705）。 |
| `explicit-credentials` | 显式凭据登录尝试 | 审计事件 4648 表示显式凭据登录尝试，合法管理操作也会产生。 |
| `admin-share-access` | 访问 Windows 管理共享 | 检测到 ADMIN$ 或 C$ 共享访问或访问检查。 |
| `kerberos-rc4-ticket` | Kerberos 服务票据使用 RC4 | 服务票据采用 RC4；这是加密配置核查线索，不能单独证明票据攻击。 |
| `firewall-policy-change` | Windows 防火墙策略变更 | 防火墙规则或策略发生增删改（4946/4947/4948/4950/4956）。 |
| `web-probe` | Web 路径穿越或敏感文件探测 | URI 出现目录穿越、系统敏感文件、环境配置或 Git 元数据路径。 |
| `web-xss` | Web 跨站脚本特征 | URI 出现脚本标签、JavaScript 协议或事件处理器特征。 |
| `web-ssrf` | Web 内网或云元数据 URL 参数 | 查询参数包含回环地址、常见私网地址或云元数据地址。 |
| `web-shell-path` | Web 常见脚本后门路径 | 请求命中常见脚本后门文件名或上传目录中的脚本路径。 |
| `web-sql-error` | Web 错误日志包含数据库错误 | 错误消息出现 SQL 语法、Oracle 错误码或数据库驱动报错。 |
| `linux-account-change` | Linux 账号或组管理操作 | 账号管理程序记录新增账号、组或用户属性变更。 |
| `linux-sudo-command` | Linux sudo 执行命令 | sudo 日志记录提权执行命令。 |
| `linux-sudo-denied` | Linux 提权认证失败或拒绝 | sudo/su 日志记录密码错误、认证失败或无 sudo 权限。 |
| `linux-crontab-change` | Linux crontab 修改 | crontab 日志记录计划任务替换或删除。 |
| `linux-ssh-key-change` | Linux SSH 授权文件修改命令 | 日志命令涉及写入、复制或修改 authorized_keys。 |
| `root-login` | 远程 root 登录 | 记录显示 root 从远程来源成功登录。 |

### 低危

| 规则 ID | 名称 | 条件 / 核查线索 |
| --- | --- | --- |
| `account-state-change` | Windows 账号停用、删除或解锁 | 账号生命周期变更（4725/4726/4767）。 |
| `special-privileges` | 登录会话获得特殊权限 | 审计事件 4672 表示新登录获得特殊权限；系统账号常见。 |
| `rdp-login` | 远程桌面登录 | 成功登录事件 4624 的 LogonType 为 10。 |
| `kerberos-preauth-failure` | Kerberos 预认证失败 | 审计事件 4771 表示 Kerberos 预认证失败。 |
| `web-admin-probe` | Web 管理、调试或备份入口访问 | URI 访问常见管理、调试、配置或备份入口。 |
| `web-scanner-agent` | Web 扫描工具 User-Agent | 请求 User-Agent 含常见扫描工具标识，标识可能被伪造。 |
| `web-unusual-method` | Web 非常见请求方法 | 出现 TRACE、CONNECT 或 PROPFIND 请求。 |
| `web-access-denied` | Web 认证失败或访问拒绝 | Web 返回 401 或 403；可能是正常访问控制。 |
| `web-server-error` | Web 服务端错误响应 | Web 返回 500–599，可能涉及应用故障或异常输入。 |
| `login-failure` | 登录失败记录 | 发现单次或零散登录失败；大量短时失败另由高危关联规则处理。 |
| `ssh-password-login` | SSH 密码认证成功 | SSH 使用密码认证登录成功。 |

## 匹配范围与边界

- Windows 事件规则核对提供者和事件 ID，避免不同提供者同号事件误匹配。1102、104、1100 使用 `Microsoft-Windows-Eventlog`；7045 使用 `Service Control Manager`；其余安全审计事件使用 `Microsoft-Windows-Security-Auditing`。高风险 PowerShell 脚本使用 `Microsoft-Windows-PowerShell` 的 4104。缺少提供者时，仅原有 4624/4625 登录兼容逻辑继续工作，其余 Windows 规则不推断提供者。
- 高权限组检查 Builtin Administrators SID `S-1-5-32-544`，以及域 SID `S-1-5-21-...` 的 512、518、519 后缀。组变更会同时命中通用中危规则与高权限组高危规则。
- Web 攻击特征主要检查解析出的 URI，做大小写归一和最多两轮百分号解码；查询字符串的 `+` 按空格处理。User-Agent、方法、状态码与错误消息使用对应字段。仅有 URI/访问日志不能覆盖未记录的请求正文或响应正文，也不能确认利用成功；这些规则不等同于完整 WAF/OWASP CRS。
- Linux 操作特征检查文本日志原始行，包括未完全识别的文本行；畸形记录跳过。二进制 utmp/wtmp/btmp 的十六进制原始内容不按命令字符串扫描。日志未记载的进程、文件变更无法凭空推断。
- 零散登录失败、SSH 密码登录、特殊权限登录、管理入口访问和 401/403/5xx 都可能属于正常行为。低危表示需要关注，不表示已确认攻击。审计服务停止也可能来自正常关机；账号/服务/任务管理应结合运维授权。
- 本地规则默认启用并可离线运行，AI 只在指定 `-a` 后调用。该规则集覆盖常见场景，无法穷尽全部攻击或替代上下文核查。

## 依据

Windows 事件含义参考 [Microsoft 高级审计策略与事件目录](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)，日志清除与服务停止参考 [事件 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102) 和 [事件 1100](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1100)。Web 类别参考 [OWASP CRS 规则类别说明](https://coreruleset.org/docs/3-about-rules/rules/)，本工具采用独立的简化匹配实现，风险分级为本工具的核查优先级。
