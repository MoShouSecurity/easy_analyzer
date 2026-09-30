//! Default triage rules. Findings describe evidence to review, not a verdict.
use super::{decoded, finding};
use crate::model::*;
use regex::Regex;
use std::{collections::BTreeMap, sync::OnceLock};

enum Detector {
    Event(&'static str, &'static [&'static str]),
    PrivilegedGroup,
    RemoteDesktop,
    AdminShare,
    KerberosRc4,
    WindowsCommand(Regex),
    WebRequest(Regex),
    WebAgent(Regex),
    WebMethod,
    WebStatus(u16, u16),
    WebDenied,
    WebError(Regex),
    LinuxText(Regex),
    LoginFailure,
    RootLogin,
    PasswordLogin,
}
struct Rule {
    id: &'static str,
    severity: Severity,
    title: &'static str,
    detail: &'static str,
    advice: &'static str,
    detector: Detector,
}
const SECURITY: &str = "Microsoft-Windows-Security-Auditing";
const EVENTLOG: &str = "Microsoft-Windows-Eventlog";

fn field<'a>(log: &'a LogData, name: &str) -> Option<&'a str> {
    log.fields.get(name).map(String::as_str).or_else(|| {
        let suffix = format!(".{name}");
        let text_suffix = format!(".{name}.#text");
        log.fields.iter().find_map(|(key, value)| {
            (key.ends_with(&suffix) || key.ends_with(&text_suffix)).then_some(value.as_str())
        })
    })
}
fn provider(log: &LogData) -> Option<&str> {
    log.fields.iter().find_map(|(key, value)| {
        key.ends_with("Provider.#attributes.Name")
            .then_some(value.as_str())
    })
}
struct Context<'a> {
    log: &'a LogData,
    raw: &'a str,
    provider: Option<&'a str>,
    event_id: Option<&'a str>,
    uri: Option<String>,
}
impl Context<'_> {
    fn event(&self, expected_provider: &str, ids: &[&str]) -> bool {
        self.log.category == "windows_event"
            && self
                .provider
                .is_some_and(|p| p.eq_ignore_ascii_case(expected_provider))
            && self.event_id.is_some_and(|id| ids.contains(&id))
    }
    fn security(&self, ids: &[&str]) -> bool {
        self.event(SECURITY, ids)
    }
}
pub(super) fn authentication_event(log: &LogData, id: &str) -> bool {
    log.category == "windows_event"
        && provider(log).is_none_or(|p| p.eq_ignore_ascii_case(SECURITY))
        && field(log, "event_id") == Some(id)
}
impl Detector {
    fn matches(&self, context: &Context<'_>) -> bool {
        let log = context.log;
        let raw = context.raw;
        match self {
            Self::Event(p, ids) => context.event(p, ids),
            Self::PrivilegedGroup => {
                context.security(&["4728", "4732", "4756"])
                    && field(log, "TargetSid").is_some_and(|sid| {
                        sid == "S-1-5-32-544"
                            || (sid.starts_with("S-1-5-21-")
                                && ["-512", "-518", "-519"].iter().any(|s| sid.ends_with(s)))
                    })
            }
            Self::RemoteDesktop => {
                context.security(&["4624"]) && field(log, "LogonType") == Some("10")
            }
            Self::AdminShare => {
                context.security(&["5140", "5145"])
                    && field(log, "ShareName").is_some_and(|s| {
                        let s = s.to_ascii_lowercase();
                        s.ends_with("\\admin$") || s.ends_with("\\c$")
                    })
            }
            Self::KerberosRc4 => {
                context.security(&["4769"])
                    && field(log, "TicketEncryptionType")
                        .is_some_and(|s| s.eq_ignore_ascii_case("0x17") || s == "23")
                    && field(log, "Status").is_none_or(|s| s == "0x0" || s == "0")
            }
            Self::WindowsCommand(pattern) => {
                (context.security(&["4688"])
                    && field(log, "CommandLine").is_some_and(|s| pattern.is_match(s)))
                    || (context.event("Microsoft-Windows-PowerShell", &["4104"])
                        && field(log, "ScriptBlockText").is_some_and(|s| pattern.is_match(s)))
            }
            Self::WebRequest(pattern) => {
                matches!(log.category.as_str(), "web_access" | "web_error")
                    && context.uri.as_deref().is_some_and(|s| pattern.is_match(s))
            }
            Self::WebAgent(pattern) => {
                log.category == "web_access"
                    && field(log, "user_agent").is_some_and(|s| pattern.is_match(s))
            }
            Self::WebMethod => {
                log.category == "web_access"
                    && field(log, "method").is_some_and(|s| {
                        ["TRACE", "CONNECT", "PROPFIND"].contains(&s.to_ascii_uppercase().as_str())
                    })
            }
            Self::WebStatus(min, max) => {
                log.category == "web_access"
                    && field(log, "status")
                        .and_then(|s| s.parse::<u16>().ok())
                        .is_some_and(|s| (*min..=*max).contains(&s))
            }
            Self::WebDenied => {
                log.category == "web_access" && matches!(field(log, "status"), Some("401" | "403"))
            }
            Self::WebError(pattern) => {
                log.category == "web_error"
                    && field(log, "message").is_some_and(|s| pattern.is_match(s))
            }
            // Do not search EVTX JSON, web URLs, or binary hex as Linux commands.
            Self::LinuxText(pattern) => log.category == "auth_text" && pattern.is_match(raw),
            Self::LoginFailure => {
                field(log, "action") == Some("login_failure") || authentication_event(log, "4625")
            }
            Self::RootLogin => {
                field(log, "action") == Some("login_success")
                    && field(log, "user") == Some("root")
                    && field(log, "client_ip").is_some_and(|s| !s.is_empty() && s != "-")
            }
            Self::PasswordLogin => {
                log.category == "auth_text"
                    && field(log, "action") == Some("login_success")
                    && raw.to_ascii_lowercase().contains("accepted password for ")
            }
        }
    }
}
fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        use Detector::*;
        use Severity::*;
        let re = |s: &str| Regex::new(s).expect("built-in rule regex");
        let command = r"(?i)(?:-(?:enc|encodedcommand)\b|frombase64string|(?:curl|wget)\b[^\r\n]*\|\s*(?:sh|bash)|/dev/tcp/|(?:invoke-expression|iex)\s*\(|downloadstring\s*\(|\bmimikatz\b|\bsekurlsa::|\bprocdump\b[^\r\n]*\blsass\b)";
        let mut r = vec![];
        let mut add = |id, severity, title, detail, advice, detector| r.push(Rule { id, severity, title, detail, advice, detector });
        add(
            "event-log-clear",
            High,
            "事件日志清除",
            "Windows 审计或事件日志被清除。",
            "核对清除账号和维护记录，关联此前登录、进程及远程访问。",
            Event(EVENTLOG, &["1102"]),
        );
        add(
            "system-log-clear",
            High,
            "系统事件日志清除",
            "Eventlog 提供者报告日志清除事件 104。",
            "核对清除的日志通道、操作账号和授权记录。",
            Event(EVENTLOG, &["104"]),
        );
        add(
            "audit-policy-change",
            High,
            "审计策略或审计权限变更",
            "审计策略或对象审计配置发生变更（4719/4907/4912）。",
            "比较变更前后的审计配置，检查是否停用关键审计。",
            Event(SECURITY, &["4719", "4907", "4912"]),
        );
        add(
            "audit-service-stop",
            Medium,
            "事件日志服务停止",
            "Eventlog 提供者报告事件日志服务停止（1100）。",
            "结合系统关机、维护记录及服务状态核对原因。",
            Event(EVENTLOG, &["1100"]),
        );
        add(
            "privileged-group-member",
            High,
            "高权限组新增成员",
            "管理员组或域高权限组 SID 对应的组新增成员。",
            "确认新增成员身份和审批，检查后续高权限操作。",
            PrivilegedGroup,
        );
        add(
            "account-hash-access",
            High,
            "账号密码哈希被访问",
            "审计事件 4782 表示账号密码哈希被访问，迁移工具也可能产生。",
            "核对访问主体、账号迁移任务及关联进程。",
            Event(SECURITY, &["4782"]),
        );
        add(
            "sid-history-added",
            High,
            "账号新增 SID History",
            "审计事件 4765 表示账号 SID History 被添加。",
            "核对域迁移授权和添加的 SID 权限。",
            Event(SECURITY, &["4765"]),
        );
        add(
            "security-package-change",
            High,
            "安全认证组件或受信登录进程加载",
            "认证包、受信登录进程或安全包注册（4610/4611/4622）。",
            "核对组件路径、签名、系统启动及安全软件安装记录。",
            Event(SECURITY, &["4610", "4611", "4622"]),
        );
        add(
            "windows-risk-command",
            High,
            "Windows 日志包含高风险执行特征",
            "进程创建或 PowerShell 脚本日志出现编码执行、下载执行或凭据访问特征。",
            "核对完整命令、脚本来源、父进程及执行账号。",
            WindowsCommand(re(command)),
        );
        add(
            "account-created",
            Medium,
            "Windows 新建账号",
            "审计事件 4720 表示账号创建。",
            "核对创建者、账号用途、权限和后续登录。",
            Event(SECURITY, &["4720"]),
        );
        add(
            "account-enabled",
            Medium,
            "Windows 账号启用",
            "审计事件 4722 表示账号被启用。",
            "核对停用账号重新启用的原因与授权。",
            Event(SECURITY, &["4722"]),
        );
        add(
            "account-changed",
            Medium,
            "Windows 账号属性或名称变更",
            "账号属性修改或重命名（4738/4781）。",
            "核对变更字段、操作主体及授权记录。",
            Event(SECURITY, &["4738", "4781"]),
        );
        add(
            "password-reset",
            Medium,
            "Windows 密码重置尝试",
            "审计事件 4724 表示尝试重置账号密码；需查看事件结果。",
            "核对结果、目标账号和重置发起者。",
            Event(SECURITY, &["4724"]),
        );
        add(
            "security-group-member",
            Medium,
            "安全组新增成员",
            "安全组成员新增（4728/4732/4756）。",
            "核对目标组权限与成员变更授权。",
            Event(SECURITY, &["4728", "4732", "4756"]),
        );
        add(
            "account-locked",
            Medium,
            "Windows 账号锁定",
            "审计事件 4740 表示账号被锁定。",
            "关联失败登录、调用主机与正常用户误输密码。",
            Event(SECURITY, &["4740"]),
        );
        add(
            "service-installed",
            Medium,
            "Windows 服务安装",
            "审计事件 4697 表示安装服务，可能用于持久化。",
            "核对服务可执行路径、账号、签名和安装授权。",
            Event(SECURITY, &["4697"]),
        );
        add(
            "system-service-installed",
            Medium,
            "系统日志记录新服务",
            "Service Control Manager 事件 7045 表示安装服务。",
            "核对服务路径、启动方式、服务账号及安装来源。",
            Event("Service Control Manager", &["7045"]),
        );
        add(
            "scheduled-task-change",
            Medium,
            "Windows 计划任务新增、启用或修改",
            "计划任务创建、启用或更新（4698/4700/4702）。",
            "核对任务动作、触发器、执行主体及持久化风险。",
            Event(SECURITY, &["4698", "4700", "4702"]),
        );
        add(
            "user-right-change",
            Medium,
            "Windows 用户权限分配变更",
            "用户权限分配或撤销（4704/4705）。",
            "核对被修改的权限、账号及审批。",
            Event(SECURITY, &["4704", "4705"]),
        );
        add(
            "explicit-credentials",
            Medium,
            "显式凭据登录尝试",
            "审计事件 4648 表示显式凭据登录尝试，合法管理操作也会产生。",
            "核对发起进程、目标服务器、账号与远程管理记录。",
            Event(SECURITY, &["4648"]),
        );
        add(
            "admin-share-access",
            Medium,
            "访问 Windows 管理共享",
            "检测到 ADMIN$ 或 C$ 共享访问或访问检查。",
            "核对访问是否获准、来源主机、目标文件及远程运维授权。",
            AdminShare,
        );
        add(
            "kerberos-rc4-ticket",
            Medium,
            "Kerberos 服务票据使用 RC4",
            "服务票据采用 RC4；这是加密配置核查线索，不能单独证明票据攻击。",
            "核对服务账号加密配置和请求频率，逐步评估 AES 兼容性。",
            KerberosRc4,
        );
        add(
            "firewall-policy-change",
            Medium,
            "Windows 防火墙策略变更",
            "防火墙规则或策略发生增删改（4946/4947/4948/4950/4956）。",
            "核对变更规则是否放开敏感端口以及授权记录。",
            Event(SECURITY, &["4946", "4947", "4948", "4950", "4956"]),
        );
        add(
            "account-state-change",
            Low,
            "Windows 账号停用、删除或解锁",
            "账号生命周期变更（4725/4726/4767）。",
            "核对账号管理记录和变更是否符合预期。",
            Event(SECURITY, &["4725", "4726", "4767"]),
        );
        add(
            "special-privileges",
            Low,
            "登录会话获得特殊权限",
            "审计事件 4672 表示新登录获得特殊权限；系统账号常见。",
            "关注非预期账号，关联登录类型、来源地址和操作。",
            Event(SECURITY, &["4672"]),
        );
        add(
            "rdp-login",
            Low,
            "远程桌面登录",
            "成功登录事件 4624 的 LogonType 为 10。",
            "核对来源、账号和远程桌面使用授权。",
            RemoteDesktop,
        );
        add(
            "kerberos-preauth-failure",
            Low,
            "Kerberos 预认证失败",
            "审计事件 4771 表示 Kerberos 预认证失败。",
            "查看失败码和来源，结合频率区分密码错误与攻击线索。",
            Event(SECURITY, &["4771"]),
        );
        add(
            "web-sql-injection",
            High,
            "Web SQL 注入特征",
            "URI 出现 UNION SELECT、布尔注入或时间延迟函数特征。",
            "关联请求参数、应用/数据库日志与响应内容核对利用情况。",
            WebRequest(re(r#"(?i)(?:\bunion\s+(?:all\s+)?select\b|\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b|['"]\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|\binformation_schema\b)"#)),
        );
        add(
            "web-command-injection",
            High,
            "Web 命令执行特征",
            "URI 出现命令拼接、下载执行或反向连接特征。",
            "核对响应和主机进程证据，不能仅凭请求确认执行。",
            WebRequest(re(r"(?i)(?:[;|`]\s*(?:curl|wget|bash|sh|cmd|powershell|cat|id|whoami)\b|\$\(\s*(?:id|whoami|curl|wget|cat)\b|/dev/tcp/|\b(?:cmd\.exe|powershell\.exe)\b)")),
        );
        add(
            "web-jndi",
            High,
            "Web JNDI 查找特征",
            "URI 出现 JNDI LDAP/RMI/DNS 等查找表达式。",
            "关联 Java 应用日志、DNS/出站连接及组件版本。",
            WebRequest(re(r"(?i)\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http)\s*:")),
        );
        add(
            "web-include",
            High,
            "Web 文件包含或代码执行特征",
            "URI 出现 PHP 过滤/输入流、数据流或 expect 执行包装器。",
            "核对参数用途、应用报错、响应及落地文件。",
            WebRequest(re(r"(?i)(?:php://(?:filter|input)|expect://|data://text/plain|\bauto_prepend_file\b|\ballow_url_include\b)")),
        );
        add(
            "web-probe",
            Medium,
            "Web 路径穿越或敏感文件探测",
            "URI 出现目录穿越、系统敏感文件、环境配置或 Git 元数据路径。",
            "核对响应码、实际响应内容与应用文件访问记录。",
            WebRequest(re(r"(?i)(?:\.\.[/\\]|/etc/(?:passwd|shadow)|/proc/self|/(?:\.env(?:[/?#]|$)|\.git(?:[/#?]|$)|\.svn/)|\bwin\.ini\b|\bboot\.ini\b)")),
        );
        add(
            "web-xss",
            Medium,
            "Web 跨站脚本特征",
            "URI 出现脚本标签、JavaScript 协议或事件处理器特征。",
            "核对参数是否反射/存储，以及输出编码和实际页面行为。",
            WebRequest(re(r"(?i)(?:<\s*script\b|javascript\s*:|\bon(?:error|load|mouseover)\s*=|<\s*(?:svg|img)\b[^>]*\bon\w+\s*=)")),
        );
        add(
            "web-ssrf",
            Medium,
            "Web 内网或云元数据 URL 参数",
            "查询参数包含回环地址、常见私网地址或云元数据地址。",
            "核对参数是否用于服务器取回 URL，以及实际出站访问记录。",
            WebRequest(re(r"(?i)[?&][^=&]+=(?:https?://)(?:localhost\b|127\.|\[::1\]|169\.254\.169\.254\b|10\.\d+\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")),
        );
        add(
            "web-shell-path",
            Medium,
            "Web 常见脚本后门路径",
            "请求命中常见脚本后门文件名或上传目录中的脚本路径。",
            "核对文件是否真实存在、内容、修改时间及部署记录。",
            WebRequest(re(r"(?i)(?:/(?:webshell|shell|cmd|c99|r57|b374k)\.(?:php|aspx?|jsp)(?:[/?#]|$)|/(?:uploads?|files)/[^?#]*\.(?:php|aspx?|jsp)(?:[/?#]|$))")),
        );
        add(
            "web-sql-error",
            Medium,
            "Web 错误日志包含数据库错误",
            "错误消息出现 SQL 语法、Oracle 错误码或数据库驱动报错。",
            "关联同一时段请求及应用栈，检查输入异常和数据库状态。",
            WebError(re(r"(?i)(?:SQL syntax|SQLSTATE\[|ORA-\d{5}|mysqli?_(?:query|fetch)|postgres[^\r\n]*ERROR)")),
        );
        add(
            "web-admin-probe",
            Low,
            "Web 管理、调试或备份入口访问",
            "URI 访问常见管理、调试、配置或备份入口。",
            "核对入口暴露范围、认证、响应及正常运维来源。",
            WebRequest(re(r"(?i)(?:/(?:wp-login\.php|wp-admin|phpmyadmin|actuator|server-status|swagger)(?:[/?#]|$)|\.(?:bak|old|sql|backup)(?:[?#]|$))")),
        );
        add(
            "web-scanner-agent",
            Low,
            "Web 扫描工具 User-Agent",
            "请求 User-Agent 含常见扫描工具标识，标识可能被伪造。",
            "核对授权扫描计划、来源地址及请求频率。",
            WebAgent(re(r"(?i)(?:sqlmap|nikto|nuclei|masscan|zgrab|gobuster|dirbuster|acunetix|nessus)")),
        );
        add(
            "web-unusual-method",
            Low,
            "Web 非常见请求方法",
            "出现 TRACE、CONNECT 或 PROPFIND 请求。",
            "核对服务是否需要该方法以及返回结果。",
            WebMethod,
        );
        add(
            "web-access-denied",
            Low,
            "Web 认证失败或访问拒绝",
            "Web 返回 401 或 403；可能是正常访问控制。",
            "结合频率、账号及目标路径检查未授权访问探测。",
            WebDenied,
        );
        add(
            "web-server-error",
            Low,
            "Web 服务端错误响应",
            "Web 返回 500–599，可能涉及应用故障或异常输入。",
            "关联错误日志、请求参数和服务运行状况。",
            WebStatus(500, 599),
        );
        add(
            "linux-risk-command",
            High,
            "Linux 日志包含高风险命令",
            "文本日志出现下载执行、反向连接或编码执行特征。",
            "核对命令是否实际执行、操作主体和关联进程。",
            LinuxText(re(command)),
        );
        add(
            "linux-evidence-clear",
            High,
            "Linux 日志或审计停用特征",
            "文本日志出现清空日志、清除历史或关闭审计的命令特征。",
            "核对维护授权、日志完整性、审计状态及操作时间。",
            LinuxText(re(r"(?i)(?:\bauditctl\s+-e\s+0\b|\bhistory\s+-c\b|\b(?:rm|truncate)\b[^\r\n]*(?:/var/log/|\.bash_history)|(?:>|tee\s+)\s*/var/log/(?:auth\.log|secure|wtmp|btmp|audit/))")),
        );
        add(
            "linux-account-change",
            Medium,
            "Linux 账号或组管理操作",
            "账号管理程序记录新增账号、组或用户属性变更。",
            "核对账号管理授权、权限和关联登录记录。",
            LinuxText(re(r"(?i)(?:\b(?:useradd|usermod|userdel|groupadd|groupmod|groupdel)\b[^\r\n]*(?:new user|new group|change|delete|COMMAND=)|\bCOMMAND=[^\r\n]*\b(?:useradd|usermod|userdel|groupadd|groupmod|groupdel|passwd)\b)")),
        );
        add(
            "linux-sudo-command",
            Medium,
            "Linux sudo 执行命令",
            "sudo 日志记录提权执行命令。",
            "核对发起账号、目标用户、完整命令与授权运维任务。",
            LinuxText(re(r"(?i)\bsudo(?:\[\d+\])?\s*:[^\r\n]*\bCOMMAND=")),
        );
        add(
            "linux-sudo-denied",
            Medium,
            "Linux 提权认证失败或拒绝",
            "sudo/su 日志记录密码错误、认证失败或无 sudo 权限。",
            "关联用户、终端和重试频率，检查是否非预期提权。",
            LinuxText(re(r"(?i)(?:\bsudo(?:\[\d+\])?\s*:[^\r\n]*(?:incorrect password|not in the sudoers|authentication failure|NOT in sudoers)|pam_unix\((?:sudo|su):auth\)[^\r\n]*authentication failure)")),
        );
        add(
            "linux-crontab-change",
            Medium,
            "Linux crontab 修改",
            "crontab 日志记录计划任务替换或删除。",
            "核对任务内容、执行账号与修改授权。",
            LinuxText(re(r"(?i)\bcrontab(?:\[\d+\])?\s*:[^\r\n]*\b(?:REPLACE|DELETE)\b")),
        );
        add(
            "linux-ssh-key-change",
            Medium,
            "Linux SSH 授权文件修改命令",
            "日志命令涉及写入、复制或修改 authorized_keys。",
            "核对公钥来源、目标用户及变更授权。",
            LinuxText(re(r"(?i)(?:\b(?:cp|tee|chmod|chown|sed)\b[^\r\n]*authorized_keys|>>?\s*[^\r\n]*authorized_keys)")),
        );
        add(
            "root-login",
            Medium,
            "远程 root 登录",
            "记录显示 root 从远程来源成功登录。",
            "核对来源地址、认证方式和直接 root 登录授权。",
            RootLogin,
        );
        add(
            "login-failure",
            Low,
            "登录失败记录",
            "发现单次或零散登录失败；大量短时失败另由高危关联规则处理。",
            "查看账号、来源与失败原因，关联是否随后登录成功。",
            LoginFailure,
        );
        add(
            "ssh-password-login",
            Low,
            "SSH 密码认证成功",
            "SSH 使用密码认证登录成功。",
            "核对来源、账号与认证策略，关注非预期登录。",
            PasswordLogin,
        );
        r
    })
}

pub(super) fn analyze(report: &mut AnalysisReport) {
    // Aggregate by rule and source to avoid one finding per routine 401/failure.
    let mut matches: BTreeMap<(usize, &str), Vec<&Record>> = BTreeMap::new();
    for record in &report.records {
        if record.status == ParseStatus::Malformed {
            continue;
        }
        let RecordData::Log(log) = &record.data else {
            continue;
        };
        let context = Context {
            log,
            raw: &record.raw,
            provider: provider(log),
            event_id: field(log, "event_id"),
            uri: field(log, "uri").map(|uri| decoded(&uri.replace('+', " "))),
        };
        for (index, rule) in rules().iter().enumerate() {
            if rule.detector.matches(&context) {
                matches
                    .entry((index, &record.source_id))
                    .or_default()
                    .push(record);
            }
        }
    }
    for ((index, _), records) in matches {
        let rule = &rules()[index];
        let mut f = finding(
            rule.id,
            rule.severity.clone(),
            rule.title,
            format!(
                "{} 同一来源命中 {} 条记录；需结合资产用途和授权操作核查。",
                rule.detail,
                records.len()
            ),
            records.iter().map(|r| r.id.clone()).collect(),
            match rule.severity {
                Severity::High => 0.8,
                Severity::Medium => 0.65,
                _ => 0.5,
            },
        );
        f.recommendations = vec![rule.advice.into()];
        report.findings.push(f);
    }
}
