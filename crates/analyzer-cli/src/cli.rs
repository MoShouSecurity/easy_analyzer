use analyzer_app::InputFormat;
use clap::{
    Arg, ArgAction, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum,
    builder::{PossibleValuesParser, TypedValueParser},
};
use std::path::PathBuf;

// Keep each spelling consistent across commands, including global arguments.
const SHORT_OPTIONS: &[(&str, char)] = &[
    ("config", 'c'),
    ("format", 'f'),
    ("web_format", 'w'),
    ("web_format_file", 'W'),
    ("auto_load", 'l'),
    ("live_processes", 'p'),
    ("evidence_dir", 'e'),
    ("query", 'q'),
    ("regex", 'r'),
    ("suspicious", 's'),
    ("tree", 't'),
    ("ai", 'a'),
    ("ai_scope", 'S'),
    ("include_payload", 'P'),
    ("output", 'o'),
    ("out", 'O'),
    ("json_out", 'j'),
    ("html_out", 'H'),
    ("limit", 'n'),
    ("raw", 'R'),
    ("max_file_mb", 'm'),
    ("max_records", 'M'),
];

const HELP_TEMPLATE: &str = "{about-with-newline}\n用法：{usage}\n\n{all-args}{after-help}";
const COMMAND_HELP_TEMPLATE: &str = "{about-with-newline}\n用法：{usage}\n\n功能命令：\n{subcommands}\n\n通用参数：\n{options}{after-help}";
const ROOT_EXAMPLES: &str = "如何选择命令：
  已知是日志文件 → logs；进程采集/快照 → processes；网络抓包文件 → pcap
  不确定文件类型，或需要混合分析 → analyze；AI 服务配置 → config

常用示例：
  easy-analyzer logs cases/Security.evtx -s
  easy-analyzer logs cases/Security.evtx -s -R
  easy-analyzer logs cases/access.log -q '.env'
  easy-analyzer processes -t
  easy-analyzer pcap cases/capture.pcapng
  easy-analyzer analyze cases/wtmp cases/processes.json cases/capture.pcap
  easy-analyzer config init

查看某个命令的参数和示例：easy-analyzer logs -h
默认在本地解析并运行规则；只有指定 --ai 才向配置的服务发送证据。";

#[derive(Parser)]
#[command(version, about = "Easy Analyzer · 日志、进程与离线网络证据分析", after_help = ROOT_EXAMPLES)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help_heading = "AI 分析",
        help = "AI 配置文件路径；省略时使用当前工作目录的 config.toml"
    )]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// 应急响应项目：创建、续办、追加证据与备注
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// 混合分析：自动识别日志、进程快照和 PCAP 文件
    #[command(after_help = "示例：
  easy-analyzer analyze cases/Security.evtx cases/wtmp cases/processes.json cases/capture.pcap
  easy-analyzer analyze cases/access.log -j reports/case.json -H reports/case.html
  easy-analyzer analyze -p -t

输入：提供文件，或使用 --auto-load / --live-processes；文件名 - 表示标准输入。
--format 强制指定所有输入的格式，混合文件通常保持 auto。
--auto-load 在 Windows/Linux 本机加载日志；macOS 请指定离线文件。
筛选只控制终端记录与 AI matches 范围；JSON/HTML 保留完整记录及 query_matches。")]
    Analyze(AnalyzeArgs),
    /// 日志分析：EVTX、Linux 登录日志、SSH 和 Web 日志
    #[command(after_help = "示例：
  easy-analyzer logs cases/Security.evtx -s
  easy-analyzer logs cases/wtmp cases/btmp
  easy-analyzer logs cases/access.log -q 'union.*select|\\.env' -r
  easy-analyzer logs cases/access.log -W nginx-format.conf
  cat cases/auth.log | easy-analyzer logs - -f text
  easy-analyzer logs cases/Security.evtx -a -S suspicious

输入：提供日志文件或 --auto-load；文件名 - 表示标准输入。
--auto-load 只加载当前 Windows/Linux 主机的日志；macOS 请指定离线文件。
本地规则自动运行；--suspicious 选择规则引用的记录，与 --query 同用时取交集。
JSON/HTML 保留完整记录；筛选结果 ID 位于 query_matches。")]
    Logs(LogArgs),
    /// 进程分析：无文件时采集本机，有文件时导入 JSON 快照
    #[command(after_help = "示例：
  easy-analyzer processes -t
  easy-analyzer processes cases/processes.json -q powershell
  easy-analyzer processes cases/processes.json -a -S suspicious
  easy-analyzer processes -j reports/processes.json

输入：不提供文件时采集当前主机；文件输入须为进程 JSON 数组或本工具报告。
可提供多个快照；文件名 - 表示从标准输入读取 JSON。
终端默认显示进程树；--tree 明确请求树形显示。
查询/筛选只控制终端记录与 AI matches 范围；JSON/HTML 保留完整记录。")]
    Processes(ProcessArgs),
    /// 网络分析：导入 PCAP/PCAPNG，解析包与网络会话
    #[command(after_help = "示例：
  easy-analyzer pcap cases/capture.pcapng
  easy-analyzer pcap cases/capture.pcap -q '/.env'
  easy-analyzer pcap cases/capture.pcap -a
  easy-analyzer pcap cases/capture.pcap -a -P

输入：提供一个或多个 PCAP/PCAPNG 文件；文件名 - 表示标准输入。
本命令离线分析已有抓包文件，不启动实时抓包。
AI 默认只接收包摘要；--include-payload 额外发送原始包与载荷。
查询/筛选只控制终端记录与 AI matches 范围；JSON/HTML 保留完整记录。")]
    Pcap(PcapArgs),
    /// AI 配置：创建模板、查看设置、检查服务
    #[command(after_help = "配置步骤：
  1. easy-analyzer config init
  2. 默认使用 DeepSeek deepseek-flash；在 config.toml 中填写 api_key
  3. easy-analyzer config check
  4. easy-analyzer logs cases/Security.evtx -a

自定义配置路径：easy-analyzer -c settings.toml config init
所有平台默认：当前工作目录的 config.toml（运行命令时所在的目录）
其他 AI 服务可修改 base_url、model 和 api_key。
config check 会发送一个不含项目证据的小请求，可能产生服务费用。")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Args)]
pub struct ProjectMetadata {
    #[arg(long, help = "项目名称；新建时默认使用客户单位")]
    pub name: Option<String>,
    #[arg(long)]
    pub client: Option<String>,
    #[arg(long)]
    pub response_start: Option<String>,
    #[arg(long)]
    pub response_end: Option<String>,
    #[arg(long)]
    pub location: Option<String>,
    #[arg(long)]
    pub responders: Option<String>,
    #[arg(long)]
    pub description: Option<String>,
}
#[derive(Subcommand)]
pub enum ProjectCommand {
    /// 创建并保存空项目，客户单位必填，名称默认为客户单位
    Create {
        path: PathBuf,
        #[command(flatten)]
        info: ProjectMetadata,
    },
    /// 打开已有项目，不重新解析或自动发送 AI
    Open {
        path: PathBuf,
        #[command(flatten)]
        common: CommonArgs,
    },
    /// 搜索本机最近打开的项目
    List {
        #[arg(long, default_value = "")]
        search: String,
        #[arg(long, default_value = "")]
        client: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        until: Option<String>,
    },
    /// 向项目追加证据，保存回项目文件
    Import {
        path: PathBuf,
        #[command(flatten)]
        args: AnalyzeArgs,
    },
    /// 修改基本资料，保存回项目文件
    Edit {
        path: PathBuf,
        #[command(flatten)]
        info: ProjectMetadata,
    },
    /// 写入或读取证据备注；空字符串删除备注
    Note {
        path: PathBuf,
        #[arg(long)]
        record: String,
        #[arg(long)]
        text: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// 创建配置模板；在 api_key 字段填写密钥，已存在时返回错误
    Init,
    /// 显示配置路径和当前设置（密钥隐藏）
    Show,
    /// 请求 AI 服务，检查连接和结构化 JSON 响应
    Check,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Output {
    Text,
    Json,
    Html,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AiScope {
    All,
    Matches,
    Suspicious,
}

#[derive(Args)]
#[command(group(ArgGroup::new("selection").args(["query", "suspicious"]).multiple(true)))]
pub struct CommonArgs {
    #[arg(long, value_name = "PATH", help = "打开应急响应项目，并追加本次证据")]
    pub project: Option<PathBuf>,
    #[arg(long, value_name = "PATH", help = "手动保存项目为 .eair 文件")]
    pub save_project: Option<PathBuf>,
    #[arg(long, help = "新项目名称；默认使用客户单位")]
    pub project_name: Option<String>,
    #[arg(long, help = "客户单位；保存新项目时必填")]
    pub client: Option<String>,
    #[arg(long, help = "响应开始时间，RFC3339 格式，包含时区")]
    pub response_start: Option<String>,
    #[arg(long, action=ArgAction::Append, value_name="FILE", help="追加 TXT/CSV IOC 文件，可重复")]
    pub ioc: Vec<PathBuf>,
    #[arg(long, action=ArgAction::Append, value_name="VALUE", help="手动添加 IOC，可重复")]
    pub ioc_value: Vec<String>,
    #[arg(long, help = "从标准输入读取 IOC 清单，与证据标准输入互斥")]
    pub ioc_stdin: bool,
    #[arg(
        long,
        requires = "ioc_stdin",
        help = "标准输入 IOC 使用 type,value,note CSV"
    )]
    pub ioc_stdin_csv: bool,
    #[arg(long, help = "域名只匹配本身，不包含子域名")]
    pub ioc_exact_domain: bool,

    #[arg(
        long,
        value_name = "TEXT",
        help_heading = "查询与筛选",
        help = "搜索原始内容及解析字段；不区分大小写"
    )]
    query: Option<String>,
    #[arg(
        long,
        requires = "query",
        help_heading = "查询与筛选",
        help = "将 --query 按正则表达式匹配"
    )]
    regex: bool,
    #[arg(
        long,
        help_heading = "查询与筛选",
        help = "一键查询默认规则命中的高危、中危及低危证据；与 --query 同用取交集"
    )]
    suspicious: bool,
    #[arg(
        long,
        help_heading = "AI 分析",
        help = "主动发送证据到配置的 AI 服务进行分析"
    )]
    ai: bool,
    #[arg(
        long,
        value_enum,
        default_value = "all",
        requires = "ai",
        requires_if("matches", "selection"),
        value_name = "SCOPE",
        help_heading = "AI 分析",
        help = "发送范围：all=全部，matches=筛选，suspicious=规则证据"
    )]
    ai_scope: AiScope,
    #[arg(
        long,
        value_enum,
        default_value = "text",
        value_name = "TYPE",
        help_heading = "报告输出",
        help = "主输出格式：text=终端摘要，json=完整 JSON，html=保存完整 HTML 文件"
    )]
    output: Output,
    #[arg(
        long,
        value_name = "PATH",
        help_heading = "报告输出",
        help = "主输出文件路径；省略时 text/json 输出到终端，html 自动保存为 report.html（已有文件时另取名称）"
    )]
    out: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help_heading = "报告输出",
        help = "额外保存完整 JSON 报告"
    )]
    json_out: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help_heading = "报告输出",
        help = "额外保存独立 HTML 报告"
    )]
    html_out: Option<PathBuf>,
    #[arg(
        long,
        default_value_t = 50,
        value_name = "N",
        help_heading = "报告输出",
        help = "终端各区来源、发现、记录、进程树、诊断及详情引用上限；0 显示全部，不裁剪 JSON/HTML"
    )]
    limit: usize,
    #[arg(
        long,
        help_heading = "报告输出",
        help = "显示发现解释、规则 ID、置信度、证据引用和原始记录；默认精简展示"
    )]
    raw: bool,
    #[arg(
        long,
        default_value_t = 512,
        value_name = "MB",
        help_heading = "输入限制",
        help = "每个输入文件大小上限（MiB）；超出时报错"
    )]
    max_file_mb: u64,
    #[arg(
        long,
        default_value_t = 1_000_000,
        value_name = "N",
        help_heading = "输入限制",
        help = "每个输入的记录数上限；超出时报错，不静默截断"
    )]
    max_records: usize,
}

#[derive(Args)]
pub struct LogLoadingArgs {
    #[arg(
        long,
        conflicts_with = "web_format_file",
        value_name = "FORMAT",
        help_heading = "Web 日志格式",
        help = "Apache LogFormat / Nginx log_format 定义或格式字符串"
    )]
    web_format: Option<String>,
    #[arg(
        long,
        value_name = "PATH",
        help_heading = "Web 日志格式",
        help = "从文件读取 Apache/Nginx 格式定义"
    )]
    web_format_file: Option<PathBuf>,
    #[arg(
        long,
        help_heading = "本机采集",
        help = "加载当前 Windows/Linux 主机常见日志；macOS 不支持"
    )]
    auto_load: bool,
    #[arg(
        long,
        default_value = "cases/captured",
        requires = "auto_load",
        value_name = "DIR",
        help_heading = "本机采集",
        help = "Windows 自动加载时，保存 wevtutil 导出的 EVTX"
    )]
    evidence_dir: PathBuf,
}

#[derive(Args)]
#[command(group(ArgGroup::new("source").args(["files", "auto_load", "live_processes", "project"]).required(true).multiple(true)))]
pub struct AnalyzeArgs {
    #[arg(
        value_name = "FILES",
        help_heading = "输入文件",
        help = "日志、进程快照、PCAP 文件；可混合多个文件，- 表示标准输入"
    )]
    files: Vec<PathBuf>,
    #[arg(long, default_value = "auto", value_name = "TYPE", help_heading = "输入文件", value_parser = all_formats(), help = "输入格式；auto 自动识别，指定其他值会作用于所有文件")]
    format: InputFormat,
    #[command(flatten)]
    loading: LogLoadingArgs,
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long, help_heading = "本机采集", help = "把当前主机进程加入分析")]
    live_processes: bool,
    #[arg(long, help_heading = "报告输出", help = "在终端报告中显示进程树")]
    tree: bool,
    #[arg(
        long,
        requires = "ai",
        help_heading = "AI 分析",
        help = "发送 PCAP 原始包与载荷；须与 --ai 同用"
    )]
    include_payload: bool,
}

#[derive(Args)]
#[command(group(ArgGroup::new("source").args(["files", "auto_load", "project"]).required(true).multiple(true)))]
pub struct LogArgs {
    #[arg(
        value_name = "FILES",
        help_heading = "输入文件",
        help = "一个或多个日志文件；- 表示标准输入"
    )]
    files: Vec<PathBuf>,
    #[arg(long, default_value = "auto", value_name = "TYPE", help_heading = "输入文件", value_parser = log_formats(), help = "日志格式；auto 自动识别，未知名称的二进制登录日志需指定")]
    format: InputFormat,
    #[command(flatten)]
    loading: LogLoadingArgs,
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
pub struct ProcessArgs {
    #[arg(
        value_name = "FILES",
        help_heading = "输入文件",
        help = "进程 JSON 快照或本工具报告；省略时采集本机，- 表示标准输入"
    )]
    files: Vec<PathBuf>,
    #[command(flatten)]
    common: CommonArgs,
    #[arg(
        long,
        help_heading = "报告输出",
        help = "显示进程树（本命令终端输出默认启用）"
    )]
    tree: bool,
}

#[derive(Args)]
pub struct PcapArgs {
    #[arg(
        required = true,
        value_name = "FILES",
        help_heading = "输入文件",
        help = "一个或多个 PCAP/PCAPNG 文件；- 表示标准输入"
    )]
    files: Vec<PathBuf>,
    #[command(flatten)]
    common: CommonArgs,
    #[arg(
        long,
        requires = "ai",
        help_heading = "AI 分析",
        help = "额外发送原始包与载荷；须与 --ai 同用"
    )]
    include_payload: bool,
}

fn all_formats() -> impl TypedValueParser<Value = InputFormat> {
    PossibleValuesParser::new([
        "auto",
        "evtx",
        "utmp",
        "wtmp",
        "btmp",
        "web",
        "text",
        "processes",
        "pcap",
        "pcapng",
    ])
    .map(|value| value.parse().expect("supported format"))
}
fn log_formats() -> impl TypedValueParser<Value = InputFormat> {
    PossibleValuesParser::new(["auto", "evtx", "utmp", "wtmp", "btmp", "web", "text"])
        .map(|value| value.parse().expect("supported log format"))
}

/// Use the same readable layout and localized help on every command level.
pub fn command() -> clap::Command {
    fn configure(command: clap::Command) -> clap::Command {
        let has_subcommands = command.get_subcommands().next().is_some();
        command
            .help_template(if has_subcommands {
                COMMAND_HELP_TEMPLATE
            } else {
                HELP_TEMPLATE
            })
            .arg_required_else_help(has_subcommands)
            .disable_help_subcommand(true)
            .disable_help_flag(true)
            .arg(
                Arg::new("help")
                    .short('h')
                    .long("help")
                    .action(ArgAction::Help)
                    .help("显示当前命令的帮助与示例")
                    .help_heading("通用选项"),
            )
            .mut_args(|arg| {
                let arg = if let Some((_, short)) = SHORT_OPTIONS
                    .iter()
                    .find(|(id, _)| *id == arg.get_id().as_str())
                {
                    arg.short(*short)
                } else {
                    arg
                };
                let order = match arg.get_id().as_str() {
                    "files" => 10,
                    "format" => 11,
                    "web_format" => 20,
                    "web_format_file" => 21,
                    "auto_load" => 30,
                    "evidence_dir" => 31,
                    "live_processes" => 32,
                    "query" => 40,
                    "regex" => 41,
                    "suspicious" => 42,
                    "config" => 50,
                    "ai" => 51,
                    "ai_scope" => 52,
                    "include_payload" => 53,
                    "tree" => 60,
                    "output" => 61,
                    "out" => 62,
                    "json_out" => 63,
                    "html_out" => 64,
                    "limit" => 65,
                    "raw" => 66,
                    "max_file_mb" => 70,
                    "max_records" => 71,
                    _ => 90,
                };
                let arg = if arg.get_id() == "files" {
                    arg.value_name("文件")
                } else {
                    arg
                };
                arg.display_order(order)
            })
            .mut_subcommands(configure)
    }
    configure(Cli::command()).disable_version_flag(true).arg(
        Arg::new("version")
            .short('V')
            .long("version")
            .action(ArgAction::Version)
            .display_order(91)
            .help("显示版本")
            .help_heading("通用选项"),
    )
}

/// Shared execution options; presentation stays specific to each subcommand.
pub struct AnalysisArgs {
    pub project: Option<PathBuf>,
    pub save_project: Option<PathBuf>,
    pub project_name: Option<String>,
    pub client: Option<String>,
    pub response_start: Option<String>,
    pub ioc: Vec<PathBuf>,
    pub ioc_value: Vec<String>,
    pub ioc_stdin: bool,
    pub ioc_stdin_csv: bool,
    pub ioc_exact_domain: bool,

    pub files: Vec<PathBuf>,
    pub format: InputFormat,
    pub web_format: Option<String>,
    pub web_format_file: Option<PathBuf>,
    pub auto_load: bool,
    pub live_processes: bool,
    pub evidence_dir: PathBuf,
    pub query: Option<String>,
    pub regex: bool,
    pub suspicious: bool,
    pub tree: bool,
    pub ai: bool,
    pub ai_scope: AiScope,
    pub include_payload: bool,
    pub output: Output,
    pub out: Option<PathBuf>,
    pub json_out: Option<PathBuf>,
    pub html_out: Option<PathBuf>,
    pub limit: usize,
    pub raw: bool,
    pub max_file_mb: u64,
    pub max_records: usize,
}
impl AnalysisArgs {
    pub fn new(files: Vec<PathBuf>, a: CommonArgs) -> Self {
        Self {
            project: a.project,
            save_project: a.save_project,
            project_name: a.project_name,
            client: a.client,
            response_start: a.response_start,
            ioc: a.ioc,
            ioc_value: a.ioc_value,
            ioc_stdin: a.ioc_stdin,
            ioc_stdin_csv: a.ioc_stdin_csv,
            ioc_exact_domain: a.ioc_exact_domain,
            files,
            format: InputFormat::Auto,
            web_format: None,
            web_format_file: None,
            auto_load: false,
            live_processes: false,
            evidence_dir: "cases/captured".into(),
            query: a.query,
            regex: a.regex,
            suspicious: a.suspicious,
            tree: false,
            ai: a.ai,
            ai_scope: a.ai_scope,
            include_payload: false,
            output: a.output,
            out: a.out,
            json_out: a.json_out,
            html_out: a.html_out,
            limit: a.limit,
            raw: a.raw,
            max_file_mb: a.max_file_mb,
            max_records: a.max_records,
        }
    }
    fn loading(&mut self, a: LogLoadingArgs) {
        self.web_format = a.web_format;
        self.web_format_file = a.web_format_file;
        self.auto_load = a.auto_load;
        self.evidence_dir = a.evidence_dir;
    }
}
impl From<AnalyzeArgs> for AnalysisArgs {
    fn from(a: AnalyzeArgs) -> Self {
        let mut result = Self::new(a.files, a.common);
        result.format = a.format;
        result.loading(a.loading);
        result.live_processes = a.live_processes;
        result.tree = a.tree;
        result.include_payload = a.include_payload;
        result
    }
}
impl From<LogArgs> for AnalysisArgs {
    fn from(a: LogArgs) -> Self {
        let mut result = Self::new(a.files, a.common);
        result.format = a.format;
        result.loading(a.loading);
        result
    }
}
impl From<ProcessArgs> for AnalysisArgs {
    fn from(a: ProcessArgs) -> Self {
        let mut result = Self::new(a.files, a.common);
        result.tree = a.tree;
        result
    }
}
impl From<PcapArgs> for AnalysisArgs {
    fn from(a: PcapArgs) -> Self {
        let mut result = Self::new(a.files, a.common);
        result.include_payload = a.include_payload;
        result
    }
}
