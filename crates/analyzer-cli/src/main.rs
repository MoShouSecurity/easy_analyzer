use analyzer_core::{
    AnalysisReport, IngestOptions, InputFormat, RecordData, ai, collect, report, rules,
};
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    version,
    about = "Rust 应急响应分析工具：日志、进程和离线 PCAP",
    long_about = "日志/进程/PCAP 证据分析。所有输入均在本地解析；只有显式指定 --ai 才发送数据到配置的服务。"
)]
struct Cli {
    #[arg(long, global = true, help = "AI 配置路径；默认位于用户配置目录")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// 自动识别多个文件并路由到日志、进程或流量模块
    Analyze(AnalysisArgs),
    /// 日志分析；--auto-load 读取本机常见日志路径
    Logs(AnalysisArgs),
    /// 进程快照分析；不提供文件时采集本机进程
    Processes(AnalysisArgs),
    /// PCAP/PCAPNG 离线分析
    Pcap(AnalysisArgs),
    /// 配置模板、查看设置或检查 AI 服务
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}
#[derive(Subcommand)]
enum ConfigCommand {
    Init,
    Show,
    Check,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Output {
    Text,
    Json,
    Html,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum AiScope {
    All,
    Matches,
    Suspicious,
}
#[derive(Args)]
struct AnalysisArgs {
    /// 输入文件；支持多个文件混合分析
    files: Vec<PathBuf>,
    #[arg(
        long,
        default_value = "auto",
        help = "auto/evtx/utmp/wtmp/btmp/web/text/processes/pcap"
    )]
    format: InputFormat,
    #[arg(
        long,
        conflicts_with = "web_format_file",
        help = "Apache LogFormat / Nginx log_format 定义或格式字符串"
    )]
    web_format: Option<String>,
    #[arg(long, help = "从文件读取服务格式定义")]
    web_format_file: Option<PathBuf>,
    #[arg(long, help = "加载本机常见日志；Windows 通过 wevtutil 导出")]
    auto_load: bool,
    #[arg(long, help = "采集当前主机进程")]
    live_processes: bool,
    #[arg(
        long,
        default_value = "cases/captured",
        help = "Windows 本机事件日志导出的保留目录"
    )]
    evidence_dir: PathBuf,
    #[arg(long, help = "查询关键词（默认不区分大小写）")]
    query: Option<String>,
    #[arg(long, requires = "query", help = "将 --query 解释为正则表达式")]
    regex: bool,
    #[arg(long, help = "终端显示所有本地规则匹配的证据记录")]
    suspicious: bool,
    #[arg(long, help = "显示进程树")]
    tree: bool,
    #[arg(long, help = "将选定证据直接发送到已配置的 AI 服务")]
    ai: bool,
    #[arg(
        long,
        value_enum,
        default_value = "all",
        requires = "ai",
        help = "AI 分析范围"
    )]
    ai_scope: AiScope,
    #[arg(
        long,
        requires = "ai",
        help = "AI 请求包含原始包和载荷；默认只发送解析后的包摘要"
    )]
    include_payload: bool,
    #[arg(long, value_enum, default_value = "text")]
    output: Output,
    #[arg(long, help = "主输出文件；省略时写到 stdout")]
    out: Option<PathBuf>,
    #[arg(long, help = "同时保存完整 JSON 报告")]
    json_out: Option<PathBuf>,
    #[arg(long, help = "同时保存完整 HTML 报告")]
    html_out: Option<PathBuf>,
    #[arg(long, default_value_t = 50, help = "终端显示记录/诊断数量；0 表示全部")]
    limit: usize,
    #[arg(long, default_value_t = 512, help = "每个输入文件大小上限 MiB")]
    max_file_mb: u64,
    #[arg(long, default_value_t = 1_000_000)]
    max_records: usize,
}
fn write_output(path: Option<&Path>, data: &str) -> Result<()> {
    if let Some(path) = path {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data).with_context(|| format!("cannot write {}", path.display()))?;
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(data.as_bytes())?;
        stdout.write_all(b"\n")?;
    }
    Ok(())
}
fn resolved_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for part in absolute.components() {
        match part {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            _ => normalized.push(part.as_os_str()),
        }
    }
    let mut ancestor = normalized.as_path();
    let mut tail = vec![];
    while !ancestor.exists() {
        tail.push(
            ancestor
                .file_name()
                .context("cannot resolve output path")?
                .to_os_string(),
        );
        ancestor = ancestor.parent().context("cannot resolve output parent")?;
    }
    let mut result = ancestor.canonicalize()?;
    for part in tail.into_iter().rev() {
        result.push(part);
    }
    Ok(result)
}
fn validate_outputs(args: &AnalysisArgs, config_path: &Path) -> Result<()> {
    let inputs: HashSet<_> = args
        .files
        .iter()
        .chain(args.web_format_file.iter())
        .filter(|p| p.as_os_str() != "-")
        .map(|p| resolved_path(p))
        .collect::<Result<_>>()?;
    let config = resolved_path(config_path)?;
    let mut outputs = HashSet::new();
    for path in [&args.out, &args.json_out, &args.html_out]
        .into_iter()
        .flatten()
    {
        let resolved = resolved_path(path)?;
        if inputs.contains(&resolved) || resolved == config {
            bail!(
                "output would overwrite an input/configuration: {}",
                path.display()
            );
        }
        if !outputs.insert(resolved) {
            bail!("report output paths must be distinct");
        }
    }
    Ok(())
}
fn run(cli: Cli) -> Result<bool> {
    let config_path = cli.config.unwrap_or_else(ai::default_config_path);
    let (mut args, kind) = match cli.command {
        Command::Analyze(a) => (a, "analyze"),
        Command::Logs(a) => (a, "logs"),
        Command::Processes(a) => (a, "processes"),
        Command::Pcap(a) => (a, "pcap"),
        Command::Config { command } => {
            match command {
                ConfigCommand::Init => {
                    ai::init_config(&config_path)?;
                    println!(
                        "Created {}\nEdit base_url/model; set the API key in the configured environment variable.",
                        config_path.display()
                    );
                }
                ConfigCommand::Show => {
                    println!(
                        "Configuration: {}\n{}",
                        config_path.display(),
                        toml_config(&ai::AiConfig::load(&config_path)?)
                    );
                }
                ConfigCommand::Check => {
                    ai::check(&ai::AiConfig::load(&config_path)?)?;
                    println!("AI connection and JSON response validation succeeded.");
                }
            }
            return Ok(true);
        }
    };
    if kind == "processes" && args.files.is_empty() {
        args.live_processes = true;
    }
    if args.files.is_empty() && !args.auto_load && !args.live_processes {
        bail!("provide input files, --auto-load or --live-processes");
    }
    if kind == "pcap" && (args.auto_load || args.live_processes) {
        bail!("pcap accepts capture files only");
    }
    if kind == "processes" && args.auto_load {
        bail!("use logs/analyze for --auto-load");
    }
    if matches!(args.ai_scope, AiScope::Matches) && args.query.is_none() && !args.suspicious {
        bail!("--ai-scope matches requires --query or --suspicious");
    }
    validate_outputs(&args, &config_path)?;
    if args.files.iter().filter(|p| p.as_os_str() == "-").count() > 1 {
        bail!("stdin (-) may only appear once");
    }
    if args.max_file_mb == 0 || args.max_records == 0 {
        bail!("input limits must be positive");
    }
    let web_format = if let Some(path) = &args.web_format_file {
        Some(fs::read_to_string(path)?)
    } else {
        args.web_format.clone()
    };
    if let Some(f) = &web_format {
        analyzer_core::web::WebParser::compile(f)?;
    }
    let opts = IngestOptions {
        format: if args.format == InputFormat::Auto {
            match kind {
                "processes" => InputFormat::Processes,
                "pcap" => InputFormat::Pcap,
                _ => InputFormat::Auto,
            }
        } else {
            args.format
        },
        web_format,
        max_file_bytes: args
            .max_file_mb
            .checked_mul(1024 * 1024)
            .context("file size limit overflow")?,
        max_records: args.max_records,
    };
    let mut report = AnalysisReport::default();
    let mut success = true;
    for path in &args.files {
        let result = if path.as_os_str() == "-" {
            let mut bytes = vec![];
            io::stdin()
                .lock()
                .take(opts.max_file_bytes.saturating_add(1))
                .read_to_end(&mut bytes)?;
            analyzer_core::ingest::ingest_bytes("stdin", &bytes, &opts)
        } else {
            analyzer_core::ingest_file(path, &opts)
        };
        match result {
            Ok(r) => {
                if kind == "logs"
                    && r.records
                        .iter()
                        .any(|r| !matches!(r.data, RecordData::Log(_)))
                {
                    success = false;
                    report.error(
                        path.to_string_lossy(),
                        None,
                        "input belongs to processes/pcap; use analyze for automatic routing",
                    );
                } else {
                    report.merge(r);
                }
            }
            Err(e) => {
                success = false;
                report.error(path.to_string_lossy(), None, format!("{e:#}"));
            }
        }
    }
    if args.auto_load {
        match collect::collect_common_logs(&opts, &args.evidence_dir) {
            Ok(r) => {
                if r.sources.is_empty() {
                    success = false;
                }
                report.merge(r);
            }
            Err(e) => {
                success = false;
                report.error("local logs", None, format!("{e:#}"));
            }
        }
    }
    if args.live_processes {
        match collect::collect_processes() {
            Ok(r) => report.merge(r),
            Err(e) => {
                success = false;
                report.error("local processes", None, format!("{e:#}"));
            }
        }
    }
    rules::analyze(&mut report);
    if let Some(query) = &args.query {
        report.query_matches = Some(rules::query(&report.records, query, args.regex)?);
    }
    let suspicious: HashSet<_> = report
        .findings
        .iter()
        .flat_map(|f| f.evidence_ids.iter().cloned())
        .collect();
    if args.suspicious {
        let matches = report
            .query_matches
            .as_ref()
            .map(|ids| ids.iter().map(String::as_str).collect::<HashSet<_>>());
        report.query_matches = Some(
            report
                .records
                .iter()
                .filter(|r| {
                    suspicious.contains(&r.id)
                        && matches
                            .as_ref()
                            .is_none_or(|ids| ids.contains(r.id.as_str()))
                })
                .map(|r| r.id.clone())
                .collect(),
        );
    }
    if args.ai {
        let matches = report
            .query_matches
            .as_ref()
            .map(|ids| ids.iter().map(String::as_str).collect::<HashSet<_>>());
        let selected: Vec<_> = report
            .records
            .iter()
            .filter(|r| match args.ai_scope {
                AiScope::All => true,
                AiScope::Matches => matches
                    .as_ref()
                    .is_some_and(|ids| ids.contains(r.id.as_str())),
                AiScope::Suspicious => suspicious.contains(&r.id),
            })
            .collect();
        let ai_result = ai::AiConfig::load(&config_path)
            .and_then(|config| ai::analyze(&selected, &config, args.include_payload));
        match ai_result {
            Ok((findings, run)) => {
                report.findings.extend(findings);
                report.ai_runs.push(run);
            }
            Err(e) => {
                success = false;
                report.error("AI", None, format!("{e:#}"));
            }
        }
    }
    for path in [&args.out, &args.json_out, &args.html_out]
        .into_iter()
        .flatten()
    {
        let resolved = resolved_path(path)?;
        for source in &report.sources {
            if !source.path.contains("://")
                && source.path != "stdin"
                && resolved_path(Path::new(&source.path))? == resolved
            {
                bail!(
                    "output would overwrite collected evidence: {}",
                    path.display()
                );
            }
        }
    }
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = &args.json_out {
        write_output(Some(path), &json)?;
    }
    if let Some(path) = &args.html_out {
        write_output(Some(path), &report::html(&report))?;
    }
    let output = match args.output {
        Output::Text => report::terminal(&report, args.limit, args.tree || kind == "processes"),
        Output::Json => json,
        Output::Html => report::html(&report),
    };
    write_output(args.out.as_deref(), &output)?;
    success &= !report
        .diagnostics
        .iter()
        .any(|d| d.level == analyzer_core::DiagnosticLevel::Error);
    if !success {
        eprintln!("Analysis completed with source/AI failures; see report diagnostics.");
    }
    Ok(success)
}
fn toml_config(c: &ai::AiConfig) -> String {
    serde_json::to_string_pretty(c).unwrap_or_default()
}
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
