mod cli;
mod diagnostics;

use analyzer_core::{
    AnalysisReport, IngestOptions, InputFormat, RecordData, ai, collect, report, rules,
};
use anyhow::{Context, Result, bail};
use clap::FromArgMatches;
use cli::{AiScope, AnalysisArgs, Cli, Command, ConfigCommand, Output};
use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

fn write_output(path: Option<&Path>, data: &str) -> Result<()> {
    if let Some(path) = path {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data).with_context(|| format!("无法写入报告 {}", path.display()))?;
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
                .context("无法解析报告输出路径")?
                .to_os_string(),
        );
        ancestor = ancestor.parent().context("无法解析报告输出的父目录")?;
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
            bail!("报告输出会覆盖输入文件或配置：{}", path.display());
        }
        if !outputs.insert(resolved) {
            bail!("各个报告输出路径必须不同");
        }
    }
    Ok(())
}
fn run(cli: Cli) -> Result<bool> {
    let config_path = cli.config.unwrap_or_else(ai::default_config_path);
    let (mut args, kind) = match cli.command {
        Command::Analyze(a) => (AnalysisArgs::from(a), "analyze"),
        Command::Logs(a) => (AnalysisArgs::from(a), "logs"),
        Command::Processes(a) => (AnalysisArgs::from(a), "processes"),
        Command::Pcap(a) => (AnalysisArgs::from(a), "pcap"),
        Command::Config { command } => {
            match command {
                ConfigCommand::Init => {
                    ai::init_config(&config_path)?;
                    println!(
                        "已创建配置 {}\n默认使用 DeepSeek deepseek-flash，请在配置文件中填写 api_key；其他服务可修改 base_url/model。",
                        config_path.display()
                    );
                }
                ConfigCommand::Show => {
                    println!(
                        "配置文件：{}\n{}",
                        config_path.display(),
                        toml_config(&ai::AiConfig::load(&config_path)?)
                    );
                }
                ConfigCommand::Check => {
                    ai::check(&ai::AiConfig::load(&config_path)?)?;
                    println!("AI 连接与 JSON 响应校验成功。");
                }
            }
            return Ok(true);
        }
    };
    if kind == "processes" && args.files.is_empty() {
        args.live_processes = true;
    }
    if args.files.is_empty() && !args.auto_load && !args.live_processes {
        bail!("请提供输入文件，或指定 --auto-load / --live-processes");
    }
    if kind == "pcap" && (args.auto_load || args.live_processes) {
        bail!("pcap 命令只接受离线抓包文件");
    }
    if kind == "processes" && args.auto_load {
        bail!("请在 logs/analyze 命令中使用 --auto-load");
    }
    if matches!(args.ai_scope, AiScope::Matches) && args.query.is_none() && !args.suspicious {
        bail!("--ai-scope matches 需要同时提供 --query 或 --suspicious");
    }
    validate_outputs(&args, &config_path)?;
    if args.files.iter().filter(|p| p.as_os_str() == "-").count() > 1 {
        bail!("标准输入（-）只能指定一次");
    }
    if args.max_file_mb == 0 || args.max_records == 0 {
        bail!("文件大小和记录数上限必须大于 0");
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
            .context("文件大小上限超出可表示范围")?,
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
                        "该输入属于进程快照或抓包文件，请使用 analyze 自动分类",
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
                bail!("报告输出会覆盖已采集的证据：{}", path.display());
            }
        }
    }
    report
        .findings
        .sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    let json = if matches!(args.output, Output::Json) || args.json_out.is_some() {
        Some(serde_json::to_string_pretty(&report)?)
    } else {
        None
    };
    if let Some(path) = &args.json_out {
        write_output(Some(path), json.as_deref().context("无法生成 JSON 报告")?)?;
    }
    if let Some(path) = &args.html_out {
        write_output(Some(path), &report::html(&report))?;
    }
    let output = match args.output {
        Output::Text => report::terminal_with_raw(
            &report,
            args.limit,
            args.tree || kind == "processes",
            args.raw,
        ),
        Output::Json => json.context("无法生成 JSON 报告")?,
        Output::Html => report::html(&report),
    };
    write_output(args.out.as_deref(), &output)?;
    success &= !report
        .diagnostics
        .iter()
        .any(|d| d.level == analyzer_core::DiagnosticLevel::Error);
    if !success {
        eprintln!("分析已完成，但部分来源或 AI 分析失败；请查看报告中的诊断信息。");
    }
    Ok(success)
}
fn toml_config(c: &ai::AiConfig) -> String {
    let mut visible = c.clone();
    if !visible.api_key.is_empty() {
        visible.api_key = "[已配置，密钥已隐藏]".into();
    }
    if visible.api_key_env.starts_with("sk-") {
        visible.api_key_env = "[密钥已隐藏，请改用 api_key]".into();
    }
    serde_json::to_string_pretty(&visible).unwrap_or_default()
}
fn main() -> ExitCode {
    let matches = match cli::command().try_get_matches() {
        Ok(matches) => matches,
        Err(error) => return diagnostics::report(error),
    };
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => return diagnostics::report(error),
    };
    match run(cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("错误：{e:#}");
            ExitCode::FAILURE
        }
    }
}
