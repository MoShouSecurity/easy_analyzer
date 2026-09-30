mod cli;
mod diagnostics;
mod progress;

use analyzer_app::{
    AnalysisInput, AnalysisMode, AnalysisRequest, AnalysisService, CancellationToken,
    ConfigService, DiagnosticLevel, ExecutionContext, ExportPlan, IngestOptions, OutputFormat,
    QueryOptions, RenderOptions, TaskStatus, core::execution::Stage,
};
use anyhow::{Context, Result, bail};
use clap::FromArgMatches;
use cli::{AnalysisArgs, Cli, Command, ConfigCommand, Output};
use std::{
    io::{self, Read, Write},
    process::ExitCode,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

// stdin belongs to the CLI adapter. A blocked pipe cannot prevent Ctrl+C from
// returning the partial analysis; the reading worker exits with this process.
fn read_stdin(limit: u64, ctx: &ExecutionContext) -> Result<Vec<u8>> {
    ctx.emit(Stage::Reading, Some("stdin"), 0, None);
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = vec![];
        let result = io::stdin()
            .lock()
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    loop {
        if ctx.cancellation.is_cancelled() {
            return Ok(vec![]);
        }
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => return Ok(result?),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn run(cli: Cli, cancellation: CancellationToken) -> Result<bool> {
    let config_path = cli.config.unwrap_or_else(ConfigService::default_path);
    let (args, mode) = match cli.command {
        Command::Analyze(a) => (AnalysisArgs::from(a), AnalysisMode::Mixed),
        Command::Logs(a) => (AnalysisArgs::from(a), AnalysisMode::Logs),
        Command::Processes(a) => (AnalysisArgs::from(a), AnalysisMode::Processes),
        Command::Pcap(a) => (AnalysisArgs::from(a), AnalysisMode::Pcap),
        Command::Config { command } => {
            match command {
                ConfigCommand::Init => {
                    ConfigService::create(&config_path)?;
                    println!(
                        "已创建配置 {}\n默认使用 DeepSeek deepseek-flash，请在配置文件中填写 api_key；其他服务可修改 base_url/model。",
                        config_path.display()
                    );
                }
                ConfigCommand::Show => println!(
                    "配置文件：{}\n{}",
                    config_path.display(),
                    ConfigService::redacted(&ConfigService::load(&config_path)?)?
                ),
                ConfigCommand::Check => {
                    ConfigService::check(&ConfigService::load(&config_path)?)?;
                    println!("AI 连接与 JSON 响应校验成功。");
                }
            }
            return Ok(true);
        }
    };
    let max_file_bytes = args
        .max_file_mb
        .checked_mul(1024 * 1024)
        .context("文件大小上限超出可表示范围")?;
    if args.files.iter().filter(|p| p.as_os_str() == "-").count() > 1 {
        bail!("标准输入（-）只能指定一次");
    }
    let mut request = AnalysisRequest {
        mode,
        inputs: args
            .files
            .iter()
            .map(|p| {
                if p.as_os_str() == "-" {
                    AnalysisInput::Bytes {
                        label: "stdin".into(),
                        bytes: Arc::from([]),
                    }
                } else {
                    AnalysisInput::File(p.clone())
                }
            })
            .collect(),
        ingest: IngestOptions {
            format: args.format,
            web_format: args.web_format,
            max_file_bytes,
            max_records: args.max_records,
        },
        web_format_file: args.web_format_file,
        auto_load: args.auto_load,
        live_processes: args.live_processes,
        evidence_dir: args.evidence_dir,
        query: if args.query.is_some() || args.suspicious {
            Some(QueryOptions {
                expression: args.query,
                regex: args.regex,
                suspicious: args.suspicious,
            })
        } else {
            None
        },
        ai: args.ai.then(|| analyzer_app::AiOptions {
            config_path: config_path.clone(),
            scope: match args.ai_scope {
                cli::AiScope::All => analyzer_app::AiScope::All,
                cli::AiScope::Matches => analyzer_app::AiScope::Matches,
                cli::AiScope::Suspicious => analyzer_app::AiScope::Suspicious,
            },
            include_payload: args.include_payload,
        }),
    };
    let export = ExportPlan {
        format: match args.output {
            Output::Text => OutputFormat::Text,
            Output::Json => OutputFormat::Json,
            Output::Html => OutputFormat::Html,
        },
        path: args.out,
        json_path: args.json_out,
        html_path: args.html_out,
        render: RenderOptions {
            limit: args.limit,
            raw: args.raw,
            tree: args.tree || mode == AnalysisMode::Processes,
        },
    };
    AnalysisService::validate(&request)?;
    export.validate_inputs(&request, &config_path)?;
    let animation: Arc<Mutex<Option<progress::AiProgress>>> = Arc::new(Mutex::new(None));
    let observer = animation.clone();
    let ctx = ExecutionContext::new(cancellation, move |event| {
        if matches!(event.stage, Stage::AiPreparing | Stage::Ai) {
            let mut animation = observer.lock().unwrap_or_else(|e| e.into_inner());
            let animation = animation.get_or_insert_with(progress::AiProgress::start);
            if event.stage == Stage::Ai {
                animation.batch(
                    event.completed,
                    event.total.unwrap_or(0),
                    event.attempt.unwrap_or(1),
                );
            }
        }
    });
    for input in &mut request.inputs {
        if let AnalysisInput::Bytes { label, bytes } = input
            && label == "stdin"
        {
            *bytes = read_stdin(max_file_bytes, &ctx)?.into();
        }
    }
    let outcome = AnalysisService::execute(&request, &ctx)?;
    if let Some(animation) = animation.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let complete = outcome.status != TaskStatus::Cancelled
            && outcome
                .session
                .with_report(|r| r.ai_runs.last().is_some_and(|run| run.is_complete()))?;
        animation.finish(complete);
    }
    let exported = export.save(&outcome.session, &config_path)?;
    for path in &exported.saved_paths {
        eprintln!("报告已保存：{}", path.display());
    }
    if let Some(output) = exported.stdout {
        let mut stdout = io::stdout().lock();
        stdout.write_all(output.as_bytes())?;
        stdout.write_all(b"\n")?;
    }
    let success = outcome.status == TaskStatus::Completed;
    if !success {
        if export.format == OutputFormat::Text && export.path.is_none() {
            eprintln!("分析部分完成，错误原因见上方诊断。");
        } else {
            eprintln!("分析部分完成，具体原因：");
            outcome.session.with_report(|report| {
                let errors: Vec<_> = report
                    .diagnostics
                    .iter()
                    .filter(|d| d.level == DiagnosticLevel::Error)
                    .collect();
                let shown = if args.limit == 0 {
                    errors.len()
                } else {
                    errors.len().min(args.limit)
                };
                for diagnostic in errors.iter().take(shown) {
                    let position = diagnostic
                        .position
                        .as_ref()
                        .map(|p| format!("/{p}"))
                        .unwrap_or_default();
                    eprintln!(
                        "  {}{}：{}",
                        diagnostic.source, position, diagnostic.message
                    );
                }
                if errors.len() > shown || errors.is_empty() {
                    eprintln!("完整原因见报告中的诊断信息。");
                }
            })?;
        }
    }
    Ok(success)
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
    let token = CancellationToken::default();
    let signal_token = token.clone();
    if let Err(error) = ctrlc::set_handler(move || signal_token.cancel()) {
        eprintln!("错误：无法安装取消处理：{error}");
        return ExitCode::FAILURE;
    }
    match run(cli, token) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("错误：{error:#}");
            ExitCode::FAILURE
        }
    }
}
