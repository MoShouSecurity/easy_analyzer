mod cli;
mod diagnostics;
mod progress;
mod projects;

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
        Command::Project { command } => {
            match projects::command(
                command,
                &config_path,
                &ExecutionContext::new(cancellation.clone(), |_| {}),
            )? {
                Some(args) => (args, AnalysisMode::Mixed),
                None => return Ok(true),
            }
        }
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
    if args.ioc_stdin && args.files.iter().any(|p| p.as_os_str() == "-") {
        bail!("IOC 和证据不能同时使用标准输入");
    }
    let has_ioc = !args.ioc.is_empty() || !args.ioc_value.is_empty() || args.ioc_stdin;
    let project_session = if let Some(path) = &args.project {
        let session = analyzer_app::ProjectService::open(
            path,
            &ExecutionContext::new(cancellation.clone(), |_| {}),
        )?;
        projects::catalog()?.register(&session)?;
        Some(session)
    } else if args.save_project.is_some() || has_ioc {
        let name = if args.save_project.is_some() {
            args.project_name
                .as_deref()
                .context("保存新项目需要 --project-name")?
        } else {
            "临时分析"
        };
        let client = if args.save_project.is_some() {
            args.client.as_deref().context("保存新项目需要 --client")?
        } else {
            "临时会话"
        };
        let mut info = analyzer_app::ProjectInfo::new(name, client);
        if let Some(start) = &args.response_start {
            info.response_start = start.clone();
        }
        Some(analyzer_app::ProjectService::create(info)?)
    } else {
        None
    };
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
    if !request.inputs.is_empty()
        || request.auto_load
        || request.live_processes
        || project_session.is_none()
    {
        AnalysisService::validate(&request)?;
    }
    export.validate_inputs(&request, &config_path)?;
    let mut protected = args.ioc.clone();
    protected.extend(args.project.iter().cloned());
    export.validate_additional_inputs(&protected, &config_path)?;
    if let Some(session) = &project_session {
        export.validate_session(session, &config_path)?;
    }
    if let Some(save) = &args.save_project {
        if let Some(session) = &project_session {
            analyzer_app::ProjectService::validate_target(session, save, &config_path)?;
        }
        let mut outputs = vec![save.clone()];
        outputs.extend(
            [&export.path, &export.json_path, &export.html_path]
                .into_iter()
                .flatten()
                .cloned(),
        );
        analyzer_app::export::validate_output_paths(&outputs, &args.ioc)?;
    }

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
    let outcome = if let Some(session) = project_session {
        let mut outcome = analyzer_app::AnalysisOutcome {
            session: session.clone(),
            status: TaskStatus::Completed,
        };
        if !request.inputs.is_empty() || request.auto_load || request.live_processes {
            outcome = analyzer_app::ProjectService::append(&session, &request, &ctx)?;
        }
        let mut sources: Vec<analyzer_app::IocSource> = args
            .ioc
            .iter()
            .cloned()
            .map(analyzer_app::IocSource::File)
            .collect();
        sources.extend(
            args.ioc_value
                .iter()
                .map(|value| analyzer_app::IocSource::Value {
                    value: value.clone(),
                    kind: None,
                    note: String::new(),
                }),
        );
        if args.ioc_stdin {
            sources.push(analyzer_app::IocSource::Text {
                text: String::from_utf8(read_stdin(64 * 1024 * 1024, &ctx)?)?,
                csv: args.ioc_stdin_csv,
                origin: "stdin".into(),
            });
        }
        if !sources.is_empty() {
            let imported = analyzer_app::IocService::import(&session, &sources, &ctx)?;
            for issue in imported.issues {
                eprintln!("IOC 第 {} 行：{}", issue.line, issue.message);
            }
        }
        if has_ioc {
            let run = analyzer_app::IocService::scan(&session, !args.ioc_exact_domain, &ctx)?;
            if !run.complete {
                outcome.status = TaskStatus::Cancelled;
            }
        }
        let query = request
            .query
            .clone()
            .or(analyzer_app::ProjectService::query_options(&session)?);
        if let Some(query) = &query {
            let selection = session.query(query, &ctx)?;
            session.set_selection(Some(&selection), &ctx)?;
            analyzer_app::ProjectService::save_query_options(&session, query)?;
        }
        if let Some(ai) = &request.ai
            && !ctx.cancellation.is_cancelled()
        {
            outcome = AnalysisService::analyze_ai(&session, ai, None, &ctx)?;
        }
        if let Some(path) = &args.save_project {
            let save_ctx = if ctx.cancellation.is_cancelled() {
                ExecutionContext::default()
            } else {
                ctx.clone()
            };
            analyzer_app::ProjectService::save(&session, path, &config_path, false, &save_ctx)?;
            projects::catalog()?.register(&session)?;
            eprintln!("项目已保存：{}", path.display());
        }
        outcome
    } else {
        AnalysisService::execute(&request, &ctx)?
    };
    if let Some(animation) = animation.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let complete = outcome.status != TaskStatus::Cancelled
            && outcome
                .session
                .ai_run_headers()?
                .last()
                .is_some_and(|run| run.is_complete());
        animation.finish(complete);
    }
    // Project JSON output goes directly to stdout; never allocate the complete report string.
    let direct_stdout = outcome.session.is_project()
        && export.path.is_none()
        && export.format != OutputFormat::Html;
    let exported = if direct_stdout {
        let saved = export.save_artifacts(&outcome.session, &config_path)?;
        export.write_primary(
            &outcome.session,
            &mut io::stdout().lock(),
            &ExecutionContext::default(),
        )?;
        saved
    } else {
        export.save(&outcome.session, &config_path)?
    };
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
            let diagnostics = outcome
                .session
                .diagnostic_page(0, args.limit.clamp(1, 1000))?;
            for diagnostic in diagnostics
                .items
                .iter()
                .filter(|d| d.level == DiagnosticLevel::Error)
            {
                eprintln!("  {}：{}", diagnostic.source, diagnostic.message);
            }
            eprintln!("完整原因见报告中的诊断信息。");
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
