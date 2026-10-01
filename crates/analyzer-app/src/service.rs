use crate::{
    AiOptions, AiScope, AnalysisInput, AnalysisMode, AnalysisOutcome, AnalysisRequest,
    AnalysisSession, ConfigService, RecordSelection, TaskStatus,
    core::{
        self, AnalysisReport, DiagnosticLevel, InputFormat, RecordData,
        execution::{ExecutionContext, ReportOutcome, Stage, is_cancelled},
    },
};
use anyhow::{Result, anyhow, bail};
use std::{fs, path::PathBuf};

pub struct AnalysisService;
impl AnalysisService {
    pub fn validate(request: &AnalysisRequest) -> Result<()> {
        if request.inputs.is_empty()
            && !request.auto_load
            && !request.live_processes
            && request.mode != AnalysisMode::Processes
        {
            bail!("请提供输入文件，或指定 --auto-load / --live-processes");
        }
        if request.mode == AnalysisMode::Pcap && (request.auto_load || request.live_processes) {
            bail!("pcap 命令只接受离线抓包文件");
        }
        if request.mode == AnalysisMode::Processes && request.auto_load {
            bail!("请在 logs/analyze 命令中使用 --auto-load");
        }
        if request.ingest.max_file_bytes == 0 || request.ingest.max_records == 0 {
            bail!("文件大小和记录数上限必须大于 0");
        }
        if request.web_format_file.is_some() && request.ingest.web_format.is_some() {
            bail!("Web 格式字符串和格式文件只能指定一个");
        }
        if let Some(query) = &request.query
            && query.regex
            && query.expression.is_none()
        {
            bail!("正则查询需要表达式");
        }
        if request
            .ai
            .as_ref()
            .is_some_and(|a| a.scope == AiScope::Matches)
            && request
                .query
                .as_ref()
                .is_none_or(|q| q.expression.is_none() && !q.suspicious)
        {
            bail!("--ai-scope matches 需要同时提供 --query 或 --suspicious");
        }
        Ok(())
    }

    /// Import and local analysis only; retain the session for later queries/AI.
    pub fn load(request: &AnalysisRequest, ctx: &ExecutionContext) -> Result<AnalysisOutcome> {
        Self::validate(request)?;
        let mut protected: Vec<PathBuf> = request
            .inputs
            .iter()
            .filter_map(|i| {
                if let AnalysisInput::File(p) = i {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .collect();
        protected.extend(request.web_format_file.iter().cloned());
        if let Some(ai) = &request.ai {
            protected.push(ai.config_path.clone());
        }
        let mut report = AnalysisReport::default();
        if ctx.cancellation.is_cancelled() {
            return Ok(cancelled_report(report, protected));
        }
        let mut options = request.ingest.clone();
        if let Some(path) = &request.web_format_file {
            options.web_format = Some(fs::read_to_string(path)?);
        }
        if let Some(format) = &options.web_format {
            core::web::WebParser::compile(format)?;
        }
        if options.format == InputFormat::Auto {
            options.format = match request.mode {
                AnalysisMode::Processes => InputFormat::Processes,
                AnalysisMode::Pcap => InputFormat::Pcap,
                _ => InputFormat::Auto,
            };
        }
        for input in &request.inputs {
            if ctx.cancellation.is_cancelled() {
                return Ok(cancelled_report(report, protected));
            }
            let parsed = match input {
                AnalysisInput::File(path) => {
                    core::ingest::ingest_file_with_context(path, &options, ctx)
                }
                AnalysisInput::Bytes { label, bytes } => {
                    core::ingest::ingest_bytes_with_context(label, bytes, &options, ctx)
                }
            };
            match parsed {
                Ok(outcome) => {
                    if request.mode == AnalysisMode::Logs
                        && outcome
                            .report
                            .records
                            .iter()
                            .any(|r| !matches!(r.data, RecordData::Log(_)))
                    {
                        report.error(
                            input.label(),
                            None,
                            "该输入属于进程快照或抓包文件，请使用 analyze 自动分类",
                        );
                    } else {
                        report.merge(outcome.report);
                    }
                    if outcome.cancelled {
                        return Ok(cancelled_report(report, protected));
                    }
                }
                Err(error) => report.error(input.label(), None, format!("{error:#}")),
            }
        }
        if request.auto_load
            && collect(
                &mut report,
                core::collect::collect_common_logs_with_context(
                    &options,
                    &request.evidence_dir,
                    ctx,
                ),
                "local logs",
            )
        {
            return Ok(cancelled_report(report, protected));
        }
        let live_processes = request.live_processes
            || (request.mode == AnalysisMode::Processes && request.inputs.is_empty());
        if live_processes
            && collect(
                &mut report,
                core::collect::collect_processes_with_context(ctx),
                "local processes",
            )
        {
            return Ok(cancelled_report(report, protected));
        }
        if let Err(error) = core::rules::analyze_with_context(&mut report, ctx) {
            if is_cancelled(&error) {
                return Ok(cancelled_report(report, protected));
            }
            return Err(error);
        }
        report
            .findings
            .sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
        let session = AnalysisSession::new(report, protected);
        if ctx.cancellation.is_cancelled() {
            mark_cancelled(&session)?;
            return Ok(AnalysisOutcome {
                session,
                status: TaskStatus::Cancelled,
            });
        }
        Ok(AnalysisOutcome {
            status: status(&session)?,
            session,
        })
    }

    pub fn execute(request: &AnalysisRequest, ctx: &ExecutionContext) -> Result<AnalysisOutcome> {
        let mut outcome = Self::load(request, ctx)?;
        if outcome.status == TaskStatus::Cancelled {
            return Ok(outcome);
        }
        if let Some(query) = &request.query {
            match outcome
                .session
                .query(query, ctx)
                .and_then(|selection| outcome.session.set_selection(Some(&selection), ctx))
            {
                Ok(()) => {}
                Err(error) if is_cancelled(&error) => {
                    mark_cancelled(&outcome.session)?;
                    outcome.status = TaskStatus::Cancelled;
                    return Ok(outcome);
                }
                Err(error) => return Err(error),
            }
        }
        if let Some(ai) = &request.ai {
            let mut ai_outcome = Self::analyze_ai(&outcome.session, ai, None, ctx)?;
            if outcome.status == TaskStatus::Partial && ai_outcome.status == TaskStatus::Completed {
                ai_outcome.status = TaskStatus::Partial;
            }
            return Ok(ai_outcome);
        }
        ctx.emit(Stage::Finalizing, None, 0, None);
        if ctx.cancellation.is_cancelled() {
            mark_cancelled(&outcome.session)?;
            outcome.status = TaskStatus::Cancelled;
        }
        Ok(outcome)
    }

    /// Evidence references remain borrowed, not cloned, during a request. Read
    /// pagination stays available; only this operation may commit session changes.
    pub fn analyze_ai(
        session: &AnalysisSession,
        options: &AiOptions,
        selection: Option<&RecordSelection>,
        ctx: &ExecutionContext,
    ) -> Result<AnalysisOutcome> {
        Self::analyze_ai_impl(session, options, selection, None, ctx)
    }

    /// Use the settings displayed by an interactive frontend. The caller freezes
    /// this value at task start; no later config-file edit changes the request.
    pub fn analyze_ai_with_config(
        session: &AnalysisSession,
        options: &AiOptions,
        selection: Option<&RecordSelection>,
        config: &core::ai::AiConfig,
        ctx: &ExecutionContext,
    ) -> Result<AnalysisOutcome> {
        Self::analyze_ai_impl(session, options, selection, Some(config), ctx)
    }

    fn analyze_ai_impl(
        session: &AnalysisSession,
        options: &AiOptions,
        selection: Option<&RecordSelection>,
        config: Option<&core::ai::AiConfig>,
        ctx: &ExecutionContext,
    ) -> Result<AnalysisOutcome> {
        if let Some(selection) = selection {
            session.validate_selection(selection)?;
        }
        let _operation = session.lock_operation(ctx)?;
        ctx.emit(Stage::AiPreparing, None, 0, None);
        let result = session.with_report(|report| {
            let ids = match options.scope {
                AiScope::All => None,
                AiScope::Matches => {
                    let ids = selection
                        .map(|s| s.ids.clone())
                        .or_else(|| report.query_matches.clone())
                        .ok_or_else(|| anyhow!("AI matches 需要查询结果"))?;
                    Some(ids.into_iter().collect::<std::collections::HashSet<_>>())
                }
                AiScope::Suspicious => Some(session.0.local_suspicious.clone()),
            };
            let mut records = vec![];
            for (i, record) in report.records.iter().enumerate() {
                ctx.tick(Stage::AiPreparing, None, i, Some(report.records.len()))?;
                if ids.as_ref().is_none_or(|ids| ids.contains(&record.id)) {
                    records.push(record);
                }
            }
            let config = match config {
                Some(config) => {
                    config.validate()?;
                    config.clone()
                }
                None => ConfigService::load(&options.config_path)?,
            };
            core::ai::analyze_report_with_context(
                &records,
                &config,
                options.include_payload,
                ctx,
                |_, _, _| {},
            )
        })?;
        let mut report = session
            .0
            .report
            .write()
            .map_err(|_| anyhow!("分析会话写入失败"))?;
        let mut cancelled = ctx.cancellation.is_cancelled();
        let mut failed = false;
        match result {
            Ok(controlled) => {
                cancelled |= controlled.cancelled;
                let mut analysis = controlled.analysis;
                // Repeated AI actions retain separate runs and unique finding IDs.
                if !report.ai_runs.is_empty() {
                    let run = report.ai_runs.len() + 1;
                    for finding in &mut analysis.findings {
                        finding.id = format!("ai:run:{run}:{}", finding.id);
                    }
                }
                report.findings.extend(analysis.findings);
                report.ai_runs.push(analysis.run);
                if let Some(error) = analysis.error {
                    failed = true;
                    report.error("AI", None, error);
                }
            }
            Err(error) => {
                failed = true;
                report.error("AI", None, format!("{error:#}"));
            }
        }
        if cancelled {
            add_cancelled(&mut report);
        }
        report
            .findings
            .sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
        drop(report);
        ctx.emit(Stage::Finalizing, None, 0, None);
        if ctx.cancellation.is_cancelled() && !cancelled {
            mark_cancelled(session)?;
            cancelled = true;
        }
        Ok(AnalysisOutcome {
            session: session.clone(),
            status: if cancelled {
                TaskStatus::Cancelled
            } else if failed {
                TaskStatus::Partial
            } else {
                TaskStatus::Completed
            },
        })
    }
}

fn collect(report: &mut AnalysisReport, outcome: Result<ReportOutcome>, label: &str) -> bool {
    match outcome {
        Ok(outcome) => {
            report.merge(outcome.report);
            outcome.cancelled
        }
        Err(error) if is_cancelled(&error) => true,
        Err(error) => {
            report.error(label, None, format!("{error:#}"));
            false
        }
    }
}
fn add_cancelled(report: &mut AnalysisReport) {
    if !report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("已取消"))
    {
        report.error(
            "task",
            None,
            "分析已取消；已完成结果保留，当前分析范围不完整。",
        );
    }
}
fn mark_cancelled(session: &AnalysisSession) -> Result<()> {
    let mut report = session
        .0
        .report
        .write()
        .map_err(|_| anyhow!("分析会话写入失败"))?;
    add_cancelled(&mut report);
    Ok(())
}
fn cancelled_report(mut report: AnalysisReport, protected: Vec<PathBuf>) -> AnalysisOutcome {
    add_cancelled(&mut report);
    AnalysisOutcome {
        session: AnalysisSession::new(report, protected),
        status: TaskStatus::Cancelled,
    }
}
fn status(session: &AnalysisSession) -> Result<TaskStatus> {
    session.with_report(|report| {
        if report
            .diagnostics
            .iter()
            .any(|d| d.level == DiagnosticLevel::Error)
        {
            TaskStatus::Partial
        } else {
            TaskStatus::Completed
        }
    })
}
