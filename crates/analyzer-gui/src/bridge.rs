use crate::{Args, model::*};
use analyzer_app::{
    core::{
        self,
        execution::{Stage, is_cancelled},
    },
    *,
};
use anyhow::{Result, anyhow, bail};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

type Rpc<T> = std::result::Result<T, String>;
fn rpc<T>(r: Result<T>) -> Rpc<T> {
    r.map_err(|e| format!("{e:#}"))
}
#[derive(Clone)]
pub struct Desktop(pub Arc<Mutex<Inner>>);
pub struct Inner {
    pub session: Option<AnalysisSession>,
    pub epoch: u64,
    pub latest_view: u64,
    pub read_cancel: Option<CancellationToken>,
    pub selection: Option<RecordSelection>,
    pub selection_info: SelectionInfo,
    pub next_selection: u64,
    pub prefs: Preferences,
    pub config: core::ai::AiConfig,
    pub config_loaded: bool,
    pub config_error: Option<String>,
    pub initialized: bool,
    pub busy: Option<TaskMessage>,
    pub cancel: Option<Arc<dyn Fn() + Send + Sync>>,
    pub data_dir: PathBuf,
    pub args: Args,
    pub elevation_pending: bool,
}
impl Desktop {
    pub fn new(data_dir: PathBuf, args: Args) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            session: None,
            epoch: 0,
            latest_view: 0,
            read_cancel: None,
            selection: None,
            selection_info: Default::default(),
            next_selection: 0,
            prefs: Default::default(),
            config: Default::default(),
            config_loaded: false,
            config_error: None,
            initialized: false,
            busy: None,
            cancel: None,
            data_dir,
            args,
            elevation_pending: false,
        })))
    }
    pub fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        self.0.lock().map_err(|_| anyhow!("界面状态不可用"))
    }
    pub fn session(&self, id: u64) -> Result<AnalysisSession> {
        self.lock()?
            .session
            .clone()
            .filter(|s| s.id() == id)
            .ok_or_else(|| anyhow!("会话已变化，请刷新视图"))
    }
}
fn status_name(s: TaskStatus) -> String {
    match s {
        TaskStatus::Running => "running",
        TaskStatus::Cancelling => "cancelling",
        TaskStatus::Completed => "completed",
        TaskStatus::Partial => "partial",
        TaskStatus::Cancelled => "cancelled",
        TaskStatus::Failed => "failed",
    }
    .into()
}
fn stage_name(s: Stage) -> String {
    match s {
        Stage::Reading => "读取文件",
        Stage::Hashing => "计算哈希",
        Stage::Parsing => "解析证据",
        Stage::Collecting => "本机采集",
        Stage::Rules => "本地规则",
        Stage::Query => "筛选记录",
        Stage::Flows => "网络会话",
        Stage::AiPreparing => "准备 AI 证据",
        Stage::Ai => "AI 批次",
        Stage::Finalizing => "整理结果",
    }
    .into()
}
fn bootstrap_value(s: &Inner) -> Bootstrap {
    let (elevated, elevation_error) = crate::elevation::status();
    Bootstrap {
        preferences: s.prefs.clone(),
        config: PublicConfig::from(&s.config),
        config_loaded: s.config_loaded,
        config_error: s.config_error.clone(),
        session_id: s.session.as_ref().map(AnalysisSession::id),
        selection: s.selection_info.clone(),
        busy: s.busy.clone(),
        platform: std::env::consts::OS.into(),
        elevated,
        elevation_error,
        live_processes: s.args.live_processes,
        capture_dir: s.data_dir.join("captured").display().to_string(),
        inputs: s
            .args
            .inputs
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        qa: s.args.qa,
        qa_ai: s.args.qa_ai,
    }
}
fn atomic_preferences(path: &Path, prefs: &Preferences) -> Result<()> {
    use std::io::Write;
    fs::create_dir_all(path.parent().ok_or_else(|| anyhow!("偏好目录不存在"))?)?;
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    file.write_all(&serde_json::to_vec_pretty(prefs)?)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[tauri::command]
pub async fn request_elevation(
    state: State<'_, Desktop>,
) -> Rpc<crate::elevation::ElevationResult> {
    let desktop = state.inner().clone();
    {
        let mut s = desktop.lock().map_err(|e| e.to_string())?;
        if s.busy.is_some() || s.elevation_pending {
            return Err("请等待当前任务或 UAC 授权完成".into());
        }
        s.elevation_pending = true;
    }
    let result = tauri::async_runtime::spawn_blocking(crate::elevation::request_admin_window).await;
    if let Ok(mut s) = desktop.lock() {
        s.elevation_pending = false;
    }
    rpc(result
        .map_err(|e| anyhow!("Windows 提权任务失败：{e}"))
        .and_then(|value| value))
}
#[tauri::command]
pub async fn initialize(app: AppHandle, state: State<'_, Desktop>) -> Rpc<Bootstrap> {
    let desktop = state.inner().clone();
    rpc(
        tauri::async_runtime::spawn_blocking(move || -> Result<Bootstrap> {
            let mut s = desktop.lock()?;
            if !s.initialized {
                if !s.args.temporary && !s.args.qa {
                    let path = s.data_dir.join("preferences.json");
                    if path.exists() {
                        s.prefs = serde_json::from_slice(&fs::read(path)?)?;
                    }
                }
                if let Some(path) = &s.args.config {
                    s.prefs.config_path = path.display().to_string();
                }
                if s.prefs.config_path.is_empty() {
                    s.prefs.config_path = s.data_dir.join("config.toml").display().to_string();
                }
                if s.args.qa {
                    s.prefs.dark = false;
                    s.prefs.inspector = true;
                    s.prefs.inspector_width = 320.;
                }
                s.prefs.inspector_width = s.prefs.inspector_width.clamp(280., 440.);
                if Path::new(&s.prefs.config_path).exists() {
                    match ConfigService::load(Path::new(&s.prefs.config_path)) {
                        Ok(c) => {
                            s.config = c;
                            s.config_loaded = true;
                        }
                        Err(e) => s.config_error = Some(format!("配置读取失败：{e:#}")),
                    }
                }
                s.initialized = true;
            }
            let result = bootstrap_value(&s);
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_theme(Some(if s.prefs.dark {
                    tauri::Theme::Dark
                } else {
                    tauri::Theme::Light
                }));
                if !s.args.temporary && !s.args.qa {
                    let _ = window.set_size(tauri::LogicalSize::new(
                        s.prefs.window_width.clamp(960., 8192.),
                        s.prefs.window_height.clamp(600., 4320.),
                    ));
                }
            }
            Ok(result)
        })
        .await
        .map_err(|e| e.to_string())?,
    )
}
#[tauri::command]
pub async fn save_preferences(
    app: AppHandle,
    state: State<'_, Desktop>,
    mut preferences: Preferences,
) -> Rpc<()> {
    let desktop = state.inner().clone();
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_theme(Some(if preferences.dark {
            tauri::Theme::Dark
        } else {
            tauri::Theme::Light
        }));
        if let (Ok(size), Ok(scale)) = (w.inner_size(), w.scale_factor()) {
            preferences.window_width = size.width as f64 / scale;
            preferences.window_height = size.height as f64 / scale;
        }
    }
    rpc(tauri::async_runtime::spawn_blocking(move || -> Result<()> {
        preferences.inspector_width = preferences.inspector_width.clamp(280., 440.);
        let mut s = desktop.lock()?;
        s.prefs = preferences;
        let prefs = s.prefs.clone();
        let path = s.data_dir.join("preferences.json");
        let temporary = s.args.temporary || s.args.qa;
        drop(s);
        if !temporary {
            atomic_preferences(&path, &prefs)?;
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?)
}

pub enum WorkerResult {
    Outcome(AnalysisOutcome),
    Config(core::ai::AiConfig),
    Saved(Vec<PathBuf>),
    Checked,
}
fn start_job(
    app: AppHandle,
    desktop: Desktop,
    kind: &str,
    label: &str,
    run: impl FnOnce(&ExecutionContext) -> Result<WorkerResult> + Send + 'static,
) -> Result<TaskMessage> {
    let mut s = desktop.lock()?;
    if s.busy.is_some() || s.elevation_pending {
        bail!("请等待当前任务完成");
    }
    let handle = task::spawn_operation(run);
    let mut message = TaskMessage {
        task_id: handle.id,
        session_id: s.session.as_ref().map(AnalysisSession::id),
        epoch: s.epoch,
        revision: s.latest_view,
        kind: kind.into(),
        status: "running".into(),
        label: label.into(),
        stage: None,
        completed: None,
        total: None,
        error: None,
        saved_paths: vec![],
    };
    let reply = message.clone();
    let handle = Arc::new(Mutex::new(handle));
    let cancellation = handle.clone();
    s.cancel = Some(Arc::new(move || {
        if let Ok(h) = cancellation.lock() {
            h.cancel();
        }
    }));
    s.busy = Some(message.clone());
    drop(s);
    std::thread::spawn(move || {
        let mut last = Instant::now() - Duration::from_secs(1);
        let result = loop {
            let h = handle.lock().unwrap_or_else(|e| e.into_inner());
            let mut latest = None;
            while let Ok(event) = h.events.try_recv() {
                if let TaskEvent::Progress { progress, .. } = event {
                    latest = Some(progress);
                }
            }
            if let Some(p) = latest {
                message.stage = Some(stage_name(p.stage));
                message.completed = Some(p.completed);
                message.total = if p.stage == Stage::Ai { None } else { p.total };
            }
            message.status = status_name(h.status());
            let result = h.try_result();
            drop(h);
            if last.elapsed() >= Duration::from_millis(100)
                && matches!(message.status.as_str(), "running" | "cancelling")
            {
                if let Ok(mut s) = desktop.lock() {
                    s.busy = Some(message.clone());
                }
                let _ = app.emit("analysis-task", &message);
                last = Instant::now();
            }
            match result {
                Ok(Some(value)) => break value,
                Err(e) => break Err(e),
                _ => std::thread::sleep(Duration::from_millis(25)),
            }
        };
        message.status = "completed".into();
        message.stage = None;
        if let Ok(mut s) = desktop.lock() {
            match result {
                Ok(WorkerResult::Outcome(outcome)) => {
                    message.status = status_name(outcome.status);
                    let replace = s
                        .session
                        .as_ref()
                        .is_none_or(|old| old.id() != outcome.session.id());
                    if replace {
                        s.epoch += 1;
                        s.selection = None;
                        s.selection_info = Default::default();
                        s.latest_view = 0;
                        if let Some(token) = s.read_cancel.take() {
                            token.cancel();
                        }
                    }
                    s.session = Some(outcome.session);
                    message.session_id = s.session.as_ref().map(AnalysisSession::id);
                    message.epoch = s.epoch;
                }
                Ok(WorkerResult::Config(config)) => {
                    s.config = config;
                    s.config_loaded = true;
                    s.config_error = None;
                }
                Ok(WorkerResult::Saved(paths)) => {
                    message.saved_paths = paths.iter().map(|p| p.display().to_string()).collect();
                    if message.kind == "config_save" {
                        s.config_loaded = true;
                        s.config_error = None;
                    }
                }
                Ok(WorkerResult::Checked) => {}
                Err(error) => {
                    message.status = if is_cancelled(&error) {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into();
                    message.error = Some(format!("{error:#}"));
                }
            }
            s.busy = None;
            s.cancel = None;
        }
        let _ = app.emit("analysis-task", &message);
    });
    Ok(reply)
}
#[tauri::command]
pub fn start_import(
    app: AppHandle,
    state: State<'_, Desktop>,
    request: ImportRequest,
) -> Rpc<TaskMessage> {
    rpc((|| {
        let request = request.request()?;
        start_job(
            app,
            state.inner().clone(),
            "import",
            "本地分析",
            move |ctx| Ok(WorkerResult::Outcome(AnalysisService::load(&request, ctx)?)),
        )
    })())
}
#[tauri::command]
pub fn cancel_task(state: State<'_, Desktop>, task_id: u64) -> Rpc<()> {
    rpc((|| {
        let s = state.lock()?;
        if s.busy.as_ref().is_some_and(|j| j.task_id == task_id)
            && let Some(cancel) = &s.cancel
        {
            cancel();
        }
        Ok(())
    })())
}
#[tauri::command]
pub fn reset_session(state: State<'_, Desktop>) -> Rpc<()> {
    rpc((|| {
        let mut s = state.lock()?;
        if s.busy.is_some() {
            bail!("任务仍在运行，请先取消并等待返回");
        }
        s.epoch += 1;
        s.session = None;
        s.selection = None;
        s.selection_info = Default::default();
        s.latest_view = 0;
        if let Some(c) = s.read_cancel.take() {
            c.cancel();
        }
        Ok(())
    })())
}

pub fn build_view(
    session: &AnalysisSession,
    request: &ViewRequest,
    ctx: &ExecutionContext,
) -> Result<(ViewResponse, Option<RecordSelection>)> {
    if ![50, 100, 200].contains(&request.filters.limit) {
        bail!("分页大小必须为 50、100 或 200");
    }
    let filters = &request.filters;
    let overview = session.overview(ctx)?;
    let mut view = ViewResponse {
        session_id: session.id(),
        revision: request.revision,
        overview,
        records: None,
        findings: None,
        flows: None,
        process_rows: vec![],
        sources: session.source_page(request.source_offset, 100)?,
        record_sources: BTreeMap::new(),
        diagnostics: session.diagnostic_page(request.diagnostic_offset, 50)?,
        runs: run_summaries(session, request.run_offset, 20)?,
        outside: false,
        offset: filters.offset,
        selection: Default::default(),
    };
    if matches!(request.screen, Screen::Overview | Screen::Ai) {
        view.findings = Some(session.finding_page(
            &filters.finding_filter(),
            filters.offset,
            filters.limit,
            ctx,
        )?);
    }
    let mut valid = None;
    if request.screen.evidence() {
        let selected = session.select_records(&filters.record_filter(request.screen), ctx)?;
        let selected = if let Some(key) = filters.flow {
            session.flow_selection(key, Some(&selected), ctx)?
        } else {
            selected
        };
        let displayed = if let Some(id) = &request.focus_id {
            if let Some(index) = session.locate_record(Some(&selected), id)? {
                view.offset = index / filters.limit * filters.limit;
                selected.clone()
            } else {
                view.outside = true;
                view.offset = 0;
                session.select_ids([id.clone()])?
            }
        } else {
            selected.clone()
        };
        if request.screen == Screen::Processes && filters.tree && !view.outside {
            let all = session.process_rows(&displayed, ctx)?;
            let mut hidden = None;
            let mut rows = vec![];
            for row in all {
                ctx.check()?;
                if hidden.is_some_and(|depth| row.depth > depth) {
                    continue;
                }
                hidden = None;
                if filters.collapsed.contains(&row.record_id) && request.focus_id.is_none() {
                    hidden = Some(row.depth);
                }
                rows.push(row);
            }
            if let Some(id) = &request.focus_id
                && let Some(index) = rows.iter().position(|r| &r.record_id == id)
            {
                view.offset = index / filters.limit * filters.limit;
            }
            let total = rows.len();
            view.process_rows = rows
                .into_iter()
                .skip(view.offset)
                .take(filters.limit)
                .collect();
            let ids = session.select_ids(view.process_rows.iter().map(|r| r.record_id.clone()))?;
            let mut page = session.page_metadata(Some(&ids), 0, filters.limit)?;
            page.total = total;
            page.offset = view.offset;
            view.records = Some(page);
        } else {
            view.records =
                Some(session.page_metadata(Some(&displayed), view.offset, filters.limit)?);
            if request.screen == Screen::Processes {
                let ids = view
                    .records
                    .as_ref()
                    .unwrap()
                    .items
                    .iter()
                    .map(|r| &r.id)
                    .collect::<std::collections::HashSet<_>>();
                view.process_rows = session
                    .process_rows(&displayed, ctx)?
                    .into_iter()
                    .filter(|r| ids.contains(&r.record_id))
                    .map(|mut r| {
                        r.depth = 0;
                        r.has_children = false;
                        r
                    })
                    .collect();
            }
        }
        if request.screen == Screen::Network {
            let all = session.select_records(&filters.record_filter(request.screen), ctx)?;
            view.flows = Some(session.flow_page(Some(&all), filters.offset, filters.limit, ctx)?);
        }
        if let Some(records) = &view.records {
            for record in &records.items {
                if !view.record_sources.contains_key(&record.source_id)
                    && let Some(source) = session.source(&record.source_id)?
                {
                    view.record_sources
                        .insert(record.source_id.clone(), source.path);
                }
            }
        }
        valid = Some(selected);
    }
    ctx.check()?;
    Ok((view, valid))
}
fn run_summaries(
    session: &AnalysisSession,
    offset: usize,
    limit: usize,
) -> Result<Page<RunSummary>> {
    session.with_report(|report| Page {
        offset,
        total: report.ai_runs.len(),
        items: report
            .ai_runs
            .iter()
            .enumerate()
            .rev()
            .skip(offset)
            .take(limit)
            .map(|(index, r)| RunSummary {
                index,
                model: r.model.clone(),
                endpoint: r.endpoint.clone(),
                batches: r.batches,
                completed: r.completed(),
                analyzed: r.analyzed_records,
                selected: r.selected(),
                include_payload: r.include_payload,
            })
            .collect(),
    })
}
fn commit_view(
    desktop: &Desktop,
    session: &AnalysisSession,
    request: &ViewRequest,
    view: &mut ViewResponse,
    selected: Option<RecordSelection>,
) -> Result<()> {
    let mut s = desktop.lock()?;
    if s.session.as_ref().map(AnalysisSession::id) != Some(session.id())
        || s.latest_view != request.revision
    {
        bail!("已忽略旧会话或过期视图");
    }
    if request.commit_selection
        && request.focus_id.is_none()
        && let Some(selected) = selected
    {
        s.next_selection += 1;
        s.selection_info = SelectionInfo {
            id: s.next_selection,
            count: selected.len(),
            label: request.filters.label(request.screen),
        };
        s.selection = Some(selected);
    }
    view.selection = s.selection_info.clone();
    Ok(())
}
#[tauri::command]
pub async fn get_view(state: State<'_, Desktop>, request: ViewRequest) -> Rpc<ViewResponse> {
    let desktop = state.inner().clone();
    let session = rpc(desktop.session(request.session_id))?;
    let token = CancellationToken::default();
    {
        let mut s = rpc(desktop.lock())?;
        if request.revision < s.latest_view {
            return Err("已忽略过期视图请求".into());
        }
        s.latest_view = request.revision;
        if let Some(old) = s.read_cancel.replace(token.clone()) {
            old.cancel();
        }
    }
    rpc(
        tauri::async_runtime::spawn_blocking(move || -> Result<ViewResponse> {
            let ctx = ExecutionContext::new(token, |_| {});
            let (mut view, selected) = build_view(&session, &request, &ctx)?;
            commit_view(&desktop, &session, &request, &mut view, selected)?;
            Ok(view)
        })
        .await
        .map_err(|e| e.to_string())?,
    )
}
#[tauri::command]
pub async fn get_detail(
    state: State<'_, Desktop>,
    session_id: u64,
    id: String,
) -> Rpc<DetailResponse> {
    let session = rpc(state.session(session_id))?;
    rpc(
        tauri::async_runtime::spawn_blocking(move || -> Result<DetailResponse> {
            let record = session.record(&id)?.ok_or_else(|| anyhow!("证据不存在"))?;
            Ok(DetailResponse {
                session_id,
                source: session.source(&record.source_id)?,
                related: session.related_findings(&id)?,
                record,
            })
        })
        .await
        .map_err(|e| e.to_string())?,
    )
}
#[tauri::command]
pub async fn get_ai_batches(
    state: State<'_, Desktop>,
    session_id: u64,
    run: usize,
    offset: usize,
) -> Rpc<Page<core::AiBatch>> {
    let session = rpc(state.session(session_id))?;
    rpc(tauri::async_runtime::spawn_blocking(move || {
        session.with_report(|r| -> Result<Page<core::AiBatch>> {
            let batches = &r
                .ai_runs
                .get(run)
                .ok_or_else(|| anyhow!("运行不存在"))?
                .batch_results;
            Ok(Page {
                offset,
                total: batches.len(),
                items: batches.iter().skip(offset).take(10).cloned().collect(),
            })
        })?
    })
    .await
    .map_err(|e| e.to_string())?)
}
#[tauri::command]
pub fn apply_config(state: State<'_, Desktop>, config: ConfigInput) -> Rpc<PublicConfig> {
    rpc((|| {
        let mut s = state.lock()?;
        s.config = config.apply(&s.config)?;
        Ok(PublicConfig::from(&s.config))
    })())
}
#[tauri::command]
pub fn config_operation(
    app: AppHandle,
    state: State<'_, Desktop>,
    operation: String,
    path: String,
) -> Rpc<TaskMessage> {
    rpc((|| {
        let desktop = state.inner().clone();
        let mut s = desktop.lock()?;
        if s.busy.is_some() {
            bail!("请等待当前任务完成");
        }
        s.prefs.config_path = path.clone();
        let config = s.config.clone();
        drop(s);
        match operation.as_str() {
            "load" => start_job(app, desktop, "config_load", "读取配置", move |ctx| {
                ctx.check()?;
                Ok(WorkerResult::Config(ConfigService::load(Path::new(&path))?))
            }),
            "save" => start_job(app, desktop, "config_save", "保存配置", move |ctx| {
                ctx.check()?;
                ConfigService::save(Path::new(&path), &config)?;
                Ok(WorkerResult::Saved(vec![path.into()]))
            }),
            "check" => start_job(app, desktop, "config_check", "检查连接", move |ctx| {
                ctx.check()?;
                ConfigService::check(&config)?;
                Ok(WorkerResult::Checked)
            }),
            _ => bail!("未知配置操作"),
        }
    })())
}
#[tauri::command]
pub async fn start_ai(
    app: AppHandle,
    state: State<'_, Desktop>,
    request: AiRequest,
) -> Rpc<TaskMessage> {
    rpc((|| {
        let desktop = state.inner().clone();
        let session = desktop.session(request.session_id)?;
        let s = desktop.lock()?;
        if !s.config_loaded {
            bail!("请先加载或保存配置");
        }
        let scope = match request.scope.as_str() {
            "all" => AiScope::All,
            "matches" => AiScope::Matches,
            "suspicious" => AiScope::Suspicious,
            _ => bail!("无效的 AI 范围"),
        };
        let selected = if scope == AiScope::Matches {
            if request.selection_id != Some(s.selection_info.id) {
                bail!("筛选范围已变化，请确认最新有效筛选");
            }
            Some(s.selection.clone().ok_or_else(|| anyhow!("尚无有效筛选"))?)
        } else {
            None
        };
        if selected.as_ref().is_some_and(RecordSelection::is_empty) {
            bail!("AI 范围为空");
        }
        let config = s.config.clone();
        if s.args.qa_ai
            && !(config.base_url.starts_with("http://127.0.0.1:")
                || config.base_url.starts_with("http://[::1]:"))
        {
            bail!("验收 AI 仅允许本机回环模拟服务");
        }
        let options = AiOptions {
            config_path: s.prefs.config_path.clone().into(),
            scope,
            include_payload: request.include_payload,
        };
        drop(s);
        start_job(app, desktop, "ai", "AI 分析", move |ctx| {
            let query = QueryOptions {
                suspicious: scope == AiScope::Suspicious,
                ..Default::default()
            };
            if scope != AiScope::Matches && session.query(&query, ctx)?.is_empty() {
                bail!("AI 范围为空");
            }
            Ok(WorkerResult::Outcome(
                AnalysisService::analyze_ai_with_config(
                    &session,
                    &options,
                    selected.as_ref(),
                    &config,
                    ctx,
                )?,
            ))
        })
    })())
}
#[tauri::command]
pub async fn start_export(
    app: AppHandle,
    state: State<'_, Desktop>,
    request: ExportRequest,
) -> Rpc<TaskMessage> {
    rpc((|| {
        let desktop = state.inner().clone();
        let session = desktop.session(request.session_id)?;
        let s = desktop.lock()?;
        if request.path.trim().is_empty() || (!request.html && !request.json) {
            bail!("请选择导出格式和路径");
        }
        if request
            .selection_id
            .is_some_and(|id| id != s.selection_info.id)
        {
            bail!("筛选范围已变化，请刷新后导出");
        }
        let selection = s.selection.clone();
        let config = s.prefs.config_path.clone();
        drop(s);
        let path = PathBuf::from(request.path);
        let html = request.html.then(|| path.with_extension("html"));
        let json = request.json.then(|| path.with_extension("json"));
        if !request.overwrite && html.iter().chain(json.iter()).any(|p| p.exists()) {
            bail!("目标报告已存在，请确认覆盖");
        }
        let plan = ExportPlan {
            format: if request.html {
                OutputFormat::Html
            } else {
                OutputFormat::Json
            },
            path: None,
            html_path: html,
            json_path: json,
            ..Default::default()
        };
        start_job(app, desktop, "export", "导出完整报告", move |ctx| {
            ctx.check()?;
            session.set_selection(selection.as_ref(), ctx)?;
            Ok(WorkerResult::Saved(
                plan.save(&session, Path::new(&config))?.saved_paths,
            ))
        })
    })())
}
#[tauri::command]
pub async fn pick_paths(app: AppHandle, kind: String) -> Rpc<Vec<String>> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let dialog = app.dialog().file();
        let paths = match kind.as_str() {
            "inputs" => dialog.blocking_pick_files().unwrap_or_default(),
            "capture" => dialog.blocking_pick_folder().into_iter().collect(),
            "export" => dialog
                .set_file_name("report.html")
                .blocking_save_file()
                .into_iter()
                .collect(),
            _ => dialog.blocking_pick_file().into_iter().collect(),
        };
        paths
            .into_iter()
            .filter_map(|p| p.into_path().ok())
            .map(|p| p.display().to_string())
            .collect()
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(result)
}

#[cfg(test)]
mod tests;
