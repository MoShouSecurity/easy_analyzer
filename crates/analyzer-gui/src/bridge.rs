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
pub struct FrozenAi {
    id: u64,
    request: AiRequest,
    config: core::ai::AiConfig,
    epoch: u64,
    prepared: PreparedAiAnalysis,
}
pub struct Inner {
    _data_directory: Option<tempfile::TempDir>,
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
    pub next_ai_preview: u64,
    pub ai_preview: Option<FrozenAi>,
    pub preview_cancel: Option<CancellationToken>,
}
impl Desktop {
    pub fn new(data_dir: PathBuf, args: Args) -> Self {
        let directory = if args.temporary {
            tempfile::tempdir().ok()
        } else {
            None
        };
        let data_dir = directory
            .as_ref()
            .map_or(data_dir, |d| d.path().to_path_buf());
        Self(Arc::new(Mutex::new(Inner {
            _data_directory: directory,
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
            next_ai_preview: 0,
            ai_preview: None,
            preview_cancel: None,
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
        project: s
            .session
            .as_ref()
            .filter(|p| p.is_project())
            .and_then(|p| ProjectService::status(p).ok()),
        filters: s
            .session
            .as_ref()
            .filter(|p| p.is_project())
            .and_then(|p| ProjectService::view_state(p).ok())
            .flatten(),
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
    start_session_job(app, desktop, kind, label, None, run)
}
fn start_session_job(
    app: AppHandle,
    desktop: Desktop,
    kind: &str,
    label: &str,
    expected_session: Option<u64>,
    run: impl FnOnce(&ExecutionContext) -> Result<WorkerResult> + Send + 'static,
) -> Result<TaskMessage> {
    let mut s = desktop.lock()?;
    if s.busy.is_some() || s.elevation_pending {
        bail!("请等待当前任务完成");
    }
    s.ai_preview = None;
    if let Some(token) = s.preview_cancel.take() {
        token.cancel();
    }
    if expected_session.is_some_and(|id| s.session.as_ref().map(AnalysisSession::id) != Some(id)) {
        bail!("会话已变化，请重新计算发送预览");
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
                message.stage = Some(
                    if p.stage == Stage::Ai
                        && p.source
                            .as_deref()
                            .is_some_and(|source| source.starts_with("跨批汇总"))
                    {
                        p.source.unwrap()
                    } else if p.source.as_deref() == Some("跨批汇总") {
                        "准备跨批汇总".into()
                    } else {
                        stage_name(p.stage)
                    },
                );
                message.completed = Some(p.completed);
                message.total = p.total;
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
            if s.epoch != message.epoch
                || s.busy.as_ref().is_none_or(|j| j.task_id != message.task_id)
            {
                return;
            }
            match result {
                Ok(WorkerResult::Outcome(outcome)) => {
                    message.status = status_name(outcome.status);
                    let replace = s
                        .session
                        .as_ref()
                        .is_none_or(|old| old.id() != outcome.session.id());
                    if replace || message.kind == "import" || message.kind == "ioc_scan" {
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
        let session = state.lock()?.session.clone();
        if session.as_ref().is_none_or(|p| !p.is_project()) && !state.lock()?.args.qa {
            bail!("请先新建应急响应项目并填写项目名称和客户单位");
        }
        start_job(
            app,
            state.inner().clone(),
            "import",
            "本地分析",
            move |ctx| {
                Ok(WorkerResult::Outcome(
                    if let Some(session) = session.filter(|p| p.is_project()) {
                        ProjectService::append(&session, &request, ctx)?
                    } else {
                        AnalysisService::load(&request, ctx)?
                    },
                ))
            },
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
        project: if session.is_project() {
            Some(ProjectService::status(session)?)
        } else {
            None
        },
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
        runs: run_summaries(session, request.run_offset, 20, ctx)?,
        outside: false,
        offset: filters.offset,
        selection: Default::default(),
    };
    if matches!(request.screen, Screen::Overview | Screen::Ai) {
        let mut filter = filters.finding_filter();
        if request.screen == Screen::Ai {
            filter.origin = FindingOrigin::Ai;
        }
        view.findings =
            Some(session.finding_previews(&filter, filters.offset, filters.limit, ctx)?);
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
    ctx: &ExecutionContext,
) -> Result<Page<RunSummary>> {
    let runs = session.ai_run_headers()?;
    let mut summaries = BTreeMap::new();
    let mut offset_d = 0;
    loop {
        let page = session.diagnostic_page(offset_d, 1000)?;
        for diagnostic in page.items {
            ctx.check()?;
            if diagnostic.source == "AI 本地整理"
                && let Some(position) = diagnostic.position
            {
                summaries.insert(position, diagnostic.message);
            }
        }
        offset_d += 1000;
        if offset_d >= page.total {
            break;
        }
    }
    Ok(Page {
        offset,
        total: runs.len(),
        items: runs
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
                local_summary: summaries.get(&format!("ai-run:{}", index + 1)).cloned(),
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
                related: session.related_finding_previews(&id)?,
                note: if session.is_project() {
                    ProjectService::read_note(&session, &id)?
                } else {
                    None
                },
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
    rpc(
        tauri::async_runtime::spawn_blocking(move || session.ai_batch_page(run, offset, 10))
            .await
            .map_err(|e| e.to_string())?,
    )
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
fn ai_options(s: &Inner, request: &AiRequest) -> Result<(AiOptions, Option<RecordSelection>)> {
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
    if s.args.qa_ai
        && !(s.config.base_url.starts_with("http://127.0.0.1:")
            || s.config.base_url.starts_with("http://[::1]:"))
    {
        bail!("验收 AI 仅允许本机回环模拟服务");
    }
    Ok((
        AiOptions {
            config_path: s.prefs.config_path.clone().into(),
            scope,
            include_payload: request.include_payload,
        },
        selected,
    ))
}

#[tauri::command]
pub async fn prepare_ai(state: State<'_, Desktop>, request: AiRequest) -> Rpc<AiPreview> {
    let desktop = state.inner().clone();
    let session = rpc(desktop.session(request.session_id))?;
    let token = CancellationToken::default();
    let (options, selected, config, epoch, id) = rpc((|| {
        let mut s = desktop.lock()?;
        if s.busy.is_some() || s.elevation_pending {
            bail!("请等待当前任务完成");
        }
        let (options, selected) = ai_options(&s, &request)?;
        s.next_ai_preview += 1;
        s.ai_preview = None;
        if let Some(old) = s.preview_cancel.replace(token.clone()) {
            old.cancel();
        }
        Ok((
            options,
            selected,
            s.config.clone(),
            s.epoch,
            s.next_ai_preview,
        ))
    })())?;
    rpc(
        tauri::async_runtime::spawn_blocking(move || -> Result<AiPreview> {
            let ctx = ExecutionContext::new(token, |_| {});
            let prepared = AnalysisService::prepare_ai_with_config(
                &session,
                &options,
                selected.as_ref(),
                &config,
                &ctx,
            )?;
            let preview = AiPreview {
                id,
                session_id: session.id(),
                plan: prepared.plan().clone(),
            };
            let mut s = desktop.lock()?;
            if s.next_ai_preview != id
                || s.epoch != epoch
                || s.config != config
                || s.busy.is_some()
                || s.session.as_ref().map(AnalysisSession::id) != Some(request.session_id)
                || (request.scope == "matches" && request.selection_id != Some(s.selection_info.id))
            {
                bail!("发送预览已过期，请重新计算");
            }
            s.preview_cancel = None;
            s.ai_preview = Some(FrozenAi {
                id,
                request,
                config,
                epoch,
                prepared,
            });
            Ok(preview)
        })
        .await
        .map_err(|e| e.to_string())?,
    )
}

fn take_ai_plan(s: &mut Inner, request: &AiRequest) -> Result<PreparedAiAnalysis> {
    let plan = s
        .ai_preview
        .as_ref()
        .ok_or_else(|| anyhow!("请先完成发送预览"))?;
    if request.plan_id != Some(plan.id)
        || plan.epoch != s.epoch
        || plan.config != s.config
        || plan.request.session_id != request.session_id
        || plan.request.scope != request.scope
        || plan.request.selection_id != request.selection_id
        || plan.request.include_payload != request.include_payload
        || s.session.as_ref().map(AnalysisSession::id) != Some(request.session_id)
        || (request.scope == "matches" && request.selection_id != Some(s.selection_info.id))
    {
        bail!("发送范围或设置已变化，请重新计算预览");
    }
    Ok(s.ai_preview.take().unwrap().prepared)
}

#[tauri::command]
pub async fn start_ai(
    app: AppHandle,
    state: State<'_, Desktop>,
    request: AiRequest,
) -> Rpc<TaskMessage> {
    rpc((|| {
        let desktop = state.inner().clone();
        let mut s = desktop.lock()?;
        if s.busy.is_some() || s.elevation_pending {
            bail!("请等待当前任务完成");
        }
        ai_options(&s, &request)?;
        let prepared = take_ai_plan(&mut s, &request)?;
        drop(s);
        start_session_job(
            app,
            desktop,
            "ai",
            "AI 分析",
            Some(request.session_id),
            move |ctx| {
                Ok(WorkerResult::Outcome(AnalysisService::analyze_prepared_ai(
                    prepared, ctx,
                )?))
            },
        )
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
                plan.save_with_context(&session, Path::new(&config), ctx)?
                    .saved_paths,
            ))
        })
    })())
}
#[tauri::command]
pub async fn pick_paths(app: AppHandle, kind: String) -> Rpc<Vec<String>> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let dialog = app.dialog().file();
        let paths = match kind.as_str() {
            "project_save" => dialog
                .add_filter("Easy Analyzer 项目", &["eair"])
                .set_file_name("响应项目.eair")
                .blocking_save_file()
                .into_iter()
                .collect(),
            "project_open" => dialog
                .add_filter("Easy Analyzer 项目", &["eair"])
                .blocking_pick_file()
                .into_iter()
                .collect(),
            "ioc" => dialog
                .add_filter("IOC 清单", &["txt", "csv"])
                .blocking_pick_files()
                .unwrap_or_default(),
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

fn editable_project(state: &Desktop, id: u64) -> Result<AnalysisSession> {
    let mut s = state.lock()?;
    if s.busy.is_some() {
        bail!("请等待当前任务完成");
    }
    s.ai_preview = None;
    if let Some(c) = s.preview_cancel.take() {
        c.cancel();
    }
    s.session
        .clone()
        .filter(|p| p.id() == id && p.is_project())
        .ok_or_else(|| anyhow!("项目已切换，请刷新"))
}
#[tauri::command]
pub async fn project_list(
    state: State<'_, Desktop>,
    search: ProjectSearch,
) -> Rpc<Vec<ProjectEntry>> {
    let root = rpc(state.lock())?.data_dir.clone();
    rpc(
        tauri::async_runtime::spawn_blocking(move || ProjectCatalog::open(&root)?.list(&search))
            .await
            .map_err(|e| e.to_string())?,
    )
}
#[tauri::command]
pub fn project_create(
    app: AppHandle,
    state: State<'_, Desktop>,
    info: ProjectInfo,
) -> Rpc<TaskMessage> {
    rpc(start_job(
        app,
        state.inner().clone(),
        "project_create",
        "新建应急响应项目",
        move |ctx| {
            ctx.check()?;
            Ok(WorkerResult::Outcome(AnalysisOutcome {
                session: ProjectService::create(info)?,
                status: TaskStatus::Completed,
            }))
        },
    ))
}
#[tauri::command]
pub fn project_open(app: AppHandle, state: State<'_, Desktop>, path: String) -> Rpc<TaskMessage> {
    let root = rpc(state.lock())?.data_dir.clone();
    rpc(start_job(
        app,
        state.inner().clone(),
        "project_open",
        "打开应急响应项目",
        move |ctx| {
            let session = ProjectService::open(Path::new(&path), ctx)?;
            ProjectCatalog::open(&root)?.register(&session)?;
            Ok(WorkerResult::Outcome(AnalysisOutcome {
                session,
                status: TaskStatus::Completed,
            }))
        },
    ))
}
#[tauri::command]
pub fn project_save(
    app: AppHandle,
    state: State<'_, Desktop>,
    session_id: u64,
    path: String,
    overwrite: bool,
) -> Rpc<TaskMessage> {
    rpc((|| {
        let session = state.session(session_id)?;
        let s = state.lock()?;
        let root = s.data_dir.clone();
        let config = PathBuf::from(&s.prefs.config_path);
        drop(s);
        start_session_job(
            app,
            state.inner().clone(),
            "project_save",
            "保存项目",
            Some(session_id),
            move |ctx| {
                let path =
                    ProjectService::save(&session, Path::new(&path), &config, overwrite, ctx)?;
                ProjectCatalog::open(&root)?.register(&session)?;
                Ok(WorkerResult::Saved(vec![path]))
            },
        )
    })())
}
#[tauri::command]
pub async fn project_edit(
    state: State<'_, Desktop>,
    session_id: u64,
    info: ProjectInfo,
) -> Rpc<ProjectStatus> {
    let session = rpc(editable_project(state.inner(), session_id))?;
    rpc(tauri::async_runtime::spawn_blocking(move || {
        ProjectService::edit(&session, info, &ExecutionContext::default())?;
        ProjectService::status(&session)
    })
    .await
    .map_err(|e| e.to_string())?)
}
#[tauri::command]
pub async fn project_note(
    state: State<'_, Desktop>,
    session_id: u64,
    record: String,
    text: String,
) -> Rpc<ProjectStatus> {
    let session = rpc(editable_project(state.inner(), session_id))?;
    rpc(tauri::async_runtime::spawn_blocking(move || {
        ProjectService::note(&session, &record, &text, &ExecutionContext::default())?;
        ProjectService::status(&session)
    })
    .await
    .map_err(|e| e.to_string())?)
}
#[tauri::command]
pub async fn project_filters(
    state: State<'_, Desktop>,
    session_id: u64,
    filters: BTreeMap<String, Filters>,
) -> Rpc<ProjectStatus> {
    let session = rpc(state.session(session_id))?;
    rpc(tauri::async_runtime::spawn_blocking(move || {
        ProjectService::save_view_state(&session, &serde_json::to_value(filters)?)?;
        ProjectService::status(&session)
    })
    .await
    .map_err(|e| e.to_string())?)
}
#[derive(serde::Deserialize)]
pub struct IocInput {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub csv: bool,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub kind: Option<IocType>,
    #[serde(default)]
    pub note: String,
}
#[tauri::command]
pub async fn import_ioc(
    state: State<'_, Desktop>,
    session_id: u64,
    input: IocInput,
) -> Rpc<IocImport> {
    let session = rpc(editable_project(state.inner(), session_id))?;
    rpc(tauri::async_runtime::spawn_blocking(move || {
        let ctx = ExecutionContext::default();
        let mut sources: Vec<IocSource> = input
            .paths
            .into_iter()
            .map(|p| IocSource::File(p.into()))
            .collect();
        if !input.text.trim().is_empty() {
            sources.push(IocSource::Text {
                text: input.text,
                csv: input.csv,
                origin: "粘贴清单".into(),
            });
        }
        if !input.value.trim().is_empty() {
            sources.push(IocSource::Value {
                value: input.value,
                kind: input.kind,
                note: input.note,
            });
        }
        IocService::import(&session, &sources, &ctx)
    })
    .await
    .map_err(|e| e.to_string())?)
}
#[derive(serde::Serialize)]
pub struct IocView {
    pub status: IocStatus,
    pub indicators: Page<core::ioc::Indicator>,
    pub hits: Page<IocHit>,
}
#[tauri::command]
pub async fn get_ioc(
    state: State<'_, Desktop>,
    session_id: u64,
    offset: usize,
    hit_offset: usize,
) -> Rpc<IocView> {
    let session = rpc(state.session(session_id))?;
    rpc(tauri::async_runtime::spawn_blocking(move || {
        Ok(IocView {
            status: IocService::status(&session)?,
            indicators: IocService::indicators(&session, offset, 100)?,
            hits: IocService::matches(&session, hit_offset, 100)?,
        })
    })
    .await
    .map_err(|e| e.to_string())?)
}
#[tauri::command]
pub async fn ioc_note(
    state: State<'_, Desktop>,
    session_id: u64,
    id: String,
    note: String,
) -> Rpc<ProjectStatus> {
    let session = rpc(editable_project(state.inner(), session_id))?;
    rpc(tauri::async_runtime::spawn_blocking(move || {
        IocService::edit_note(&session, &id, &note, &ExecutionContext::default())?;
        ProjectService::status(&session)
    })
    .await
    .map_err(|e| e.to_string())?)
}
#[tauri::command]
pub fn start_ioc_scan(
    app: AppHandle,
    state: State<'_, Desktop>,
    session_id: u64,
    include_subdomains: bool,
) -> Rpc<TaskMessage> {
    rpc((|| {
        let session = state.session(session_id)?;
        start_session_job(
            app,
            state.inner().clone(),
            "ioc_scan",
            "IOC 匹配",
            Some(session_id),
            move |ctx| {
                let run = IocService::scan(&session, include_subdomains, ctx)?;
                Ok(WorkerResult::Outcome(AnalysisOutcome {
                    session,
                    status: if run.complete {
                        TaskStatus::Completed
                    } else {
                        TaskStatus::Cancelled
                    },
                }))
            },
        )
    })())
}

#[tauri::command]
pub async fn finding_references(
    state: State<'_, Desktop>,
    session_id: u64,
    id: String,
    offset: usize,
) -> Rpc<Page<String>> {
    let session = rpc(state.session(session_id))?;
    rpc(
        tauri::async_runtime::spawn_blocking(move || session.finding_references(&id, offset, 100))
            .await
            .map_err(|e| e.to_string())?,
    )
}

#[cfg(test)]
mod tests;
