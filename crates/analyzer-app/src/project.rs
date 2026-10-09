//! One response project per portable SQLite file. Working changes stay on private disk until Save.
use crate::{
    storage::{APP_ID, Database, VERSION, json},
    *,
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Local};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension,
    backup::{Backup, StepResult},
    params,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub id: String,
    pub name: String,
    pub client: String,
    pub response_start: String,
    #[serde(default)]
    pub response_end: Option<String>,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub responders: String,
    #[serde(default)]
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}
impl ProjectInfo {
    pub fn new(name: impl Into<String>, client: impl Into<String>) -> Self {
        let now = Local::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            client: client.into(),
            response_start: now.clone(),
            response_end: None,
            location: String::new(),
            responders: String::new(),
            description: String::new(),
            created_at: now.clone(),
            updated_at: now,
        }
    }
    pub fn validate(&self) -> Result<()> {
        Uuid::parse_str(&self.id).context("无效的项目 UUID")?;
        if self.name.trim().is_empty() || self.client.trim().is_empty() {
            bail!("项目名称和客户单位为必填项");
        }
        let start = DateTime::parse_from_rfc3339(&self.response_start)
            .context("响应开始时间必须包含日期、时间和时区")?;
        if let Some(end) = &self.response_end
            && DateTime::parse_from_rfc3339(end).context("响应结束时间格式不正确")? < start
        {
            bail!("响应结束时间不能早于开始时间");
        }
        DateTime::parse_from_rfc3339(&self.created_at)?;
        DateTime::parse_from_rfc3339(&self.updated_at)?;
        Ok(())
    }
    fn normalize(&mut self) {
        self.name = self.name.trim().into();
        self.client = self.client.trim().into();
        if self.name.is_empty() {
            self.name = self.client.clone();
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct ProjectStatus {
    pub info: ProjectInfo,
    pub path: Option<String>,
    pub dirty: bool,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectEntry {
    pub info: ProjectInfo,
    pub path: String,
    pub last_opened: String,
    #[serde(default)]
    pub missing: bool,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProjectSearch {
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
}
fn db(session: &AnalysisSession) -> Result<&Arc<Database>> {
    session
        .0
        .store
        .as_ref()
        .ok_or_else(|| anyhow!("当前会话不是应急响应项目"))
}
pub(crate) fn touch(c: &Connection) -> Result<()> {
    touch_revision(c, true)
}
fn touch_view(c: &Connection) -> Result<()> {
    touch_revision(c, false)
}
pub(crate) fn content_revision(c: &Connection) -> Result<u64> {
    let value: Option<String> = c
        .query_row(
            "SELECT value FROM metadata WHERE key='content_revision'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    match value {
        Some(value) => crate::storage::decode(value),
        None => Database::get(c, "revision"),
    }
}
fn touch_revision(c: &Connection, content_changed: bool) -> Result<()> {
    let rev: u64 = Database::get(c, "revision")?;
    let content = content_revision(c)?;
    Database::set(
        c,
        "content_revision",
        &(content + u64::from(content_changed)),
    )?;
    Database::set(c, "revision", &(rev + 1))?;
    let mut info: ProjectInfo = Database::get(c, "project")?;
    info.updated_at = Local::now().to_rfc3339();
    Database::set(c, "project", &info)
}
fn copy(source: &Connection, target: &mut Connection, ctx: &ExecutionContext) -> Result<()> {
    let backup = Backup::new(source, target)?;
    loop {
        ctx.check()?;
        match backup.step(128)? {
            StepResult::Done => break,
            StepResult::More => {
                let p = backup.progress();
                ctx.emit(
                    core::execution::Stage::Finalizing,
                    Some("项目数据库"),
                    (p.pagecount - p.remaining) as usize,
                    Some(p.pagecount as usize),
                );
            }
            StepResult::Busy | StepResult::Locked => bail!("项目数据库被其他程序占用，请稍后重试"),
            _ => bail!("数据库备份未完成"),
        }
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn clone_snapshot(
    file: &fs::File,
    path: &Path,
    target: &Path,
    source: &Connection,
) -> Result<bool> {
    use std::{
        ffi::CString,
        os::{
            fd::AsRawFd,
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
    };
    // Hold a SQLite read transaction while cloning; WAL snapshots require the Backup API.
    let mode: String = source.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    if mode != "delete" {
        return Ok(false);
    }
    let original = file.metadata()?;
    let current = fs::metadata(path)?;
    if original.dev() != current.dev() || original.ino() != current.ino() {
        bail!("项目文件在打开期间已被替换，请重试");
    }
    let target = CString::new(target.as_os_str().as_bytes())?;
    // SAFETY: file owns a live descriptor; target is a valid NUL-terminated path.
    // fclonefileat creates an independent inode with copy-on-write data on APFS.
    Ok(unsafe { libc::fclonefileat(file.as_raw_fd(), libc::AT_FDCWD, target.as_ptr(), 0) } == 0)
}
fn validate_file(c: &Connection, ctx: &ExecutionContext) -> Result<ProjectInfo> {
    crate::compression::register(c)?;
    c.execute_batch("PRAGMA trusted_schema=OFF;")?;
    if c.pragma_query_value(None, "application_id", |r| r.get::<_, i32>(0))? != APP_ID {
        bail!("这不是 Easy Analyzer 项目文件");
    }
    if c.pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0))? != VERSION {
        bail!("不支持该项目文件版本");
    }
    if c.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type IN ('trigger','view')",
        [],
        |r| r.get::<_, i64>(0),
    )? != 0
    {
        bail!("项目包含不支持的数据库结构");
    }
    let token = ctx.cancellation.clone();
    c.progress_handler(2048, Some(move || token.is_cancelled()))?;
    let checked = (|| -> Result<()> {
        if c.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? != "ok" {
            bail!("项目数据库损坏");
        }
        if c.prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_some()
        {
            bail!("项目存在无效证据引用");
        }
        if !c.query_row(
            "SELECT COUNT(*)=COALESCE(MAX(ordinal),0) AND COALESCE(MIN(ordinal),1)=1 FROM records",
            [],
            |r| r.get::<_, bool>(0),
        )? {
            bail!("项目记录序号不连续");
        }
        for table in [
            "sources",
            "records",
            "findings",
            "finding_refs",
            "flows",
            "flow_refs",
            "diagnostics",
            "ai_runs",
            "ai_batches",
            "notes",
            "view_state",
            "protected",
            "iocs",
            "ioc_origins",
            "ioc_runs",
            "ioc_matches",
            "selections",
            "selection_refs",
        ] {
            c.prepare(&format!("SELECT * FROM {table} LIMIT 0"))?;
        }
        Ok(())
    })();
    c.progress_handler(0, None::<fn() -> bool>)?;
    ctx.check()?;
    checked?;
    // Validate constraints and indices as well as the table names before executing queries.
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(crate::storage::SCHEMA)?;
    let structure = |db: &Connection| -> Result<Vec<(String, String, Option<String>)>> {
        let mut stmt=db.prepare("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
        Ok(stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
    };
    if structure(c)? != structure(&expected)? {
        bail!("项目表结构或索引不符合 schema 版本");
    }
    let invalid_ai = crate::storage::with_progress(c, ctx, || {
        Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM ai_batches b,json_each(eair_text(b.json),'$.evidence_ids') e LEFT JOIN records r ON r.id=e.value WHERE r.id IS NULL)",[],|r|r.get::<_,bool>(0))?)
    })?;
    if invalid_ai {
        bail!("AI 历史引用不存在的证据");
    }
    let info: ProjectInfo = Database::get(c, "project")?;
    info.validate()?;
    let _: u64 = Database::get(c, "revision")?;
    let report: AnalysisReport = Database::get(c, "report")?;
    if report.schema_version != core::SCHEMA_VERSION {
        bail!("不支持项目内的报告版本");
    }
    Ok(info)
}
pub struct ProjectService;
impl ProjectService {
    pub fn create(mut info: ProjectInfo) -> Result<AnalysisSession> {
        info.id = Uuid::new_v4().to_string();
        info.created_at = Local::now().to_rfc3339();
        info.updated_at = info.created_at.clone();
        info.normalize();
        info.validate()?;
        let store = Database::new()?;
        {
            let c = store.lock()?;
            Database::set(&c, "project", &info)?;
            Database::set(&c, "revision", &0u64)?;
            Database::set(&c, "saved_revision", &Option::<u64>::None)?;
            Database::set(&c, "path", &Option::<String>::None)?;
            Database::set(&c, "query_selection", &Option::<i64>::None)?;
        }
        Ok(AnalysisSession::from_database(store))
    }
    pub fn open(path: &Path, ctx: &ExecutionContext) -> Result<AnalysisSession> {
        ctx.check()?;
        #[cfg(target_os = "macos")]
        let file = fs::File::open(path).context("无法打开项目文件")?;
        let source = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .context("无法打开项目文件")?;
        let snapshot = source.unchecked_transaction()?;
        ctx.emit(
            core::execution::Stage::Reading,
            Some("项目完整性校验"),
            0,
            None,
        );
        validate_file(&snapshot, ctx)?;
        ctx.emit(core::execution::Stage::Query, Some("项目统计"), 0, None);
        // Validation has just read the source pages. Compute once here so the first
        // view does not reread cold APFS clone pages, then cache the same snapshot.
        let overview = crate::storage::with_progress(&snapshot, ctx, || {
            Database::compute_overview(&snapshot, ctx)
        })?;
        ctx.check()?;
        let directory = tempfile::tempdir()?;
        let working = directory.path().join("working.sqlite");
        #[cfg(target_os = "macos")]
        let cloned = clone_snapshot(&file, path, &working, &snapshot)?;
        #[cfg(not(target_os = "macos"))]
        let cloned = false;
        if !cloned && working.exists() {
            fs::remove_file(&working)?;
        }
        let mut c = Connection::open(&working)?;
        if !cloned {
            copy(&snapshot, &mut c, ctx)?;
        }
        ctx.check()?;
        let store = Database::from_connection(c, directory);
        {
            let c = store.lock()?;
            Database::configure(&c)?;
            c.execute_batch("DELETE FROM selections;")?;
            Database::set(&c, "query_selection", &Option::<i64>::None)?;
            let rev: u64 = Database::get(&c, "revision")?;
            *store
                .overview_cache
                .lock()
                .map_err(|_| anyhow!("项目统计缓存不可用"))? =
                Some((content_revision(&c)?, overview));
            Database::set(&c, "saved_revision", &Some(rev))?;
            Database::set(
                &c,
                "path",
                &Some(path.canonicalize()?.display().to_string()),
            )?;
        }
        Ok(AnalysisSession::from_database(store))
    }
    pub fn status(session: &AnalysisSession) -> Result<ProjectStatus> {
        let c = db(session)?.lock()?;
        let revision: u64 = Database::get(&c, "revision")?;
        let saved: Option<u64> = Database::get(&c, "saved_revision")?;
        Ok(ProjectStatus {
            info: Database::get(&c, "project")?,
            path: Database::get(&c, "path")?,
            dirty: saved != Some(revision),
            revision,
        })
    }
    pub fn edit(
        session: &AnalysisSession,
        mut info: ProjectInfo,
        ctx: &ExecutionContext,
    ) -> Result<()> {
        info.normalize();
        info.validate()?;
        let _operation = session.lock_operation(ctx)?;
        let mut c = db(session)?.lock()?;
        let tx = c.transaction()?;
        let c = &tx;
        let old: ProjectInfo = Database::get(c, "project")?;
        if old.id != info.id {
            bail!("不能修改项目 UUID");
        }
        info.created_at = old.created_at;
        Database::set(c, "project", &info)?;
        touch_view(c)?;
        tx.commit()?;
        Ok(())
    }
    pub fn note(
        session: &AnalysisSession,
        record: &str,
        text: &str,
        ctx: &ExecutionContext,
    ) -> Result<()> {
        let _op = session.lock_operation(ctx)?;
        let mut c = db(session)?.lock()?;
        let tx = c.transaction()?;
        let c = &tx;
        if !c.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
            [record],
            |r| r.get::<_, bool>(0),
        )? {
            bail!("证据编号不属于当前项目");
        }
        if text.trim().is_empty() {
            c.execute("DELETE FROM notes WHERE record_id=?1", [record])?;
        } else {
            c.execute("INSERT INTO notes VALUES(?1,?2) ON CONFLICT(record_id) DO UPDATE SET text=excluded.text",params![record,text])?;
        }
        touch_view(c)?;
        tx.commit()?;
        Ok(())
    }
    pub fn read_note(session: &AnalysisSession, record: &str) -> Result<Option<String>> {
        Ok(db(session)?
            .lock()?
            .query_row("SELECT text FROM notes WHERE record_id=?1", [record], |r| {
                r.get(0)
            })
            .optional()?)
    }
    pub fn view_state(session: &AnalysisSession) -> Result<Option<serde_json::Value>> {
        let c = db(session)?.lock()?;
        let text: Option<String> = c
            .query_row("SELECT json FROM view_state WHERE key='filters'", [], |r| {
                r.get(0)
            })
            .optional()?;
        text.map(crate::storage::decode).transpose()
    }
    pub fn save_view_state(session: &AnalysisSession, value: &serde_json::Value) -> Result<()> {
        let c = db(session)?.lock()?;
        let value = json(value)?;
        let old: Option<String> = c
            .query_row("SELECT json FROM view_state WHERE key='filters'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if old.as_ref() != Some(&value) {
            c.execute("INSERT INTO view_state VALUES('filters',?1) ON CONFLICT(key) DO UPDATE SET json=excluded.json",[value])?;
            touch_view(&c)?;
        }
        Ok(())
    }
    pub fn query_options(session: &AnalysisSession) -> Result<Option<QueryOptions>> {
        let c = db(session)?.lock()?;
        c.query_row(
            "SELECT json FROM view_state WHERE key='cli_query'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .map(crate::storage::decode)
        .transpose()
    }
    pub fn save_query_options(session: &AnalysisSession, query: &QueryOptions) -> Result<()> {
        let mut c = db(session)?.lock()?;
        let tx = c.transaction()?;
        let encoded = json(query)?;
        let old = tx
            .query_row(
                "SELECT json FROM view_state WHERE key='cli_query'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        if old.as_ref() != Some(&encoded) {
            tx.execute("INSERT INTO view_state VALUES('cli_query',?1) ON CONFLICT(key) DO UPDATE SET json=excluded.json",[encoded])?;
            touch_view(&tx)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn append(
        session: &AnalysisSession,
        request: &AnalysisRequest,
        ctx: &ExecutionContext,
    ) -> Result<AnalysisOutcome> {
        let _operation = session.lock_operation(ctx)?;
        AnalysisService::validate(request)?;
        let store = db(session)?;
        let mut cancelled = false;
        let mut partial = false;
        let mut jobs = Vec::new();
        for input in &request.inputs {
            let mut one = request.clone();
            one.inputs = vec![input.clone()];
            one.auto_load = false;
            one.live_processes = false;
            one.ai = None;
            jobs.push(one);
        }
        if request.auto_load
            || request.live_processes
            || (request.mode == AnalysisMode::Processes && request.inputs.is_empty())
        {
            let mut one = request.clone();
            one.inputs.clear();
            one.ai = None;
            jobs.push(one);
        }
        let result = (|| -> Result<()> {
            for job in jobs {
                ctx.check()?;
                let outcome = AnalysisService::load(&job, ctx)?;
                outcome.session.with_report(|r| store.ingest(r, ctx))??;
                store.protect(&outcome.session.0.protected)?;
                cancelled |= outcome.status == TaskStatus::Cancelled;
                partial |= outcome.status == TaskStatus::Partial;
                if cancelled {
                    break;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            if core::execution::is_cancelled(&error) {
                cancelled = true;
            } else {
                return Err(error);
            }
        }
        {
            let c = store.lock()?;
            if cancelled {
                touch(&c)?;
                c.execute(
                    "INSERT INTO diagnostics(json) VALUES(?1)",
                    [crate::storage::packed_json(&core::Diagnostic {
                        level: DiagnosticLevel::Error,
                        source: "项目导入".into(),
                        position: None,
                        message: "导入已取消；保留已校验的证据，当前导入范围未完成。".into(),
                    })?],
                )?;
            }
        }
        Ok(AnalysisOutcome {
            session: session.clone(),
            status: if cancelled {
                TaskStatus::Cancelled
            } else if partial {
                TaskStatus::Partial
            } else {
                TaskStatus::Completed
            },
        })
    }
    pub fn validate_target(session: &AnalysisSession, path: &Path, config: &Path) -> Result<()> {
        let mut protected = db(session)?.protected()?;
        protected.push(config.into());
        crate::export::validate_output_paths(&[path.into()], &protected)
    }
    pub fn save(
        session: &AnalysisSession,
        path: &Path,
        config: &Path,
        overwrite: bool,
        ctx: &ExecutionContext,
    ) -> Result<PathBuf> {
        let _operation = session.lock_operation(ctx)?;
        let store = db(session)?;
        let status = Self::status(session)?;
        status.info.validate()?;
        let mut protected = store.protected()?;
        protected.push(config.to_path_buf());
        crate::export::validate_output_paths(&[path.to_path_buf()], &protected)?;
        let target = crate::export::resolved_path(path)?;
        let current = status.path.as_ref().map(PathBuf::from);
        if path.exists() {
            if current.as_ref() == Some(&target) {
                let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                let info = validate_file(&c, ctx)?;
                let rev: u64 = Database::get(&c, "revision")?;
                let saved: Option<u64> = Database::get(&*store.lock()?, "saved_revision")?;
                if info.id != status.info.id || Some(rev) != saved {
                    bail!("项目已被其他程序修改，请重新打开或另存为");
                }
            } else if !overwrite {
                bail!("目标文件已存在，请使用另存为或明确允许覆盖");
            }
        }
        let parent = target
            .parent()
            .ok_or_else(|| anyhow!("项目保存目录不可用"))?;
        fs::create_dir_all(parent)?;
        let temporary = tempfile::NamedTempFile::new_in(parent)?;
        {
            let mut dest = Connection::open(temporary.path())?;
            let source = store.lock()?;
            copy(&source, &mut dest, ctx)?;
            Database::configure(&dest)?;
            dest.execute_batch("DELETE FROM selections;DELETE FROM metadata WHERE key IN ('query_selection','path','saved_revision');PRAGMA journal_mode=DELETE;")?;
            Database::set(&dest, "saved_revision", &Some(status.revision))?;
            Database::set(&dest, "path", &Option::<String>::None)?;
            if dest.pragma_query_value(None, "freelist_count", |r| r.get::<_, i64>(0))? > 0 {
                crate::storage::with_progress(&dest, ctx, || Ok(dest.execute_batch("VACUUM;")?))?;
            }
        }
        temporary.as_file().sync_all()?;
        ctx.check()?;
        temporary
            .persist(&target)
            .map_err(|e| e.error)
            .context("无法保存项目；原文件保留")?;
        {
            let c = store.lock()?;
            Database::set(&c, "saved_revision", &Some(status.revision))?;
            Database::set(&c, "path", &Some(target.display().to_string()))?;
        }
        Ok(target)
    }
}

pub fn project_data_dir() -> Result<PathBuf> {
    if let Some(root) = std::env::var_os("EASY_ANALYZER_DATA_DIR") {
        return Ok(root.into());
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .ok_or_else(|| anyhow!("用户目录不可用"))?;
    Ok(if cfg!(target_os = "macos") {
        PathBuf::from(home).join("Library/Application Support/com.easyanalyzer.gui")
    } else if cfg!(windows) {
        PathBuf::from(std::env::var_os("APPDATA").ok_or_else(|| anyhow!("APPDATA 不可用"))?)
            .join("com.easyanalyzer.gui")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(home).join(".local/share"))
            .join("com.easyanalyzer.gui")
    })
}
pub struct ProjectCatalog {
    connection: MutexConnection,
}
type MutexConnection = std::sync::Mutex<Connection>;
impl ProjectCatalog {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        let c = Connection::open(root.join("projects.sqlite"))?;
        c.execute_batch("CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,path TEXT NOT NULL,json TEXT NOT NULL,last_opened TEXT NOT NULL);")?;
        Ok(Self {
            connection: std::sync::Mutex::new(c),
        })
    }
    pub fn register(&self, session: &AnalysisSession) -> Result<()> {
        let status = ProjectService::status(session)?;
        if let Some(path) = status.path {
            let c = self
                .connection
                .lock()
                .map_err(|_| anyhow!("项目目录不可用"))?;
            c.execute("INSERT INTO projects VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET path=excluded.path,json=excluded.json,last_opened=excluded.last_opened",params![status.info.id,path,json(&status.info)?,chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos,true)])?;
        }
        Ok(())
    }
    /// Remove only the catalog entry. The project file and open session are preserved.
    pub fn remove(&self, id: &str, path: &str) -> Result<()> {
        Uuid::parse_str(id).context("无效的项目 UUID")?;
        let c = self
            .connection
            .lock()
            .map_err(|_| anyhow!("项目目录不可用"))?;
        // Matching the displayed path also protects a project relocated since the list was read.
        if c.execute(
            "DELETE FROM projects WHERE id=?1 AND path=?2",
            params![id, path],
        )? == 0
        {
            bail!("项目列表已更新，请刷新后重试");
        }
        Ok(())
    }
    pub fn list(&self, search: &ProjectSearch) -> Result<Vec<ProjectEntry>> {
        let from = search
            .from
            .as_deref()
            .map(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d"))
            .transpose()?;
        let until = search
            .until
            .as_deref()
            .map(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d"))
            .transpose()?;
        if from.zip(until).is_some_and(|(f, u)| f > u) {
            bail!("开始日期不得晚于结束日期");
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| anyhow!("项目目录不可用"))?;
        let mut stmt =
            c.prepare("SELECT path,json,last_opened FROM projects ORDER BY last_opened DESC,id")?;
        let mut rows = stmt.query([])?;
        let mut out = vec![];
        while let Some(r) = rows.next()? {
            let info: ProjectInfo = crate::storage::decode(r.get(1)?)?;
            let date = DateTime::parse_from_rfc3339(&info.response_start)?.date_naive();
            if !info
                .name
                .to_lowercase()
                .contains(&search.text.to_lowercase())
                && !info
                    .client
                    .to_lowercase()
                    .contains(&search.text.to_lowercase())
            {
                continue;
            }
            if !info
                .client
                .to_lowercase()
                .contains(&search.client.to_lowercase())
                || from.is_some_and(|f| date < f)
                || until.is_some_and(|u| date > u)
            {
                continue;
            }
            let path: String = r.get(0)?;
            out.push(ProjectEntry {
                missing: !Path::new(&path).is_file(),
                path,
                info,
                last_opened: r.get(2)?,
            });
        }
        Ok(out)
    }
}
