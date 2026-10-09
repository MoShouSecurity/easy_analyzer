use crate::compression::{encode, row_text};
use crate::{core::*, *};
use anyhow::{Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

pub(crate) const APP_ID: i32 = 0x45414952;
pub(crate) const VERSION: i32 = 2;
#[derive(Debug)]
pub(crate) struct Database {
    pub connection: Mutex<Connection>,
    pub _directory: tempfile::TempDir,
    pub overview_cache: Mutex<Option<(u64, SessionOverview)>>,
    pub ai_summary_cache: Mutex<Option<(u64, std::collections::BTreeMap<String, String>)>>,
    pub diagnostic_count_cache: Mutex<Option<(i64, usize)>>,
    pub diagnostic_level_cache: Mutex<Option<(i64, (usize, usize))>>,
    pub process_cache: Mutex<Option<(i64, Arc<core::process::ProcessForest>)>>,
}
pub(crate) fn json<T: Serialize>(v: &T) -> Result<String> {
    Ok(serde_json::to_string(v)?)
}
pub(crate) fn packed_json<T: Serialize>(v: &T) -> Result<rusqlite::types::Value> {
    encode(json(v)?)
}
pub(crate) fn decode<T: DeserializeOwned>(v: String) -> Result<T> {
    Ok(serde_json::from_str(&v)?)
}
pub(crate) fn page_limit(limit: usize) -> Result<()> {
    if !(1..=1000).contains(&limit) {
        bail!("分页大小必须为 1 到 1000");
    }
    Ok(())
}
pub(crate) fn scalar(c: &Connection, sql: &str) -> Result<usize> {
    Ok(c.query_row(sql, [], |r| r.get::<_, i64>(0))? as usize)
}
pub(crate) fn with_progress<T>(
    c: &Connection,
    ctx: &ExecutionContext,
    run: impl FnOnce() -> Result<T>,
) -> Result<T> {
    ctx.check()?;
    let token = ctx.cancellation.clone();
    c.progress_handler(2048, Some(move || token.is_cancelled()))?;
    let result = run();
    c.progress_handler(0, None::<fn() -> bool>)?;
    ctx.check()?;
    result
}
pub(crate) fn values<T: DeserializeOwned>(
    c: &Connection,
    sql: &str,
    p: impl rusqlite::Params,
) -> Result<Vec<T>> {
    let mut stmt = c.prepare(sql)?;
    let mut rows = stmt.query(p)?;
    let mut out = vec![];
    while let Some(r) = rows.next()? {
        out.push(decode(row_text(r, 0)?)?);
    }
    Ok(out)
}
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE sources(id TEXT PRIMARY KEY,path TEXT NOT NULL,json TEXT NOT NULL);
CREATE TABLE records(ordinal INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,source_id TEXT NOT NULL REFERENCES sources(id),timestamp TEXT,status TEXT NOT NULL,kind TEXT NOT NULL,category TEXT NOT NULL,protocol TEXT NOT NULL,raw TEXT NOT NULL,data TEXT NOT NULL,preview TEXT NOT NULL,summary TEXT NOT NULL);
CREATE INDEX record_source ON records(source_id,ordinal);
CREATE INDEX record_kind ON records(kind,ordinal);
CREATE INDEX record_status ON records(status,ordinal);
CREATE INDEX record_category ON records(category,ordinal);
CREATE INDEX record_protocol ON records(protocol,ordinal);
CREATE TABLE findings(ordinal INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,origin TEXT NOT NULL,severity INTEGER NOT NULL,json TEXT NOT NULL);
CREATE INDEX finding_order ON findings(severity DESC,ordinal);
CREATE TABLE finding_refs(finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,record_id TEXT NOT NULL REFERENCES records(id),ordinal INTEGER NOT NULL,PRIMARY KEY(finding_id,record_id));
CREATE INDEX finding_record ON finding_refs(record_id,finding_id);
CREATE TABLE flows(ordinal INTEGER PRIMARY KEY,source_id TEXT NOT NULL REFERENCES sources(id),json TEXT NOT NULL);
CREATE TABLE flow_refs(flow_id INTEGER NOT NULL REFERENCES flows(ordinal) ON DELETE CASCADE,record_id TEXT NOT NULL REFERENCES records(id),ordinal INTEGER NOT NULL,PRIMARY KEY(flow_id,record_id));
CREATE INDEX flow_record ON flow_refs(record_id,flow_id);
CREATE TABLE diagnostics(ordinal INTEGER PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE ai_runs(ordinal INTEGER PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE ai_batches(run_id INTEGER NOT NULL REFERENCES ai_runs(ordinal),ordinal INTEGER NOT NULL,json TEXT NOT NULL,PRIMARY KEY(run_id,ordinal));
CREATE TABLE notes(record_id TEXT PRIMARY KEY REFERENCES records(id),text TEXT NOT NULL);
CREATE TABLE view_state(key TEXT PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE protected(path TEXT PRIMARY KEY);
CREATE TABLE iocs(id TEXT PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE ioc_origins(ioc_id TEXT NOT NULL REFERENCES iocs(id),origin TEXT NOT NULL,PRIMARY KEY(ioc_id,origin));
CREATE TABLE ioc_runs(id INTEGER PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE ioc_matches(ordinal INTEGER PRIMARY KEY,run_id INTEGER NOT NULL REFERENCES ioc_runs(id),ioc_id TEXT NOT NULL REFERENCES iocs(id),record_id TEXT NOT NULL REFERENCES records(id),json TEXT NOT NULL);
CREATE INDEX ioc_match_record ON ioc_matches(record_id);
CREATE TABLE selections(id INTEGER PRIMARY KEY,count INTEGER NOT NULL);
CREATE TABLE selection_refs(selection_id INTEGER NOT NULL REFERENCES selections(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,record_id TEXT NOT NULL REFERENCES records(id),PRIMARY KEY(selection_id,ordinal),UNIQUE(selection_id,record_id));
CREATE INDEX selection_record ON selection_refs(selection_id,record_id);
"#;
impl Database {
    pub fn new() -> Result<Arc<Self>> {
        let directory = tempfile::tempdir()?;
        let c = Connection::open(directory.path().join("working.sqlite"))?;
        Self::configure(&c)?;
        c.pragma_update(None, "application_id", APP_ID)?;
        c.pragma_update(None, "user_version", VERSION)?;
        c.execute_batch(SCHEMA)?;
        c.execute(
            "INSERT INTO metadata VALUES('report',?1)",
            [json(&AnalysisReport::default())?],
        )?;
        Ok(Self::from_connection(c, directory))
    }
    pub fn from_connection(c: Connection, directory: tempfile::TempDir) -> Arc<Self> {
        Arc::new(Self {
            connection: Mutex::new(c),
            _directory: directory,
            overview_cache: Mutex::default(),
            ai_summary_cache: Mutex::default(),
            diagnostic_count_cache: Mutex::default(),
            diagnostic_level_cache: Mutex::default(),
            process_cache: Mutex::default(),
        })
    }
    pub fn configure(c: &Connection) -> Result<()> {
        crate::compression::register(c)?;
        c.execute_batch("PRAGMA foreign_keys=ON;PRAGMA trusted_schema=OFF;PRAGMA temp_store=FILE;PRAGMA cache_size=-8192;PRAGMA journal_mode=DELETE;")?;
        c.busy_timeout(std::time::Duration::from_secs(2))?;
        Ok(())
    }
    pub fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow!("项目数据库不可用"))
    }
    pub fn set<T: Serialize>(c: &Connection, key: &str, value: &T) -> Result<()> {
        c.execute("INSERT INTO metadata VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key,json(value)?])?;
        Ok(())
    }
    pub fn get<T: DeserializeOwned>(c: &Connection, key: &str) -> Result<T> {
        decode(
            c.query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
                r.get(0)
            })?,
        )
    }
    pub fn protect(&self, paths: &[PathBuf]) -> Result<()> {
        let c = self.lock()?;
        for p in paths {
            c.execute(
                "INSERT OR IGNORE INTO protected VALUES(?1)",
                [p.to_string_lossy().as_ref()],
            )?;
        }
        Ok(())
    }
    pub fn protected(&self) -> Result<Vec<PathBuf>> {
        let c = self.lock()?;
        let mut s = c.prepare("SELECT path FROM protected UNION SELECT path FROM sources WHERE path NOT LIKE '%://%' AND path<>'stdin'")?;
        Ok(s.query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(PathBuf::from)
            .collect())
    }
    pub fn record(c: &Connection, id: &str) -> Result<Option<Record>> {
        let row = c.query_row("SELECT id,source_id,timestamp,status,raw,data,ordinal,json_extract(summary,'$.position') FROM records WHERE id=?1", [id], Self::record_row).optional()?;
        Ok(row.map(|r| r.1))
    }
    pub fn record_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, Record)> {
        let status: String = r.get(3)?;
        let data = row_text(r, 5)?;
        let parse = |e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        };
        Ok((
            r.get(6)?,
            Record {
                id: r.get(0)?,
                source_id: r.get(1)?,
                timestamp: r.get(2)?,
                status: serde_json::from_str(&status).map_err(parse)?,
                raw: row_text(r, 4)?,
                data: serde_json::from_str(&data).map_err(parse)?,
                position: r.get(7)?,
            },
        ))
    }
    pub fn records_after(&self, after: i64, limit: usize) -> Result<Vec<(i64, Record)>> {
        let c = self.lock()?;
        let mut stmt = c.prepare("SELECT id,source_id,timestamp,status,raw,data,ordinal,json_extract(summary,'$.position') FROM records WHERE ordinal>?1 ORDER BY ordinal LIMIT ?2")?;
        Ok(stmt
            .query_map(params![after, limit as i64], Self::record_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn insert_finding(c: &Connection, finding: &Finding) -> Result<usize> {
        let mut header = finding.clone();
        header.evidence_ids.clear();
        let mut changed=c.execute("INSERT INTO findings(id,origin,severity,json) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET origin=excluded.origin,severity=excluded.severity,json=excluded.json WHERE findings.json<>excluded.json", params![finding.id,finding.origin,finding.severity.rank(),json(&header)?])?;
        for (i, id) in finding.evidence_ids.iter().enumerate() {
            changed += c.execute(
                "INSERT OR IGNORE INTO finding_refs VALUES(?1,?2,?3)",
                params![finding.id, id, i as i64],
            )?;
        }
        Ok(changed)
    }
    pub fn finding(c: &Connection, data: String) -> Result<Finding> {
        let mut f: Finding = decode(data)?;
        let mut s =
            c.prepare("SELECT record_id FROM finding_refs WHERE finding_id=?1 ORDER BY ordinal")?;
        f.evidence_ids = s
            .query_map([&f.id], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(f)
    }
    pub fn ai(c: &Connection) -> Result<Vec<AiRun>> {
        let mut runs: Vec<AiRun> = values(c, "SELECT json FROM ai_runs ORDER BY ordinal", [])?;
        for (i, run) in runs.iter_mut().enumerate() {
            run.batch_results = values(
                c,
                "SELECT json FROM ai_batches WHERE run_id=?1 ORDER BY ordinal",
                [i as i64 + 1],
            )?;
        }
        Ok(runs)
    }
    pub fn insert_ai(c: &Connection, run: &AiRun) -> Result<()> {
        let mut header = run.clone();
        header.batch_results.clear();
        c.execute("INSERT INTO ai_runs(json) VALUES(?1)", [json(&header)?])?;
        let id = c.last_insert_rowid();
        for (i, b) in run.batch_results.iter().enumerate() {
            c.execute(
                "INSERT INTO ai_batches VALUES(?1,?2,?3)",
                params![id, i as i64, encode(json(b)?)?],
            )?;
        }
        Ok(())
    }
    pub fn ingest(&self, report: &AnalysisReport, ctx: &ExecutionContext) -> Result<usize> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let mut added = 0;
        let mut new_sources = 0;
        let mut changed_findings = 0;
        let mut changed_sources = std::collections::HashSet::new();
        for source in &report.sources {
            new_sources += tx.execute(
                "INSERT OR IGNORE INTO sources VALUES(?1,?2,?3)",
                params![source.id, source.path, json(source)?],
            )?;
        }
        let mut insert=tx.prepare("INSERT OR IGNORE INTO records(id,source_id,timestamp,status,kind,category,protocol,raw,data,preview,summary) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)")?;
        for (i, r) in report.records.iter().enumerate() {
            // A cancelled import may already contain validated, useful evidence. Persist it.
            if !ctx.cancellation.is_cancelled() {
                ctx.tick(
                    core::execution::Stage::Finalizing,
                    None,
                    i,
                    Some(report.records.len()),
                )?;
            }
            let (kind, cat, proto) = match &r.data {
                RecordData::Log(l) => ("log", l.category.as_str(), ""),
                RecordData::Process(_) => ("process", "", ""),
                RecordData::Packet(p) => ("packet", "", p.protocol.as_str()),
            };
            let mut preview = r.data.clone();
            if let RecordData::Packet(p) = &mut preview {
                p.payload_hex.clear();
            }
            let data = json(&r.data)?;
            let preview = json(&preview)?;
            let preview = if preview == data {
                rusqlite::types::Value::Text(String::new())
            } else {
                encode(preview)?
            };
            let n=insert.execute(params![r.id,r.source_id,r.timestamp,json(&r.status)?,kind,cat,proto,encode(r.raw.clone())?,encode(data)?,preview,json(&serde_json::json!({"position":r.position,"text":core::report::record_summary(r)}))?])?;
            added += n;
            if n > 0 {
                changed_sources.insert(&r.source_id);
            }
        }
        drop(insert);
        // A source may have been interrupted before. Replace its partial flow groups
        // with the groups from this parse, rather than duplicating the same sessions.
        for source in &changed_sources {
            tx.execute("DELETE FROM flows WHERE source_id=?1", [source])?;
        }
        for f in &report.findings {
            changed_findings += Self::insert_finding(&tx, f)?;
        }
        let record_sources: std::collections::HashMap<_, _> = report
            .records
            .iter()
            .map(|r| (&r.id, &r.source_id))
            .collect();
        for flow in &report.flows {
            let source = flow
                .evidence_ids
                .first()
                .and_then(|id| record_sources.get(id))
                .copied();
            let Some(source) = source else {
                continue;
            };
            if !changed_sources.contains(source) {
                continue;
            }
            let mut head = flow.clone();
            head.evidence_ids.clear();
            tx.execute(
                "INSERT INTO flows(source_id,json) VALUES(?1,?2)",
                params![source, json(&head)?],
            )?;
            let id = tx.last_insert_rowid();
            for (i, r) in flow.evidence_ids.iter().enumerate() {
                tx.execute(
                    "INSERT OR IGNORE INTO flow_refs VALUES(?1,?2,?3)",
                    params![id, r, i as i64],
                )?;
            }
        }
        let new_diagnostics = new_sources > 0 || added > 0 || report.sources.is_empty();
        if new_diagnostics {
            for d in &report.diagnostics {
                tx.execute(
                    "INSERT INTO diagnostics(json) VALUES(?1)",
                    [encode(json(d)?)?],
                )?;
            }
        }
        for run in &report.ai_runs {
            Self::insert_ai(&tx, run)?;
        }
        if new_sources > 0
            || added > 0
            || changed_findings > 0
            || (new_diagnostics && !report.diagnostics.is_empty())
            || !report.ai_runs.is_empty()
        {
            crate::project::touch(&tx)?;
        }
        tx.commit()?;
        Ok(added)
    }
    /// Explicit compatibility materialization; GUI pages and IOC never call this.
    pub fn report(&self) -> Result<AnalysisReport> {
        let mut report: AnalysisReport = {
            let c = self.lock()?;
            Self::get(&c, "report")?
        };
        let mut after = 0;
        loop {
            let batch = self.records_after(after, 256)?;
            if batch.is_empty() {
                break;
            }
            for (n, r) in batch {
                after = n;
                report.records.push(r);
            }
        }
        let c = self.lock()?;
        report.sources = values(&c, "SELECT json FROM sources ORDER BY rowid", [])?;
        let mut s = c.prepare("SELECT json FROM findings ORDER BY severity DESC,ordinal")?;
        let rows = s.query_map([], |r| r.get::<_, String>(0))?;
        for row in rows {
            report.findings.push(Self::finding(&c, row?)?);
        }
        report.flows = values(&c, "SELECT json FROM flows ORDER BY ordinal", [])?;
        for (i, f) in report.flows.iter_mut().enumerate() {
            let mut s =
                c.prepare("SELECT record_id FROM flow_refs WHERE flow_id=?1 ORDER BY ordinal")?;
            f.evidence_ids = s
                .query_map([i as i64 + 1], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
        }
        report.diagnostics = values(&c, "SELECT json FROM diagnostics ORDER BY ordinal", [])?;
        report.ai_runs = Self::ai(&c)?;
        if let Some(selection) = c
            .query_row(
                "SELECT value FROM metadata WHERE key='query_selection'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            && let Some(id) = serde_json::from_str::<Option<i64>>(&selection)?
        {
            let mut s = c.prepare(
                "SELECT record_id FROM selection_refs WHERE selection_id=?1 ORDER BY ordinal",
            )?;
            report.query_matches = Some(
                s.query_map([id], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<String>>>()?,
            );
        }
        Ok(report)
    }
    pub fn read_page(
        &self,
        selection: Option<i64>,
        offset: usize,
        limit: usize,
        payload: bool,
    ) -> Result<Page<RecordSummary>> {
        page_limit(limit)?;
        let c = self.lock()?;
        let total = if let Some(id) = selection {
            c.query_row("SELECT count FROM selections WHERE id=?1", [id], |r| {
                r.get::<_, i64>(0).map(|n| n as usize)
            })?
        } else {
            scalar(&c, "SELECT COUNT(*) FROM records")?
        };
        let data = if payload {
            "r.data"
        } else {
            "COALESCE(NULLIF(r.preview,''),r.data)"
        };
        let sql = if selection.is_some() {
            format!(
                "SELECT r.id,r.source_id,r.timestamp,r.status,{data},r.summary FROM selection_refs s JOIN records r ON r.id=s.record_id WHERE s.selection_id=?1 AND s.ordinal>=?3 ORDER BY s.ordinal LIMIT ?2"
            )
        } else {
            format!(
                "SELECT r.id,r.source_id,r.timestamp,r.status,{data},r.summary FROM records r WHERE ordinal>?3 ORDER BY ordinal LIMIT ?2"
            )
        };
        let mut s = c.prepare(&sql)?;
        let mut rows = s.query(params![
            selection.unwrap_or(0),
            limit as i64,
            offset.min(total) as i64
        ])?;
        let mut items = vec![];
        while let Some(r) = rows.next()? {
            items.push(Self::summary_row(r)?);
        }
        Ok(Page {
            offset,
            total,
            items,
        })
    }
    fn summary_row(r: &rusqlite::Row<'_>) -> Result<RecordSummary> {
        let summary: serde_json::Value = decode(r.get(5)?)?;
        Ok(RecordSummary {
            id: r.get(0)?,
            source_id: r.get(1)?,
            timestamp: r.get(2)?,
            status: decode(r.get(3)?)?,
            data: decode(row_text(r, 4)?)?,
            position: summary["position"].as_str().unwrap_or_default().into(),
            summary: summary["text"].as_str().unwrap_or_default().into(),
        })
    }
    pub fn read_lazy_page(
        &self,
        selection: &StoredSelection,
        offset: usize,
        limit: usize,
        payload: bool,
    ) -> Result<Page<RecordSummary>> {
        page_limit(limit)?;
        let c = self.lock()?;
        let mut membership = selection.membership();
        membership.arguments.push((limit as i64).into());
        membership
            .arguments
            .push((offset.min(selection.count) as i64).into());
        let data = if payload {
            "r.data"
        } else {
            "COALESCE(NULLIF(r.preview,''),r.data)"
        };
        let mut stmt = c.prepare(&format!("SELECT r.id,r.source_id,r.timestamp,r.status,{data},r.summary FROM records r WHERE {} ORDER BY r.ordinal LIMIT ? OFFSET ?", membership.predicate))?;
        let mut rows = stmt.query(rusqlite::params_from_iter(&membership.arguments))?;
        let mut items = Vec::new();
        while let Some(r) = rows.next()? {
            items.push(Self::summary_row(r)?);
        }
        Ok(Page {
            offset,
            total: selection.count,
            items,
        })
    }
    pub fn locate_lazy_record(
        &self,
        selection: &StoredSelection,
        id: &str,
    ) -> Result<Option<usize>> {
        let c = self.lock()?;
        let membership = selection.membership();
        let mut args = vec![rusqlite::types::Value::Text(id.into())];
        args.extend(membership.arguments.clone());
        let ordinal = c
            .query_row(
                &format!(
                    "SELECT r.ordinal FROM records r WHERE r.id=? AND {}",
                    membership.predicate
                ),
                rusqlite::params_from_iter(args),
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        ordinal
            .map(|ordinal| {
                let mut args = membership.arguments;
                args.push(ordinal.into());
                Ok(c.query_row(
                    &format!(
                        "SELECT COUNT(*) FROM records r WHERE {} AND r.ordinal<?",
                        membership.predicate
                    ),
                    rusqlite::params_from_iter(args),
                    |r| r.get::<_, i64>(0),
                )? as usize)
            })
            .transpose()
    }
}

#[derive(Debug)]
pub(crate) struct StoredSelection {
    pub db: Arc<Database>,
    pub id: i64,
    pub count: usize,
    pub ids: std::sync::OnceLock<Vec<String>>,
    pub lazy: Option<SqlSelection>,
    pub materialized: std::sync::OnceLock<()>,
}
#[derive(Debug)]
pub(crate) struct SqlSelection {
    pub predicate: String,
    pub arguments: Vec<rusqlite::types::Value>,
}
impl StoredSelection {
    pub fn membership(&self) -> SqlSelection {
        if let Some(lazy) = &self.lazy {
            SqlSelection {
                predicate: lazy.predicate.clone(),
                arguments: lazy.arguments.clone(),
            }
        } else {
            SqlSelection { predicate: "EXISTS(SELECT 1 FROM selection_refs s WHERE s.selection_id=? AND s.record_id=r.id)".into(), arguments: vec![self.id.into()] }
        }
    }
    pub fn materialize(&self, ctx: &ExecutionContext) -> Result<i64> {
        ctx.check()?;
        if let Some(lazy) = &self.lazy
            && self.materialized.get().is_none()
        {
            let mut c = self.db.lock()?;
            if self.materialized.get().is_none() {
                let tx = c.transaction()?;
                let sql = format!(
                    "INSERT INTO selection_refs SELECT {},ROW_NUMBER() OVER(ORDER BY r.ordinal)-1,r.id FROM records r WHERE {}",
                    self.id, lazy.predicate
                );
                with_progress(&tx, ctx, || {
                    Ok(tx.execute(&sql, rusqlite::params_from_iter(&lazy.arguments))?)
                })?;
                ctx.check()?;
                tx.commit()?;
                let _ = self.materialized.set(());
            }
        }
        Ok(self.id)
    }
    pub fn load_ids(&self) -> Result<&[String]> {
        if self.ids.get().is_none() {
            self.materialize(&ExecutionContext::default())?;
            let c = self.db.lock()?;
            let mut s = c.prepare(
                "SELECT record_id FROM selection_refs WHERE selection_id=?1 ORDER BY ordinal",
            )?;
            let ids = s
                .query_map([self.id], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            let _ = self.ids.set(ids);
        }
        Ok(self.ids.get().ok_or_else(|| anyhow!("筛选编号读取失败"))?)
    }
}
impl Database {
    pub fn select(
        self: &Arc<Self>,
        session_id: u64,
        filter: &RecordFilter,
        ctx: &ExecutionContext,
    ) -> Result<RecordSelection> {
        use rusqlite::types::Value;
        let search =
            core::rules::compile_query(filter.query.expression.as_deref(), filter.query.regex)?;
        let mut clauses = vec!["1=1".to_string()];
        let mut args: Vec<Value> = vec![];
        for (column, value) in [
            (
                "kind",
                match filter.kind {
                    RecordKind::All => None,
                    RecordKind::Log => Some("log".to_string()),
                    RecordKind::Process => Some("process".to_string()),
                    RecordKind::Packet => Some("packet".to_string()),
                },
            ),
            ("source_id", filter.source.clone()),
            ("category", filter.category.clone()),
            ("protocol", filter.protocol.clone()),
            ("status", filter.status.as_ref().map(json).transpose()?),
        ] {
            if let Some(v) = value {
                args.push(v.into());
                clauses.push(format!("r.{column}=?"));
            }
        }
        if filter.query.suspicious {
            clauses.push("EXISTS(SELECT 1 FROM finding_refs e JOIN findings f ON f.id=e.finding_id WHERE e.record_id=r.id AND f.origin LIKE 'local:%')".into());
        }
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        // Records are append-only. The upper ordinal freezes a typed selection
        // without copying every ID; text and finding-dependent selections stay materialized.
        let lazy = search.is_none() && !filter.query.suspicious;
        if lazy {
            args.push(
                tx.query_row("SELECT COALESCE(MAX(ordinal),0) FROM records", [], |r| {
                    r.get::<_, i64>(0)
                })?
                .into(),
            );
            clauses.push("r.ordinal<=?".into());
        }
        let where_sql = clauses.join(" AND ");
        tx.execute("INSERT INTO selections(count) VALUES(0)", [])?;
        let id = tx.last_insert_rowid();
        let mut count = 0;
        if let Some(search) = search {
            let mut s = tx.prepare(&format!(
                "SELECT id,raw,data FROM records r WHERE {where_sql} ORDER BY ordinal"
            ))?;
            let mut rows = s.query(rusqlite::params_from_iter(args.iter()))?;
            let mut n = 0;
            while let Some(r) = rows.next()? {
                ctx.tick(core::execution::Stage::Query, None, n, None)?;
                n += 1;
                let raw = row_text(r, 1)?;
                let data = row_text(r, 2)?;
                if search.is_match(&raw) || search.is_match(&data) {
                    tx.execute(
                        "INSERT INTO selection_refs VALUES(?1,?2,?3)",
                        params![id, count as i64, r.get::<_, String>(0)?],
                    )?;
                    count += 1;
                }
            }
        } else if lazy {
            count = with_progress(&tx, ctx, || {
                Ok(tx.query_row(
                    &format!("SELECT COUNT(*) FROM records r WHERE {where_sql}"),
                    rusqlite::params_from_iter(&args),
                    |r| r.get::<_, i64>(0),
                )? as usize)
            })?;
        } else {
            let token = ctx.cancellation.clone();
            tx.progress_handler(2048, Some(move || token.is_cancelled()))?;
            let sql = format!(
                "INSERT INTO selection_refs SELECT {id},ROW_NUMBER() OVER(ORDER BY r.ordinal)-1,r.id FROM records r WHERE {where_sql}"
            );
            let result = tx.execute(&sql, rusqlite::params_from_iter(args.iter()));
            tx.progress_handler(0, None::<fn() -> bool>)?;
            ctx.check()?;
            count = result?;
        }
        tx.execute(
            "UPDATE selections SET count=?1 WHERE id=?2",
            params![count as i64, id],
        )?;
        ctx.check()?;
        tx.commit()?;
        Ok(RecordSelection {
            session_id,
            ids: vec![],
            stored: Some(Arc::new(StoredSelection {
                db: self.clone(),
                id,
                count,
                ids: Default::default(),
                lazy: lazy.then_some(SqlSelection {
                    predicate: where_sql,
                    arguments: args,
                }),
                materialized: Default::default(),
            })),
        })
    }
    pub fn overview(&self, ctx: &ExecutionContext) -> Result<SessionOverview> {
        ctx.check()?;
        let c = self.lock()?;
        let revision = crate::project::content_revision(&c)?;
        let mut cache = self
            .overview_cache
            .lock()
            .map_err(|_| anyhow!("项目统计缓存不可用"))?;
        if let Some((old, overview)) = cache.as_ref()
            && *old == revision
        {
            return Ok(overview.clone());
        }
        let out = with_progress(&c, ctx, || Self::compute_overview(&c, ctx))?;
        *cache = Some((revision, out.clone()));
        Ok(out)
    }
    pub(crate) fn compute_overview(
        c: &Connection,
        ctx: &ExecutionContext,
    ) -> Result<SessionOverview> {
        let mut out = SessionOverview {
            sources: scalar(c, "SELECT COUNT(*) FROM sources")?,
            records: scalar(c, "SELECT COUNT(*) FROM records")?,
            flows: scalar(c, "SELECT COUNT(*) FROM flows")?,
            suspicious: scalar(
                c,
                "SELECT COUNT(DISTINCT e.record_id) FROM finding_refs e JOIN findings f ON f.id=e.finding_id WHERE f.origin LIKE 'local:%'",
            )?,
            ..Default::default()
        };
        // Separate covering indices avoid reading every multi-kilobyte evidence row.
        let mut s = c.prepare("SELECT kind,COUNT(*) FROM records GROUP BY kind")?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            ctx.check()?;
            let n = r.get::<_, i64>(1)? as usize;
            match r.get::<_, String>(0)?.as_str() {
                "log" => out.logs += n,
                "process" => out.processes += n,
                "packet" => out.packets += n,
                _ => {}
            }
        }
        let mut s = c.prepare("SELECT status,COUNT(*) FROM records GROUP BY status")?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            ctx.check()?;
            let n = r.get::<_, i64>(1)? as usize;
            match decode::<ParseStatus>(r.get(0)?)? {
                ParseStatus::Parsed => out.parse_counts[0] += n,
                ParseStatus::Unrecognized => out.parse_counts[1] += n,
                ParseStatus::Malformed => out.parse_counts[2] += n,
            }
        }
        let mut s=c.prepare("SELECT severity,origin LIKE 'local:%',COUNT(*) FROM findings GROUP BY severity,origin LIKE 'local:%'")?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            let n = r.get::<_, i64>(2)? as usize;
            out.risks[r.get::<_, i64>(0).map(|n| n as usize)?] += n;
            if r.get::<_, bool>(1)? {
                out.local_findings += n
            } else {
                out.ai_findings += n
            }
        }
        for (sql, target) in [
            (
                "SELECT DISTINCT category FROM records WHERE category<>'' ORDER BY category",
                &mut out.categories,
            ),
            (
                "SELECT DISTINCT protocol FROM records WHERE protocol<>'' ORDER BY protocol",
                &mut out.protocols,
            ),
        ] {
            let mut s = c.prepare(sql)?;
            *target = s
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
        }
        Ok(out)
    }
    pub fn finding_page(
        &self,
        filter: &FindingFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Page<Finding>> {
        page_limit(limit)?;
        let c = self.lock()?;
        let local = match filter.origin {
            FindingOrigin::All => None,
            FindingOrigin::Local => Some(true),
            FindingOrigin::Ai => Some(false),
        };
        let args = params![filter.severity.as_ref().map(|s| s.rank()), local];
        let condition =
            "(?1 IS NULL OR severity=?1) AND (?2 IS NULL OR (origin LIKE 'local:%')=?2)";
        let total = c.query_row(
            &format!("SELECT COUNT(*) FROM findings WHERE {condition}"),
            args,
            |r| r.get::<_, i64>(0).map(|n| n as usize),
        )?;
        let mut s=c.prepare(&format!("SELECT json FROM findings WHERE {condition} ORDER BY severity DESC,ordinal LIMIT ?3 OFFSET ?4"))?;
        let mut rows = s.query(params![
            filter.severity.as_ref().map(|s| s.rank()),
            local,
            limit as i64,
            offset.min(i64::MAX as usize) as i64
        ])?;
        let mut items = vec![];
        while let Some(r) = rows.next()? {
            items.push(Self::finding(&c, r.get(0)?)?);
        }
        Ok(Page {
            offset,
            total,
            items,
        })
    }
    pub fn source_page(&self, offset: usize, limit: usize) -> Result<Page<Source>> {
        page_limit(limit)?;
        let c = self.lock()?;
        Ok(Page {
            offset,
            total: scalar(&c, "SELECT COUNT(*) FROM sources")?,
            items: values(
                &c,
                "SELECT json FROM sources ORDER BY rowid LIMIT ?1 OFFSET ?2",
                params![limit as i64, offset.min(i64::MAX as usize) as i64],
            )?,
        })
    }
    pub fn diagnostic_page(&self, offset: usize, limit: usize) -> Result<Page<Diagnostic>> {
        page_limit(limit)?;
        let total = self.diagnostic_count()?;
        let c = self.lock()?;
        Ok(Page {
            offset,
            total,
            items: values(
                &c,
                "SELECT json FROM diagnostics ORDER BY ordinal LIMIT ?1 OFFSET ?2",
                params![limit as i64, offset.min(i64::MAX as usize) as i64],
            )?,
        })
    }
    pub fn diagnostic_count(&self) -> Result<usize> {
        let c = self.lock()?;
        let last = c.query_row(
            "SELECT COALESCE(MAX(ordinal),0) FROM diagnostics",
            [],
            |r| r.get::<_, i64>(0),
        )?;
        let mut cache = self
            .diagnostic_count_cache
            .lock()
            .map_err(|_| anyhow!("诊断统计缓存不可用"))?;
        if let Some((old, count)) = *cache
            && old == last
        {
            return Ok(count);
        }
        let count = scalar(&c, "SELECT COUNT(*) FROM diagnostics")?;
        *cache = Some((last, count));
        Ok(count)
    }
    pub fn diagnostic_levels(&self, ctx: &ExecutionContext) -> Result<(usize, usize)> {
        ctx.check()?;
        let c = self.lock()?;
        let last = c.query_row(
            "SELECT COALESCE(MAX(ordinal),0) FROM diagnostics",
            [],
            |r| r.get::<_, i64>(0),
        )?;
        let mut cache = self
            .diagnostic_level_cache
            .lock()
            .map_err(|_| anyhow!("诊断统计缓存不可用"))?;
        if let Some((old, counts)) = *cache
            && old == last
        {
            return Ok(counts);
        }
        let counts = with_progress(&c, ctx, || {
            let mut stmt = c.prepare("SELECT json_extract(eair_text(json),'$.level'),COUNT(*) FROM diagnostics GROUP BY 1")?;
            let mut rows = stmt.query([])?;
            let (mut errors, mut warnings) = (0, 0);
            while let Some(r) = rows.next()? {
                let count = r.get::<_, i64>(1)? as usize;
                if r.get::<_, String>(0)? == "error" {
                    errors += count;
                } else {
                    warnings += count;
                }
            }
            Ok((errors, warnings))
        })?;
        *cache = Some((last, counts));
        Ok(counts)
    }
    pub fn flow_page(
        &self,
        selection: Option<&StoredSelection>,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
    ) -> Result<Page<FlowSummary>> {
        page_limit(limit)?;
        let c = self.lock()?;
        let membership = selection.map(StoredSelection::membership);
        let predicate = membership.as_ref().map_or_else(|| "1=1".into(), |m| format!("EXISTS(SELECT 1 FROM flow_refs e JOIN records r ON r.id=e.record_id WHERE e.flow_id=f.ordinal AND {})",m.predicate));
        let args = membership
            .as_ref()
            .map_or_else(Vec::new, |m| m.arguments.clone());
        let total = with_progress(&c, ctx, || {
            Ok(c.query_row(
                &format!("SELECT COUNT(*) FROM flows f WHERE {predicate}"),
                rusqlite::params_from_iter(&args),
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )?)
        })?;
        let mut page_args = args.clone();
        page_args.push((limit as i64).into());
        page_args.push((offset.min(i64::MAX as usize) as i64).into());
        let mut stmt=c.prepare(&format!("SELECT ordinal,source_id,json FROM flows f WHERE {predicate} ORDER BY ordinal LIMIT ? OFFSET ?"))?;
        let mut rows = stmt.query(rusqlite::params_from_iter(page_args))?;
        let mut items = vec![];
        while let Some(r) = rows.next()? {
            let id: i64 = r.get(0)?;
            let f: NetworkFlow = decode(r.get(2)?)?;
            ctx.check()?;
            let matched = if let Some(m) = &membership {
                let mut count_args = vec![id.into()];
                count_args.extend(args.clone());
                with_progress(&c, ctx, || {
                    Ok(c.query_row(&format!("SELECT COUNT(*) FROM flow_refs e JOIN records r ON r.id=e.record_id WHERE e.flow_id=? AND {}",m.predicate),rusqlite::params_from_iter(count_args),|r|r.get::<_,i64>(0).map(|n|n as usize))?)
                })?
            } else {
                f.packets
            };
            items.push(FlowSummary {
                key: (id - 1) as usize,
                source_id: r.get(1)?,
                endpoint_a: f.endpoint_a,
                endpoint_b: f.endpoint_b,
                protocol: f.protocol,
                packets: f.packets,
                matched_packets: matched,
                bytes: f.bytes,
                first_seen: f.first_seen,
                last_seen: f.last_seen,
            });
        }
        Ok(Page {
            offset,
            total,
            items,
        })
    }
    pub fn flow_selection(
        self: &Arc<Self>,
        session_id: u64,
        key: usize,
        selection: Option<&StoredSelection>,
        ctx: &ExecutionContext,
    ) -> Result<RecordSelection> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        if scalar(
            &tx,
            &format!("SELECT COUNT(*) FROM flows WHERE ordinal={}", key + 1),
        )? == 0
        {
            bail!("会话不存在");
        }
        tx.execute("INSERT INTO selections VALUES(NULL,0)", [])?;
        let id = tx.last_insert_rowid();
        ctx.check()?;
        let membership = selection
            .map(StoredSelection::membership)
            .unwrap_or(SqlSelection {
                predicate: "1=1".into(),
                arguments: vec![],
            });
        let mut args = vec![id.into(), ((key + 1) as i64).into()];
        args.extend(membership.arguments);
        let count = with_progress(&tx, ctx, || {
            Ok(tx.execute(&format!("INSERT INTO selection_refs SELECT ?,ROW_NUMBER() OVER(ORDER BY e.ordinal)-1,e.record_id FROM flow_refs e JOIN records r ON r.id=e.record_id WHERE e.flow_id=? AND {}",membership.predicate),rusqlite::params_from_iter(args))?)
        })?;
        tx.execute(
            "UPDATE selections SET count=?1 WHERE id=?2",
            params![count as i64, id],
        )?;
        tx.commit()?;
        Ok(RecordSelection {
            session_id,
            ids: vec![],
            stored: Some(Arc::new(StoredSelection {
                db: self.clone(),
                id,
                count,
                ids: Default::default(),
                lazy: None,
                materialized: Default::default(),
            })),
        })
    }
    fn process_records(&self, ctx: &ExecutionContext) -> Result<Vec<Record>> {
        let c = self.lock()?;
        with_progress(&c, ctx, || {
            let mut s=c.prepare("SELECT id,source_id,timestamp,status,'',json_remove(eair_text(data),'$.fields.command','$.fields.path','$.fields.user','$.fields.start_time','$.fields.status'),ordinal,json_extract(summary,'$.position') FROM records WHERE kind='process' ORDER BY ordinal")?;
            Ok(s.query_map([], Self::record_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|r| r.1)
                .collect())
        })
    }
    pub fn process_forest(
        &self,
        ctx: &ExecutionContext,
    ) -> Result<Arc<core::process::ProcessForest>> {
        ctx.check()?;
        let last =
            self.lock()?
                .query_row("SELECT COALESCE(MAX(ordinal),0) FROM records", [], |r| {
                    r.get::<_, i64>(0)
                })?;
        let mut cache = self
            .process_cache
            .lock()
            .map_err(|_| anyhow!("进程树缓存不可用"))?;
        if let Some((old, forest)) = cache.as_ref()
            && *old == last
        {
            return Ok(forest.clone());
        }
        let forest = Arc::new(core::process::process_forest_with_context(
            &self.process_records(ctx)?,
            ctx,
        )?);
        *cache = Some((last, forest.clone()));
        Ok(forest)
    }
}
impl Database {
    pub fn selected_records_after(
        &self,
        selection: i64,
        after: i64,
        limit: usize,
        payload: bool,
    ) -> Result<Vec<(i64, Record)>> {
        let c = self.lock()?;
        let fields = if payload {
            "r.raw,r.data"
        } else {
            "CASE WHEN r.kind='packet' THEN '' ELSE r.raw END,COALESCE(NULLIF(r.preview,''),r.data)"
        };
        let mut s=c.prepare(&format!("SELECT r.id,r.source_id,r.timestamp,r.status,{fields},s.ordinal,json_extract(r.summary,'$.position') FROM selection_refs s JOIN records r ON r.id=s.record_id WHERE s.selection_id=?1 AND s.ordinal>?2 ORDER BY s.ordinal LIMIT ?3"))?;
        Ok(
            s.query_map(params![selection, after, limit as i64], Self::record_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        )
    }
}

impl Drop for StoredSelection {
    fn drop(&mut self) {
        if let Ok(c) = self.db.lock() {
            let current = Database::get::<Option<i64>>(&c, "query_selection").unwrap_or(None);
            if current != Some(self.id) {
                let _ = c.execute("DELETE FROM selections WHERE id=?1", [self.id]);
            }
        }
    }
}
impl Database {
    pub fn ioc_records_after(&self, after: i64, limit: usize) -> Result<Vec<(i64, Record)>> {
        let c = self.lock()?;
        let mut s=c.prepare("SELECT id,source_id,timestamp,status,CASE WHEN kind='packet' OR category IN ('utmp','wtmp','btmp') THEN '' ELSE raw END,COALESCE(NULLIF(preview,''),data),ordinal,json_extract(summary,'$.position') FROM records WHERE ordinal>?1 ORDER BY ordinal LIMIT ?2")?;
        Ok(s.query_map(params![after, limit as i64], Self::record_row)?
            .collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
