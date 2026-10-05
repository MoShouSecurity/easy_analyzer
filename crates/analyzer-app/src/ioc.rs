use crate::{
    core::{
        self,
        ioc::{Indicator, IocMatcher},
    },
    storage::{Database, json, scalar, values},
    *,
};
use anyhow::{Result, anyhow, bail};
pub use core::ioc::{IocImport, IocIssue, IocType};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocRun {
    pub id: i64,
    pub total_records: usize,
    pub scanned_records: usize,
    pub complete: bool,
    pub include_subdomains: bool,
    pub ioc_revision: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct IocStatus {
    pub indicators: usize,
    pub records: usize,
    pub run: Option<IocRun>,
    pub needs_rescan: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocHit {
    pub value: String,
    pub note: String,
    pub indicator_id: String,
    pub record_id: String,
    pub source_id: String,
    pub position: String,
    pub timestamp: Option<String>,
    pub field: String,
    pub matched_value: String,
    pub byte_offset: Option<usize>,
}
fn store(session: &AnalysisSession) -> Result<&std::sync::Arc<Database>> {
    session
        .0
        .store
        .as_ref()
        .ok_or_else(|| anyhow!("IOC 操作需要一个项目"))
}
pub struct IocService;
#[derive(Debug, Clone)]
pub enum IocSource {
    File(std::path::PathBuf),
    Text {
        text: String,
        csv: bool,
        origin: String,
    },
    Value {
        value: String,
        kind: Option<IocType>,
        note: String,
    },
}
impl IocService {
    /// One mixed import: reject individual invalid inputs while accepting the rest.
    pub fn import(
        session: &AnalysisSession,
        inputs: &[IocSource],
        ctx: &ExecutionContext,
    ) -> Result<IocImport> {
        let mut result = IocImport::default();
        for input in inputs {
            ctx.check()?;
            let (origin, imported) = match input {
                IocSource::File(path) => (
                    path.display().to_string(),
                    Self::add_file(session, path, ctx),
                ),
                IocSource::Text { text, csv, origin } => (
                    origin.clone(),
                    Self::add_text(session, text, *csv, origin, ctx),
                ),
                IocSource::Value { value, kind, note } => (
                    format!("手动输入 {value}"),
                    Self::add_value(session, value, *kind, note, ctx),
                ),
            };
            match imported {
                Ok(imported) => {
                    result.indicators.extend(imported.indicators);
                    result
                        .issues
                        .extend(imported.issues.into_iter().map(|mut issue| {
                            issue.message = format!("{origin}：{}", issue.message);
                            issue
                        }));
                }
                Err(e) if core::execution::is_cancelled(&e) => return Err(e),
                Err(e) => result.issues.push(IocIssue {
                    line: 1,
                    message: format!("{origin}：{e:#}"),
                }),
            }
        }
        if result.indicators.is_empty() {
            bail!(
                "没有有效 IOC；原清单保留。{}",
                result
                    .issues
                    .iter()
                    .map(|i| i.message.as_str())
                    .collect::<Vec<_>>()
                    .join("；")
            );
        }
        Ok(result)
    }
    pub fn add_text(
        session: &AnalysisSession,
        text: &str,
        csv: bool,
        origin: &str,
        ctx: &ExecutionContext,
    ) -> Result<IocImport> {
        let parsed = core::ioc::import_text(text, csv, ctx)?;
        Self::add(session, parsed, origin, ctx)
    }
    pub fn add_value(
        session: &AnalysisSession,
        value: &str,
        kind: Option<IocType>,
        note: &str,
        ctx: &ExecutionContext,
    ) -> Result<IocImport> {
        Self::add(
            session,
            IocImport {
                indicators: vec![core::ioc::indicator(value, kind, note)?],
                issues: vec![],
            },
            "手动输入",
            ctx,
        )
    }
    fn add(
        session: &AnalysisSession,
        parsed: IocImport,
        origin: &str,
        ctx: &ExecutionContext,
    ) -> Result<IocImport> {
        if parsed.indicators.is_empty() {
            bail!(
                "没有有效 IOC；原清单保留。{}",
                parsed
                    .issues
                    .iter()
                    .map(|e| format!("第 {} 行：{}", e.line, e.message))
                    .collect::<Vec<_>>()
                    .join("；")
            );
        }
        let _operation = session.lock_operation(ctx)?;
        let mut c = store(session)?.lock()?;
        let tx = c.transaction()?;
        for item in &parsed.indicators {
            ctx.check()?;
            let existing: Vec<Indicator> =
                values(&tx, "SELECT json FROM iocs WHERE id=?1", [&item.id])?;
            let mut item = item.clone();
            if item.note.is_empty()
                && let Some(old) = existing.first()
            {
                item.note = old.note.clone();
            }
            tx.execute(
                "INSERT INTO iocs VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET json=excluded.json",
                params![item.id, json(&item)?],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO ioc_origins VALUES(?1,?2)",
                params![item.id, origin],
            )?;
        }
        let rev = Database::get::<u64>(&tx, "ioc_revision").unwrap_or(0);
        Database::set(&tx, "ioc_revision", &(rev + 1))?;
        crate::project::touch(&tx)?;
        tx.commit()?;
        Ok(parsed)
    }
    pub fn add_file(
        session: &AnalysisSession,
        path: &Path,
        ctx: &ExecutionContext,
    ) -> Result<IocImport> {
        if fs::metadata(path)?.len() > 64 * 1024 * 1024 {
            bail!("IOC 清单超过 64 MiB 上限");
        }
        let text = fs::read_to_string(path)?;
        let parsed = Self::add_text(
            session,
            &text,
            path.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("csv")),
            &path.display().to_string(),
            ctx,
        )?;
        store(session)?.protect(&[path.to_path_buf()])?;
        Ok(parsed)
    }
    pub fn indicators(
        session: &AnalysisSession,
        offset: usize,
        limit: usize,
    ) -> Result<Page<Indicator>> {
        crate::storage::page_limit(limit)?;
        let c = store(session)?.lock()?;
        Ok(Page {
            offset,
            total: scalar(&c, "SELECT COUNT(*) FROM iocs")?,
            items: values(
                &c,
                "SELECT json FROM iocs ORDER BY rowid LIMIT ?1 OFFSET ?2",
                params![limit as i64, offset.min(i64::MAX as usize) as i64],
            )?,
        })
    }
    pub fn edit_note(
        session: &AnalysisSession,
        id: &str,
        note: &str,
        ctx: &ExecutionContext,
    ) -> Result<()> {
        let _op = session.lock_operation(ctx)?;
        let mut c = store(session)?.lock()?;
        let tx = c.transaction()?;
        let c = &tx;
        let mut items: Vec<Indicator> = values(c, "SELECT json FROM iocs WHERE id=?1", [id])?;
        let item = items
            .first_mut()
            .ok_or_else(|| anyhow!("IOC 不属于当前项目"))?;
        let old_note = item.note.clone();
        item.note = note.into();
        c.execute(
            "UPDATE iocs SET json=?1 WHERE id=?2",
            params![json(item)?, id],
        )?;
        c.execute(
            "UPDATE ioc_matches SET json=json_set(json,'$.note',?1) WHERE ioc_id=?2",
            params![note, id],
        )?;
        let prefix = format!("ioc:{id}:%");
        c.execute("UPDATE findings SET json=json_set(json,'$.description',?1||char(10)||substr(json_extract(json,'$.description'),?2)) WHERE id LIKE ?3 AND origin='local:ioc'",params![note,(old_note.chars().count()+2) as i64,prefix])?;
        crate::project::touch(c)?;
        tx.commit()?;
        Ok(())
    }
    pub fn status(session: &AnalysisSession) -> Result<IocStatus> {
        let c = store(session)?.lock()?;
        let runs: Vec<IocRun> =
            values(&c, "SELECT json FROM ioc_runs ORDER BY id DESC LIMIT 1", [])?;
        let run = runs.into_iter().next();
        let records = scalar(&c, "SELECT COUNT(*) FROM records")?;
        let indicators = scalar(&c, "SELECT COUNT(*) FROM iocs")?;
        let revision = Database::get::<u64>(&c, "ioc_revision").unwrap_or(0);
        let needs_rescan = indicators > 0
            && run.as_ref().is_none_or(|r| {
                !r.complete || r.total_records != records || r.ioc_revision != revision
            });
        Ok(IocStatus {
            indicators,
            records,
            run,
            needs_rescan,
        })
    }
    pub fn matches(session: &AnalysisSession, offset: usize, limit: usize) -> Result<Page<IocHit>> {
        crate::storage::page_limit(limit)?;
        let c = store(session)?.lock()?;
        Ok(Page {
            offset,
            total: scalar(&c, "SELECT COUNT(*) FROM ioc_matches")?,
            items: values(
                &c,
                "SELECT json FROM ioc_matches ORDER BY ordinal LIMIT ?1 OFFSET ?2",
                params![limit as i64, offset.min(i64::MAX as usize) as i64],
            )?,
        })
    }
    pub fn scan(
        session: &AnalysisSession,
        subdomains: bool,
        ctx: &ExecutionContext,
    ) -> Result<IocRun> {
        let _op = session.lock_operation(ctx)?;
        let db = store(session)?;
        let (items, total, revision) = {
            let c = db.lock()?;
            (
                values::<Indicator>(&c, "SELECT json FROM iocs ORDER BY id", [])?,
                scalar(&c, "SELECT COUNT(*) FROM records")?,
                Database::get::<u64>(&c, "ioc_revision").unwrap_or(0),
            )
        };
        if items.is_empty() {
            bail!("请先添加 IOC");
        }
        ctx.check()?;
        let matcher = IocMatcher::new(&items, subdomains);
        let lookup: BTreeMap<_, _> = items.iter().map(|i| (&i.id, i)).collect();
        let mut run = IocRun {
            id: 0,
            total_records: total,
            scanned_records: 0,
            complete: false,
            include_subdomains: subdomains,
            ioc_revision: revision,
        };
        {
            let mut c = db.lock()?;
            let tx = c.transaction()?;
            tx.execute("INSERT INTO ioc_runs(json) VALUES(?1)", [json(&run)?])?;
            run.id = tx.last_insert_rowid();
            // Keep earlier valid hits for unvisited records if this scan is interrupted.
            crate::project::touch(&tx)?;
            tx.commit()?;
        }
        let mut after = 0;
        let mut cancelled = false;
        loop {
            if ctx.cancellation.is_cancelled() {
                cancelled = true;
                break;
            }
            let batch = db.ioc_records_after(after, 256)?;
            if batch.is_empty() {
                break;
            }
            let mut c = db.lock()?;
            let tx = c.transaction()?;
            let mut prior = tx.prepare("SELECT m.record_id FROM ioc_matches m JOIN records r ON r.id=m.record_id WHERE r.ordinal>?1 AND r.ordinal<=?2")?;
            let previous_hits = prior
                .query_map(
                    params![after, batch.last().map(|r| r.0).unwrap_or(after)],
                    |r| r.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?;
            drop(prior);
            for (ordinal, record) in batch {
                let found = match matcher.record(&record, ctx) {
                    Ok(m) => m,
                    Err(e) if core::execution::is_cancelled(&e) => {
                        cancelled = true;
                        break;
                    }
                    Err(e) => return Err(e),
                };
                if previous_hits.contains(&record.id) {
                    tx.execute("DELETE FROM findings WHERE origin='local:ioc' AND id IN (SELECT finding_id FROM finding_refs WHERE record_id=?1)", [&record.id])?;
                    tx.execute("DELETE FROM ioc_matches WHERE record_id=?1", [&record.id])?;
                }
                let mut matched = BTreeMap::<String, Vec<String>>::new();
                for m in found {
                    let hit = IocHit {
                        value: lookup[&m.indicator_id].value.clone(),
                        note: lookup[&m.indicator_id].note.clone(),
                        indicator_id: m.indicator_id.clone(),
                        record_id: record.id.clone(),
                        source_id: record.source_id.clone(),
                        position: record.position.clone(),
                        timestamp: record.timestamp.clone(),
                        field: m.field.clone(),
                        matched_value: m.matched_value.clone(),
                        byte_offset: m.byte_offset,
                    };
                    tx.execute(
                        "INSERT INTO ioc_matches(run_id,ioc_id,record_id,json) VALUES(?1,?2,?3,?4)",
                        params![run.id, m.indicator_id, record.id, json(&hit)?],
                    )?;
                    matched
                        .entry(m.indicator_id)
                        .or_default()
                        .push(format!("{} = {}", m.field, m.matched_value));
                }
                for (id, fields) in matched {
                    let item = lookup[&id];
                    Database::insert_finding(
                        &tx,
                        &core::Finding {
                            id: format!("ioc:{id}:{}", record.id),
                            origin: "local:ioc".into(),
                            severity: core::Severity::Medium,
                            title: format!("IOC 命中：{}", item.value),
                            description: format!(
                                "{}\n{}\n仅证明证据出现该 IOC，需结合来源和业务用途核查。",
                                item.note,
                                fields.join("；")
                            ),
                            evidence_ids: vec![record.id.clone()],
                            confidence: 1.0,
                            recommendations: vec!["核查该地址的访问目的、时段和关联行为。".into()],
                        },
                    )?;
                }
                after = ordinal;
                run.scanned_records += 1;
                ctx.emit(
                    core::execution::Stage::Rules,
                    Some("IOC 匹配"),
                    run.scanned_records,
                    Some(total),
                );
            }
            tx.execute(
                "UPDATE ioc_runs SET json=?1 WHERE id=?2",
                params![json(&run)?, run.id],
            )?;
            tx.commit()?;
            if cancelled {
                break;
            }
        }
        run.complete = !cancelled && run.scanned_records == total;
        {
            let c = db.lock()?;
            c.execute(
                "UPDATE ioc_runs SET json=?1 WHERE id=?2",
                params![json(&run)?, run.id],
            )?;
            c.execute("DELETE FROM ioc_runs WHERE id<>?1 AND NOT EXISTS(SELECT 1 FROM ioc_matches WHERE run_id=ioc_runs.id)", [run.id])?;
            if !run.complete {
                c.execute(
                    "INSERT INTO diagnostics(json) VALUES(?1)",
                    [json(&core::Diagnostic {
                        level: DiagnosticLevel::Warning,
                        source: "IOC 匹配".into(),
                        position: None,
                        message: format!(
                            "扫描未完成：已扫描 {} / {} 条，保留有效命中。",
                            run.scanned_records, total
                        ),
                    })?],
                )?;
            }
            crate::project::touch(&c)?;
        }
        Ok(run)
    }
}
