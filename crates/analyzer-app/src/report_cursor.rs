use crate::{
    core::{report::stream::*, *},
    storage::{Database, decode, scalar, values},
    *,
};
use anyhow::Result;
use rusqlite::{OptionalExtension, params};

pub(crate) struct ProjectCursor<'a>(pub &'a AnalysisSession);
impl ReportCursor for ProjectCursor<'_> {
    fn metadata(&self) -> Result<Metadata> {
        let db = self.0.0.store.as_ref().expect("project cursor");
        let c = db.lock()?;
        let report: AnalysisReport = Database::get(&c, "report")?;
        let info: ProjectInfo = Database::get(&c, "project")?;
        let mut stats = Statistics {
            sources: scalar(&c, "SELECT COUNT(*) FROM sources")?,
            records: scalar(&c, "SELECT COUNT(*) FROM records")?,
            findings: scalar(&c, "SELECT COUNT(*) FROM findings")?,
            local_findings: scalar(
                &c,
                "SELECT COUNT(*) FROM findings WHERE origin NOT LIKE 'ai:%'",
            )?,
            ai_findings: scalar(&c, "SELECT COUNT(*) FROM findings WHERE origin LIKE 'ai:%'")?,
            flows: scalar(&c, "SELECT COUNT(*) FROM flows")?,
            referenced: scalar(&c, "SELECT COUNT(DISTINCT record_id) FROM finding_refs")?,
            errors: scalar(
                &c,
                "SELECT COUNT(*) FROM diagnostics WHERE json_extract(json,'$.level')='error'",
            )?,
            warnings: scalar(
                &c,
                "SELECT COUNT(*) FROM diagnostics WHERE json_extract(json,'$.level')<>'error'",
            )?,
            ai_runs: values(&c, "SELECT json FROM ai_runs ORDER BY ordinal", [])?,
            ..Statistics::default()
        };
        for rank in 0..5 {
            stats.risks[rank] = c.query_row(
                "SELECT COUNT(*) FROM findings WHERE severity=?1",
                [rank as i64],
                |r| r.get::<_, i64>(0),
            )? as usize;
        }
        let selection: Option<i64> = c
            .query_row(
                "SELECT value FROM metadata WHERE key='query_selection'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(decode)
            .transpose()?
            .flatten();
        stats.query_matches = selection
            .map(|id| {
                c.query_row("SELECT count FROM selections WHERE id=?1", [id], |r| {
                    r.get::<_, i64>(0)
                })
                .map(|v| v as usize)
            })
            .transpose()?;
        let mut s=c.prepare("SELECT json,(SELECT COUNT(*) FROM finding_refs WHERE finding_id=f.id) FROM findings f ORDER BY severity DESC,ordinal LIMIT 5")?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            let f: Finding = decode(r.get(0)?)?;
            let count: i64 = r.get(1)?;
            stats.priorities.push(serde_json::json!({"id":f.id,"severity":f.severity,"title":f.title,"origin":f.origin,"evidence_count":count,"confidence":f.confidence}));
        }
        Ok(Metadata {
            schema_version: report.schema_version,
            generated_at: report.generated_at,
            stats,
            heading: Some(Heading {
                name: info.name,
                client: info.client,
                response_start: info.response_start,
                response_end: info.response_end,
            }),
        })
    }

    fn references(
        &self,
        key: References<'_>,
        ctx: &ExecutionContext,
        visitor: &mut dyn FnMut(String) -> Result<bool>,
    ) -> Result<()> {
        let db = self.0.0.store.as_ref().expect("project cursor");
        let c = db.lock()?;
        let (sql, param) = match key {
            References::Finding(id) => (
                "SELECT record_id FROM finding_refs WHERE finding_id=?1 ORDER BY ordinal",
                rusqlite::types::Value::Text(id.into()),
            ),
            References::Flow(id) => (
                "SELECT record_id FROM flow_refs WHERE flow_id=?1 ORDER BY ordinal",
                rusqlite::types::Value::Integer(id),
            ),
        };
        let mut s = c.prepare(sql)?;
        let mut rows = s.query([param])?;
        while let Some(r) = rows.next()? {
            ctx.check()?;
            if !visitor(r.get(0)?)? {
                break;
            }
        }
        Ok(())
    }
    fn ai_batches(
        &self,
        run: i64,
        ctx: &ExecutionContext,
        visitor: &mut dyn FnMut(AiBatch) -> Result<bool>,
    ) -> Result<()> {
        let db = self.0.0.store.as_ref().expect("project cursor");
        let c = db.lock()?;
        let mut s = c.prepare("SELECT json FROM ai_batches WHERE run_id=?1 ORDER BY ordinal")?;
        let mut rows = s.query([run])?;
        while let Some(r) = rows.next()? {
            ctx.check()?;
            if !visitor(decode(r.get(0)?)?)? {
                break;
            }
        }
        Ok(())
    }
    fn visit(
        &self,
        section: Section,
        ctx: &ExecutionContext,
        visitor: &mut dyn FnMut(Item) -> Result<bool>,
    ) -> Result<()> {
        let db = self.0.0.store.as_ref().expect("project cursor");
        let selection: Option<i64> = {
            let c = db.lock()?;
            Database::get(&c, "query_selection").unwrap_or(None)
        };
        if matches!(section, Section::Records | Section::SelectedRecords) {
            let mut after = if matches!(section, Section::SelectedRecords) && selection.is_some() {
                -1
            } else {
                0
            };
            loop {
                let batch = if matches!(section, Section::SelectedRecords) {
                    if let Some(id) = selection {
                        db.selected_records_after(id, after, 256, true)?
                    } else {
                        db.records_after(after, 256)?
                    }
                } else {
                    db.records_after(after, 256)?
                };
                if batch.is_empty() {
                    break;
                }
                for (id, record) in batch {
                    ctx.check()?;
                    after = id;
                    if !visitor(Item::Record(record))? {
                        return Ok(());
                    }
                }
            }
            return Ok(());
        }
        let mut after = if matches!(section, Section::QueryMatches) {
            -1i64
        } else {
            0
        };
        let mut rank = 5i64;
        loop {
            let batch = {
                let c = db.lock()?;
                let (sql,parameters):(String,Vec<rusqlite::types::Value>)=match section{
                    Section::Sources=>("SELECT json,rowid,0 FROM sources WHERE rowid>?1 ORDER BY rowid LIMIT 64".into(),vec![after.into()]),
                    Section::Findings|Section::SelectedFindings=>{let scoped=if matches!(section,Section::SelectedFindings)&&selection.is_some(){" AND EXISTS(SELECT 1 FROM finding_refs fr JOIN selection_refs sr ON sr.record_id=fr.record_id WHERE fr.finding_id=f.id AND sr.selection_id=?3)"}else{""};let mut p=vec![after.into(),rank.into()];if !scoped.is_empty(){p.push(selection.unwrap().into());}(format!("SELECT json,ordinal,severity FROM findings f WHERE (severity<?2 OR (severity=?2 AND ordinal>?1)){scoped} ORDER BY severity DESC,ordinal LIMIT 64"),p)},
                    Section::Flows=>("SELECT json,ordinal,0 FROM flows WHERE ordinal>?1 ORDER BY ordinal LIMIT 64".into(),vec![after.into()]),
                    Section::Diagnostics=>("SELECT json,ordinal,0 FROM diagnostics WHERE ordinal>?1 ORDER BY ordinal LIMIT 64".into(),vec![after.into()]),
                    Section::AiRuns=>("SELECT json,ordinal,0 FROM ai_runs WHERE ordinal>?1 ORDER BY ordinal LIMIT 64".into(),vec![after.into()]),
                    Section::QueryMatches=>{let Some(selection)=selection else{return Ok(());};("SELECT record_id,ordinal,0 FROM selection_refs WHERE selection_id=?2 AND ordinal>?1 ORDER BY ordinal LIMIT 64".into(),vec![after.into(),selection.into()])},
                    _=>unreachable!()
                };
                let mut stmt = c.prepare(&sql)?;
                stmt.query_map(rusqlite::params_from_iter(parameters), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
            };
            if batch.is_empty() {
                break;
            }
            for (data, id, severity) in batch {
                ctx.check()?;
                after = id;
                rank = severity;
                let item = match section {
                    Section::Sources => Item::Source(decode(data)?),
                    Section::Findings | Section::SelectedFindings => Item::Finding(decode(data)?),
                    Section::Flows => Item::Flow(decode(data)?, id),
                    Section::Diagnostics => Item::Diagnostic(decode(data)?),
                    Section::AiRuns => Item::AiRun(decode(data)?, id),
                    Section::QueryMatches => Item::QueryId(data),
                    _ => unreachable!(),
                };
                if !visitor(item)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}
impl AnalysisSession {
    /// Only headers are loaded; individual AI replies are paged separately.
    pub fn ai_run_headers(&self) -> Result<Vec<AiRun>> {
        if let Some(db) = &self.0.store {
            values(
                &*db.lock()?,
                "SELECT json FROM ai_runs ORDER BY ordinal",
                [],
            )
        } else {
            self.with_report(|r| {
                r.ai_runs
                    .iter()
                    .map(|run| {
                        let mut run = run.clone();
                        run.batch_results.clear();
                        run
                    })
                    .collect()
            })
        }
    }
    pub fn ai_batch_page(
        &self,
        run_index: usize,
        offset: usize,
        limit: usize,
    ) -> Result<Page<AiBatch>> {
        crate::storage::page_limit(limit)?;
        if let Some(db) = &self.0.store {
            let c = db.lock()?;
            let id: i64 = c.query_row(
                "SELECT ordinal FROM ai_runs ORDER BY ordinal LIMIT 1 OFFSET ?1",
                [run_index as i64],
                |r| r.get(0),
            )?;
            let total = c.query_row(
                "SELECT COUNT(*) FROM ai_batches WHERE run_id=?1",
                [id],
                |r| r.get::<_, i64>(0),
            )? as usize;
            Ok(Page {
                offset,
                total,
                items: values(
                    &c,
                    "SELECT json FROM ai_batches WHERE run_id=?1 ORDER BY ordinal LIMIT ?2 OFFSET ?3",
                    params![id, limit as i64, offset as i64],
                )?,
            })
        } else {
            self.with_report(|r| {
                let batches = &r
                    .ai_runs
                    .get(run_index)
                    .ok_or_else(|| anyhow::anyhow!("AI 运行不存在"))?
                    .batch_results;
                Ok(Page {
                    offset,
                    total: batches.len(),
                    items: batches.iter().skip(offset).take(limit).cloned().collect(),
                })
            })?
        }
    }
}
