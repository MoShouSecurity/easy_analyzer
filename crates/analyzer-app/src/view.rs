//! GUI-neutral selections and bounded view models. Evidence never leaves the session wholesale.
use crate::{AnalysisSession, ExecutionContext, Page, QueryOptions, RecordSelection, core};
use anyhow::{Result, bail};
use core::{
    AiRun, Diagnostic, Finding, ParseStatus, RecordData, Severity, Source, execution::Stage,
};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordKind {
    #[default]
    All,
    Log,
    Process,
    Packet,
}
#[derive(Debug, Clone, Default)]
pub struct RecordFilter {
    pub query: QueryOptions,
    pub kind: RecordKind,
    pub source: Option<String>,
    pub category: Option<String>,
    pub status: Option<ParseStatus>,
    pub protocol: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FindingOrigin {
    #[default]
    All,
    Local,
    Ai,
}
#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    pub severity: Option<Severity>,
    pub origin: FindingOrigin,
}
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SessionOverview {
    pub sources: usize,
    pub records: usize,
    pub logs: usize,
    pub processes: usize,
    pub packets: usize,
    pub flows: usize,
    pub local_findings: usize,
    pub ai_findings: usize,
    pub suspicious: usize,
    pub risks: [usize; 5],
    pub categories: Vec<String>,
    pub protocols: Vec<String>,
    pub parse_counts: [usize; 3],
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowSummary {
    /// Stable within a session, includes capture source through the underlying flow index.
    pub key: usize,
    pub source_id: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub protocol: String,
    pub packets: usize,
    pub matched_packets: usize,
    pub bytes: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessRow {
    pub record_id: String,
    pub depth: usize,
    pub context: bool,
    pub orphan: bool,
    pub cyclic: bool,
    pub has_children: bool,
}

fn page<T>(all: Vec<T>, offset: usize, limit: usize) -> Result<Page<T>> {
    if !(1..=1000).contains(&limit) {
        bail!("分页大小必须为 1 到 1000");
    }
    let total = all.len();
    Ok(Page {
        offset,
        total,
        items: all.into_iter().skip(offset).take(limit).collect(),
    })
}

fn page_slice<T: Clone>(all: &[T], offset: usize, limit: usize) -> Result<Page<T>> {
    if !(1..=1000).contains(&limit) {
        bail!("分页大小必须为 1 到 1000");
    }
    Ok(Page {
        offset,
        total: all.len(),
        items: all[offset.min(all.len())..offset.saturating_add(limit).min(all.len())].to_vec(),
    })
}

impl AnalysisSession {
    pub fn select_records(
        &self,
        filter: &RecordFilter,
        ctx: &ExecutionContext,
    ) -> Result<RecordSelection> {
        let selection = self.query(&filter.query, ctx)?;
        self.with_report(|r| {
            let mut ids = Vec::new();
            for (i, id) in selection.ids().iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(selection.len()))?;
                let record = &r.records[self.0.index[id]];
                let kind = match record.data {
                    RecordData::Log(_) => RecordKind::Log,
                    RecordData::Process(_) => RecordKind::Process,
                    RecordData::Packet(_) => RecordKind::Packet,
                };
                if filter.kind != RecordKind::All && filter.kind != kind {
                    continue;
                }
                if filter
                    .source
                    .as_ref()
                    .is_some_and(|s| s != &record.source_id)
                    || filter.status.as_ref().is_some_and(|s| s != &record.status)
                {
                    continue;
                }
                if let Some(category) = &filter.category
                    && !matches!(&record.data, RecordData::Log(l) if &l.category == category)
                {
                    continue;
                }
                if let Some(protocol) = &filter.protocol
                    && !matches!(&record.data, RecordData::Packet(p) if &p.protocol == protocol)
                {
                    continue;
                }
                ids.push(id.clone());
            }
            self.select_ids(ids)
        })?
    }
    pub fn overview(&self, ctx: &ExecutionContext) -> Result<SessionOverview> {
        self.with_report(|r| {
            let mut o = SessionOverview {
                sources: r.sources.len(),
                records: r.records.len(),
                flows: r.flows.len(),
                suspicious: self.0.local_suspicious.len(),
                ..Default::default()
            };
            let mut categories = BTreeMap::new();
            let mut protocols = BTreeMap::new();
            for (i, record) in r.records.iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(r.records.len()))?;
                o.parse_counts[match record.status {
                    ParseStatus::Parsed => 0,
                    ParseStatus::Unrecognized => 1,
                    ParseStatus::Malformed => 2,
                }] += 1;
                match &record.data {
                    RecordData::Log(l) => {
                        o.logs += 1;
                        categories.insert(l.category.clone(), ());
                    }
                    RecordData::Process(_) => o.processes += 1,
                    RecordData::Packet(p) => {
                        o.packets += 1;
                        protocols.insert(p.protocol.clone(), ());
                    }
                }
            }
            for (i, finding) in r.findings.iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(r.findings.len()))?;
                o.risks[finding.severity.rank() as usize] += 1;
                if finding.origin.starts_with("local:") {
                    o.local_findings += 1;
                } else {
                    o.ai_findings += 1;
                }
            }
            o.categories = categories.into_keys().collect();
            o.protocols = protocols.into_keys().collect();
            Ok(o)
        })?
    }
    pub fn finding_page(
        &self,
        filter: &FindingFilter,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
    ) -> Result<Page<Finding>> {
        self.with_report(|r| {
            if !(1..=1000).contains(&limit) {
                bail!("分页大小必须为 1 到 1000");
            }
            let mut all = Vec::new();
            let mut total = 0;
            for (i, f) in r.findings.iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(r.findings.len()))?;
                let local = f.origin.starts_with("local:");
                if filter.severity.as_ref().is_some_and(|s| s != &f.severity)
                    || (filter.origin == FindingOrigin::Local && !local)
                    || (filter.origin == FindingOrigin::Ai && local)
                {
                    continue;
                }
                if total >= offset && total < offset.saturating_add(limit) {
                    all.push(f.clone());
                }
                total += 1;
            }
            Ok(Page {
                offset,
                total,
                items: all,
            })
        })?
    }
    pub fn locate_record(
        &self,
        selection: Option<&RecordSelection>,
        id: &str,
    ) -> Result<Option<usize>> {
        if let Some(s) = selection {
            self.validate_selection(s)?;
            return Ok(s.ids().iter().position(|candidate| candidate == id));
        }
        Ok(self.0.index.get(id).copied())
    }
    pub fn source(&self, id: &str) -> Result<Option<Source>> {
        self.with_report(|r| r.sources.iter().find(|s| s.id == id).cloned())
    }
    pub fn source_page(&self, offset: usize, limit: usize) -> Result<Page<Source>> {
        self.with_report(|r| page_slice(&r.sources, offset, limit))?
    }
    pub fn diagnostic_page(&self, offset: usize, limit: usize) -> Result<Page<Diagnostic>> {
        self.with_report(|r| page_slice(&r.diagnostics, offset, limit))?
    }
    pub fn ai_runs(&self) -> Result<Vec<AiRun>> {
        self.with_report(|r| r.ai_runs.clone())
    }
    pub fn related_findings(&self, id: &str) -> Result<Vec<Finding>> {
        self.with_report(|r| {
            r.findings
                .iter()
                .filter(|f| f.evidence_ids.iter().any(|e| e == id))
                .cloned()
                .collect()
        })
    }
    pub fn flow_page(
        &self,
        selection: Option<&RecordSelection>,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
    ) -> Result<Page<FlowSummary>> {
        if let Some(s) = selection {
            self.validate_selection(s)?;
        }
        let selected = selection.map(|s| s.ids().iter().collect::<HashSet<_>>());
        self.with_report(|r| {
            let mut all = Vec::new();
            for (key, f) in r.flows.iter().enumerate() {
                ctx.tick(Stage::Flows, None, key, Some(r.flows.len()))?;
                let mut matched = 0;
                for (i, id) in f.evidence_ids.iter().enumerate() {
                    ctx.tick(Stage::Flows, None, i, Some(f.evidence_ids.len()))?;
                    if selected.as_ref().is_none_or(|s| s.contains(id)) {
                        matched += 1;
                    }
                }
                if matched == 0 {
                    continue;
                }
                all.push(FlowSummary {
                    key,
                    source_id: f
                        .evidence_ids
                        .first()
                        .and_then(|id| self.0.index.get(id))
                        .map(|i| r.records[*i].source_id.clone())
                        .unwrap_or_default(),
                    endpoint_a: f.endpoint_a.clone(),
                    endpoint_b: f.endpoint_b.clone(),
                    protocol: f.protocol.clone(),
                    packets: f.packets,
                    matched_packets: matched,
                    bytes: f.bytes,
                    first_seen: f.first_seen.clone(),
                    last_seen: f.last_seen.clone(),
                });
            }
            page(all, offset, limit)
        })?
    }
    pub fn flow_selection(
        &self,
        key: usize,
        selection: Option<&RecordSelection>,
        ctx: &ExecutionContext,
    ) -> Result<RecordSelection> {
        if let Some(s) = selection {
            self.validate_selection(s)?;
        }
        let selected = selection.map(|s| s.ids().iter().collect::<HashSet<_>>());
        self.with_report(|r| {
            let f = r
                .flows
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("会话不存在"))?;
            let mut ids = Vec::new();
            for (i, id) in f.evidence_ids.iter().enumerate() {
                ctx.tick(Stage::Flows, None, i, Some(f.evidence_ids.len()))?;
                if selected.as_ref().is_none_or(|s| s.contains(id)) {
                    ids.push(id.clone());
                }
            }
            self.select_ids(ids)
        })?
    }
    /// Iterative traversal with explicit context ancestors. No recursive stack growth on deep trees.
    pub fn process_rows(
        &self,
        selection: &RecordSelection,
        ctx: &ExecutionContext,
    ) -> Result<Vec<ProcessRow>> {
        self.validate_selection(selection)?;
        let forest =
            self.with_report(|r| core::process::process_forest_with_context(&r.records, ctx))??;
        let selected = selection.ids().iter().cloned().collect::<HashSet<_>>();
        let mut rows = Vec::new();
        for tree in forest.trees {
            let nodes = tree
                .nodes
                .iter()
                .map(|n| (&n.record_id, n))
                .collect::<BTreeMap<_, _>>();
            let mut visible = selected.clone();
            let mut expanded = HashSet::new();
            for (i, node) in tree.nodes.iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(tree.nodes.len()))?;
                if !selected.contains(&node.record_id) {
                    continue;
                }
                let mut parent = node.parent_id.as_ref();
                let mut walked = HashSet::new();
                while let Some(id) = parent {
                    ctx.check()?;
                    if !walked.insert(id) || !expanded.insert(id) {
                        break;
                    }
                    // An already included ancestor has had its ancestors included as well.
                    visible.insert(id.clone());
                    parent = nodes.get(id).and_then(|n| n.parent_id.as_ref());
                }
            }
            let mut stack = tree
                .roots
                .iter()
                .chain(&tree.cycle_roots)
                .rev()
                .map(|id| (id, 0usize))
                .collect::<Vec<_>>();
            let mut visited = HashSet::new();
            while let Some((id, depth)) = stack.pop() {
                ctx.check()?;
                if !visited.insert(id) || !visible.contains(id) {
                    continue;
                }
                let n = nodes[id];
                rows.push(ProcessRow {
                    record_id: id.clone(),
                    depth,
                    context: !selected.contains(id),
                    orphan: n.orphan,
                    cyclic: n.cyclic,
                    has_children: !n.children.is_empty(),
                });
                stack.extend(n.children.iter().rev().map(|c| (c, depth + 1)));
            }
        }
        Ok(rows)
    }
}
