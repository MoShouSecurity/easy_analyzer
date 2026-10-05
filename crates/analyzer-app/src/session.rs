use crate::{
    QueryOptions,
    core::{
        self, AnalysisReport, Finding, NetworkFlow, Record, RecordData,
        execution::{ExecutionContext, Stage},
    },
};
use anyhow::{Result, anyhow, bail};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

pub(crate) struct SessionInner {
    pub id: u64,
    pub report: RwLock<AnalysisReport>,
    pub store: Option<Arc<crate::storage::Database>>,
    pub index: HashMap<String, usize>,
    pub local_suspicious: HashSet<String>,
    pub mutation: Mutex<()>,
    pub protected: Vec<PathBuf>,
}

#[derive(Clone)]
pub struct AnalysisSession(pub(crate) Arc<SessionInner>);

#[derive(Debug, Clone)]
pub struct RecordSelection {
    pub(crate) session_id: u64,
    pub(crate) ids: Vec<String>,
    pub(crate) stored: Option<Arc<crate::storage::StoredSelection>>,
}
impl RecordSelection {
    pub fn try_ids(&self) -> Result<&[String]> {
        match &self.stored {
            Some(s) => s.load_ids(),
            None => Ok(&self.ids),
        }
    }
    pub(crate) fn stored_id(&self) -> Option<i64> {
        self.stored.as_ref().map(|s| s.id)
    }
    pub fn ids(&self) -> &[String] {
        self.try_ids()
            .expect("筛选存储读取失败；可用 try_ids 获取错误")
    }
    pub fn len(&self) -> usize {
        self.stored.as_ref().map_or(self.ids.len(), |s| s.count)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Page<T> {
    pub offset: usize,
    pub total: usize,
    pub items: Vec<T>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecordSummary {
    pub id: String,
    pub source_id: String,
    pub position: String,
    pub timestamp: Option<String>,
    pub status: core::ParseStatus,
    pub data: RecordData,
    pub summary: String,
}

impl AnalysisSession {
    pub(crate) fn new(report: AnalysisReport, protected: Vec<PathBuf>) -> Self {
        let index = report
            .records
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.clone(), i))
            .collect();
        let local_suspicious = report
            .findings
            .iter()
            .filter(|f| f.origin.starts_with("local:"))
            .flat_map(|f| f.evidence_ids.iter().cloned())
            .collect();
        Self(Arc::new(SessionInner {
            id: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
            report: RwLock::new(report),
            store: None,
            index,
            local_suspicious,
            mutation: Mutex::new(()),
            protected,
        }))
    }
    pub(crate) fn from_database(store: Arc<crate::storage::Database>) -> Self {
        Self(Arc::new(SessionInner {
            id: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
            report: RwLock::new(AnalysisReport::default()),
            store: Some(store),
            index: HashMap::new(),
            local_suspicious: HashSet::new(),
            mutation: Mutex::new(()),
            protected: vec![],
        }))
    }
    pub fn is_project(&self) -> bool {
        self.0.store.is_some()
    }
    pub fn id(&self) -> u64 {
        self.0.id
    }
    /// Read without copying the full evidence set. The callback must not mutate this session.
    pub fn with_report<T>(&self, read: impl FnOnce(&AnalysisReport) -> T) -> Result<T> {
        if let Some(db) = &self.0.store {
            return Ok(read(&db.report()?));
        }
        let report = self
            .0
            .report
            .read()
            .map_err(|_| anyhow!("分析会话读取失败"))?;
        Ok(read(&report))
    }
    pub fn record(&self, id: &str) -> Result<Option<Record>> {
        if let Some(db) = &self.0.store {
            return crate::storage::Database::record(&*db.lock()?, id);
        }
        self.with_report(|r| self.0.index.get(id).map(|&i| r.records[i].clone()))
    }
    pub fn select_ids(&self, ids: impl IntoIterator<Item = String>) -> Result<RecordSelection> {
        if let Some(db) = &self.0.store {
            let mut c = db.lock()?;
            let tx = c.transaction()?;
            tx.execute("INSERT INTO selections(count) VALUES(0)", [])?;
            let key = tx.last_insert_rowid();
            let mut n = 0;
            for id in ids {
                if !tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
                    [&id],
                    |r| r.get::<_, bool>(0),
                )? {
                    bail!("证据编号不属于当前会话");
                }
                n += tx.execute(
                    "INSERT OR IGNORE INTO selection_refs VALUES(?1,?2,?3)",
                    rusqlite::params![key, n as i64, id],
                )?;
            }
            tx.execute(
                "UPDATE selections SET count=?1 WHERE id=?2",
                rusqlite::params![n as i64, key],
            )?;
            tx.commit()?;
            return Ok(RecordSelection {
                session_id: self.id(),
                ids: vec![],
                stored: Some(Arc::new(crate::storage::StoredSelection {
                    db: db.clone(),
                    id: key,
                    count: n,
                    ids: Default::default(),
                })),
            });
        }
        let mut seen = HashSet::new();
        let mut result = vec![];
        for id in ids {
            if !self.0.index.contains_key(&id) {
                bail!("证据编号不属于当前会话");
            }
            if seen.insert(id.clone()) {
                result.push(id);
            }
        }
        Ok(RecordSelection {
            session_id: self.id(),
            ids: result,
            stored: None,
        })
    }
    pub(crate) fn validate_selection(&self, selection: &RecordSelection) -> Result<()> {
        if selection.session_id != self.id() {
            bail!("证据选择属于其他会话");
        }
        Ok(())
    }
    pub fn query(&self, query: &QueryOptions, ctx: &ExecutionContext) -> Result<RecordSelection> {
        if let Some(db) = &self.0.store {
            return db.select(
                self.id(),
                &crate::RecordFilter {
                    query: query.clone(),
                    ..Default::default()
                },
                ctx,
            );
        }
        if query.regex && query.expression.is_none() {
            bail!("正则查询需要表达式");
        }
        self.with_report(|report| {
            let mut ids = if let Some(expression) = &query.expression {
                core::rules::query_with_context(&report.records, expression, query.regex, ctx)?
            } else {
                let mut ids = vec![];
                for (i, record) in report.records.iter().enumerate() {
                    ctx.tick(Stage::Query, None, i, Some(report.records.len()))?;
                    ids.push(record.id.clone());
                }
                ids
            };
            if query.suspicious {
                ids.retain(|id| self.0.local_suspicious.contains(id));
            }
            ctx.check()?;
            Ok(RecordSelection {
                session_id: self.id(),
                ids,
                stored: None,
            })
        })?
    }
    pub fn set_selection(
        &self,
        selection: Option<&RecordSelection>,
        ctx: &ExecutionContext,
    ) -> Result<()> {
        if let Some(selection) = selection {
            self.validate_selection(selection)?;
        }
        let _operation = self.lock_operation(ctx)?;
        if let Some(db) = &self.0.store {
            ctx.check()?;
            crate::storage::Database::set(
                &*db.lock()?,
                "query_selection",
                &selection.and_then(RecordSelection::stored_id),
            )?;
            return Ok(());
        }
        let mut report = self
            .0
            .report
            .write()
            .map_err(|_| anyhow!("分析会话写入失败"))?;
        ctx.check()?;
        report.query_matches = selection.map(|s| s.ids.clone());
        Ok(())
    }
    pub fn page(
        &self,
        selection: Option<&RecordSelection>,
        offset: usize,
        limit: usize,
    ) -> Result<Page<RecordSummary>> {
        self.page_impl(selection, offset, limit, true)
    }
    /// Lightweight table page: packet payload is fetched only through `record(id)`.
    /// The existing `page` API retains its complete parsed-field behavior.
    pub fn page_metadata(
        &self,
        selection: Option<&RecordSelection>,
        offset: usize,
        limit: usize,
    ) -> Result<Page<RecordSummary>> {
        self.page_impl(selection, offset, limit, false)
    }
    fn page_impl(
        &self,
        selection: Option<&RecordSelection>,
        offset: usize,
        limit: usize,
        include_payload: bool,
    ) -> Result<Page<RecordSummary>> {
        check_page(limit)?;
        if let Some(selection) = selection {
            self.validate_selection(selection)?;
        }
        if let Some(db) = &self.0.store {
            return db.read_page(
                selection.and_then(RecordSelection::stored_id),
                offset,
                limit,
                include_payload,
            );
        }
        self.with_report(|report| {
            let total = selection.map_or(report.records.len(), |s| s.ids.len());
            let items = (offset.min(total)..offset.saturating_add(limit).min(total))
                .map(|i| {
                    let record = match selection {
                        Some(s) => &report.records[self.0.index[&s.ids[i]]],
                        None => &report.records[i],
                    };
                    RecordSummary {
                        id: record.id.clone(),
                        source_id: record.source_id.clone(),
                        position: record.position.clone(),
                        timestamp: record.timestamp.clone(),
                        status: record.status.clone(),
                        data: match &record.data {
                            RecordData::Packet(packet) if !include_payload => {
                                RecordData::Packet(core::PacketData {
                                    link_type: packet.link_type,
                                    captured_bytes: packet.captured_bytes,
                                    original_bytes: packet.original_bytes,
                                    source: packet.source.clone(),
                                    destination: packet.destination.clone(),
                                    source_port: packet.source_port,
                                    destination_port: packet.destination_port,
                                    protocol: packet.protocol.clone(),
                                    tcp_flags: packet.tcp_flags,
                                    application: packet.application.clone(),
                                    payload_hex: String::new(),
                                })
                            }
                            data => data.clone(),
                        },
                        summary: core::report::record_summary(record),
                    }
                })
                .collect();
            Page {
                offset,
                total,
                items,
            }
        })
    }
    pub fn findings(&self, offset: usize, limit: usize) -> Result<Page<Finding>> {
        check_page(limit)?;
        if let Some(db) = &self.0.store {
            return db.finding_page(&Default::default(), offset, limit);
        }
        self.with_report(|r| page_slice(&r.findings, offset, limit))
    }
    pub fn flows(&self, offset: usize, limit: usize) -> Result<Page<NetworkFlow>> {
        check_page(limit)?;
        if let Some(db) = &self.0.store {
            let c = db.lock()?;
            let mut items: Vec<NetworkFlow> = crate::storage::values(
                &c,
                "SELECT json FROM flows ORDER BY ordinal LIMIT ?1 OFFSET ?2",
                rusqlite::params![limit as i64, offset.min(i64::MAX as usize) as i64],
            )?;
            for (i, f) in items.iter_mut().enumerate() {
                let mut s =
                    c.prepare("SELECT record_id FROM flow_refs WHERE flow_id=?1 ORDER BY ordinal")?;
                f.evidence_ids = s
                    .query_map([(offset + i + 1) as i64], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
            }
            return Ok(Page {
                offset,
                total: crate::storage::scalar(&c, "SELECT COUNT(*) FROM flows")?,
                items,
            });
        }
        self.with_report(|r| page_slice(&r.flows, offset, limit))
    }
    pub fn process_forest(&self) -> Result<core::process::ProcessForest> {
        if let Some(db) = &self.0.store {
            return Ok(core::process::process_forest(&db.process_records()?));
        }
        self.with_report(|r| core::process::process_forest(&r.records))
    }
    pub(crate) fn lock_operation(&self, ctx: &ExecutionContext) -> Result<MutexGuard<'_, ()>> {
        loop {
            ctx.check()?;
            match self.0.mutation.try_lock() {
                Ok(lock) => return Ok(lock),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                Err(_) => bail!("分析会话修改失败"),
            }
        }
    }
}

fn check_page(limit: usize) -> Result<()> {
    if !(1..=1000).contains(&limit) {
        bail!("分页大小必须为 1 到 1000");
    }
    Ok(())
}
fn page_slice<T: Clone>(items: &[T], offset: usize, limit: usize) -> Page<T> {
    Page {
        offset,
        total: items.len(),
        items: items[offset.min(items.len())..offset.saturating_add(limit).min(items.len())]
            .to_vec(),
    }
}
