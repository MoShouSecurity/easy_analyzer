//! UI-independent cooperative cancellation and progress.
use crate::AnalysisReport;
use anyhow::Result;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("分析已取消")
    }
}
impl std::error::Error for Cancelled {}
pub fn is_cancelled(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Cancelled>().is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Reading,
    Hashing,
    Parsing,
    Collecting,
    Rules,
    Query,
    Flows,
    AiPreparing,
    Ai,
    Finalizing,
}

/// Counts are bytes during Reading/Hashing, records during Parsing/Rules/Query,
/// and one-based batches during Ai. No credentials or evidence content are emitted.
#[derive(Debug, Clone)]
pub struct ProgressEvent {
    pub stage: Stage,
    pub source: Option<String>,
    pub completed: usize,
    pub total: Option<usize>,
    pub attempt: Option<usize>,
}

type TickKey = (Stage, Option<String>, usize, Option<usize>);

#[derive(Clone, Default)]
pub struct ExecutionContext {
    pub cancellation: CancellationToken,
    observer: Option<Arc<dyn Fn(ProgressEvent) + Send + Sync>>,
    last_tick: Arc<Mutex<Option<TickKey>>>,
}

impl ExecutionContext {
    pub fn new(
        cancellation: CancellationToken,
        observer: impl Fn(ProgressEvent) + Send + Sync + 'static,
    ) -> Self {
        Self {
            cancellation,
            observer: Some(Arc::new(observer)),
            last_tick: Arc::default(),
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.cancellation.is_cancelled() {
            Err(Cancelled.into())
        } else {
            Ok(())
        }
    }
    pub fn emit(&self, stage: Stage, source: Option<&str>, completed: usize, total: Option<usize>) {
        if self.observer.is_none() {
            return;
        }
        self.notify(ProgressEvent {
            stage,
            source: source.map(str::to_owned),
            completed,
            total,
            attempt: None,
        });
    }
    pub fn notify(&self, progress: ProgressEvent) {
        if let Some(observer) = &self.observer {
            observer(progress);
        }
    }
    /// Check every iteration; emit periodically so a large input does not flood a UI.
    pub fn tick(
        &self,
        stage: Stage,
        source: Option<&str>,
        completed: usize,
        total: Option<usize>,
    ) -> Result<()> {
        if self.observer.is_some() && completed.is_multiple_of(256) {
            // Metadata-only PCAPNG blocks may never advance the record count.
            // Suppress identical ticks without holding a lock across callbacks.
            let changed = {
                let mut last = self.last_tick.lock().unwrap_or_else(|e| e.into_inner());
                let changed = last.as_ref().is_none_or(|(s, path, n, t)| {
                    *s != stage || path.as_deref() != source || *n != completed || *t != total
                });
                if changed {
                    *last = Some((stage, source.map(str::to_owned), completed, total));
                }
                changed
            };
            if changed {
                self.emit(stage, source, completed, total);
            }
        }
        self.check()
    }
}

pub struct ReportOutcome {
    pub report: AnalysisReport,
    pub cancelled: bool,
}
impl ReportOutcome {
    pub fn complete(report: AnalysisReport) -> Self {
        Self {
            report,
            cancelled: false,
        }
    }
    pub fn cancelled(mut report: AnalysisReport, source: &str) -> Self {
        report.error(
            source,
            None,
            "分析已取消；仅保留已完成读取并校验来源的证据及已解析记录，当前范围不完整。",
        );
        Self {
            report,
            cancelled: true,
        }
    }
}
