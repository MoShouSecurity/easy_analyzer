use crate::{AnalysisSession, IngestOptions};
use std::{path::PathBuf, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisMode {
    Mixed,
    Logs,
    Processes,
    Pcap,
}

#[derive(Debug, Clone)]
pub enum AnalysisInput {
    File(PathBuf),
    Bytes { label: String, bytes: Arc<[u8]> },
}
impl AnalysisInput {
    pub fn label(&self) -> String {
        match self {
            Self::File(p) => p.to_string_lossy().into_owned(),
            Self::Bytes { label, .. } => label.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    pub expression: Option<String>,
    pub regex: bool,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiScope {
    All,
    Matches,
    Suspicious,
}

#[derive(Debug, Clone)]
pub struct AiOptions {
    pub config_path: PathBuf,
    pub scope: AiScope,
    pub include_payload: bool,
}

#[derive(Debug, Clone)]
pub struct AnalysisRequest {
    pub mode: AnalysisMode,
    pub inputs: Vec<AnalysisInput>,
    pub ingest: IngestOptions,
    pub web_format_file: Option<PathBuf>,
    pub auto_load: bool,
    pub live_processes: bool,
    pub evidence_dir: PathBuf,
    pub query: Option<QueryOptions>,
    pub ai: Option<AiOptions>,
}
impl Default for AnalysisRequest {
    fn default() -> Self {
        Self {
            mode: AnalysisMode::Mixed,
            inputs: vec![],
            ingest: IngestOptions::default(),
            web_format_file: None,
            auto_load: false,
            live_processes: false,
            evidence_dir: "cases/captured".into(),
            query: None,
            ai: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Running,
    Cancelling,
    Completed,
    Partial,
    Cancelled,
    Failed,
}
impl TaskStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Running | Self::Cancelling)
    }
}

pub struct AnalysisOutcome {
    pub session: AnalysisSession,
    pub status: TaskStatus,
}
