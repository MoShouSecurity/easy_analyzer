use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub path: String,
    pub format: String,
    pub sha256: String,
    pub bytes: u64,
    pub collected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub source_id: String,
    pub position: String,
    pub timestamp: Option<String>,
    /// Text for text logs; hex for binary evidence; JSON for process snapshots.
    pub raw: String,
    pub status: ParseStatus,
    pub data: RecordData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParseStatus {
    Parsed,
    Unrecognized,
    Malformed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "fields", rename_all = "snake_case")]
pub enum RecordData {
    Log(LogData),
    Process(ProcessData),
    Packet(PacketData),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogData {
    pub category: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessData {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub start_time: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketData {
    pub link_type: u32,
    pub captured_bytes: u32,
    pub original_bytes: u32,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub tcp_flags: Option<u8>,
    pub application: BTreeMap<String, String>,
    pub payload_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub protocol: String,
    pub packets: usize,
    pub bytes: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub origin: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence_ids: Vec<String>,
    pub confidence: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    #[default]
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    #[serde(default)]
    pub level: DiagnosticLevel,
    pub source: String,
    pub position: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: u32,
    pub generated_at: String,
    pub sources: Vec<Source>,
    pub records: Vec<Record>,
    pub findings: Vec<Finding>,
    pub flows: Vec<NetworkFlow>,
    pub diagnostics: Vec<Diagnostic>,
    /// IDs matching an explicit query; None means no query was applied.
    pub query_matches: Option<Vec<String>>,
    pub ai_runs: Vec<AiRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRun {
    pub model: String,
    pub endpoint: String,
    pub batches: usize,
    pub analyzed_records: usize,
    pub include_payload: bool,
}

impl Default for AnalysisReport {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            generated_at: Utc::now().to_rfc3339(),
            sources: vec![],
            records: vec![],
            findings: vec![],
            flows: vec![],
            diagnostics: vec![],
            query_matches: None,
            ai_runs: vec![],
        }
    }
}

impl AnalysisReport {
    pub fn warn(
        &mut self,
        source: impl Into<String>,
        position: Option<String>,
        message: impl Into<String>,
    ) {
        self.diagnostics.push(Diagnostic {
            level: DiagnosticLevel::Warning,
            source: source.into(),
            position,
            message: message.into(),
        });
    }
    pub fn error(
        &mut self,
        source: impl Into<String>,
        position: Option<String>,
        message: impl Into<String>,
    ) {
        self.diagnostics.push(Diagnostic {
            level: DiagnosticLevel::Error,
            source: source.into(),
            position,
            message: message.into(),
        });
    }
    pub fn merge(&mut self, other: Self) {
        for source in other.sources {
            if !self.sources.iter().any(|s| s.id == source.id) {
                self.sources.push(source);
            }
        }
        let mut existing: std::collections::HashSet<String> =
            self.records.iter().map(|r| r.id.clone()).collect();
        self.records.extend(
            other
                .records
                .into_iter()
                .filter(|r| existing.insert(r.id.clone())),
        );
        self.diagnostics.extend(other.diagnostics);
    }
}

pub fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
