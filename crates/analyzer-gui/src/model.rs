use analyzer_app::{
    core::{self, Finding, ParseStatus, Record, Severity},
    *,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Screen {
    #[default]
    Import,
    Overview,
    Logs,
    Processes,
    Network,
    Ai,
    Reports,
    Settings,
}
impl Screen {
    pub fn evidence(self) -> bool {
        matches!(self, Self::Logs | Self::Processes | Self::Network)
    }
    pub fn kind(self) -> RecordKind {
        match self {
            Self::Logs => RecordKind::Log,
            Self::Processes => RecordKind::Process,
            Self::Network => RecordKind::Packet,
            _ => RecordKind::All,
        }
    }
}
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(default)]
pub struct Filters {
    pub text: String,
    pub regex: bool,
    pub suspicious: bool,
    pub source: Option<String>,
    pub category: Option<String>,
    pub status: Option<ParseStatus>,
    pub protocol: Option<String>,
    pub offset: usize,
    pub limit: usize,
    pub tree: bool,
    pub packets: bool,
    pub flow: Option<usize>,
    pub collapsed: HashSet<String>,
    pub severity: Option<Severity>,
    pub origin: String,
}
impl Default for Filters {
    fn default() -> Self {
        Self {
            text: String::new(),
            regex: false,
            suspicious: false,
            source: None,
            category: None,
            status: None,
            protocol: None,
            offset: 0,
            limit: 100,
            tree: true,
            packets: false,
            flow: None,
            collapsed: HashSet::new(),
            severity: None,
            origin: "all".into(),
        }
    }
}
impl Filters {
    pub fn record_filter(&self, screen: Screen) -> RecordFilter {
        RecordFilter {
            query: QueryOptions {
                expression: (!self.text.is_empty()).then(|| self.text.clone()),
                regex: self.regex,
                suspicious: self.suspicious,
            },
            kind: screen.kind(),
            source: self.source.clone(),
            category: self.category.clone(),
            status: self.status.clone(),
            protocol: self.protocol.clone(),
        }
    }
    pub fn finding_filter(&self) -> FindingFilter {
        FindingFilter {
            severity: self.severity.clone(),
            origin: match self.origin.as_str() {
                "local" => FindingOrigin::Local,
                "ai" => FindingOrigin::Ai,
                _ => FindingOrigin::All,
            },
        }
    }
    pub fn label(&self, screen: Screen) -> String {
        let mut parts = vec![
            match screen {
                Screen::Logs => "日志",
                Screen::Processes => "进程",
                _ => "数据包",
            }
            .to_string(),
        ];
        if !self.text.is_empty() {
            parts.push(format!(
                "{}：{}",
                if self.regex { "正则" } else { "关键词" },
                self.text
            ));
        }
        if self.suspicious {
            parts.push("本地可疑项".into());
        }
        if self.source.is_some() {
            parts.push("指定来源".into());
        }
        if let Some(v) = &self.category {
            parts.push(format!("类别：{v}"));
        }
        if let Some(v) = &self.protocol {
            parts.push(format!("协议：{v}"));
        }
        if let Some(v) = &self.status {
            parts.push(format!("解析状态：{v:?}"));
        }
        if let Some(v) = self.flow {
            parts.push(format!("会话 #{} 关联包", v + 1));
        }
        parts.join(" · ")
    }
}
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(default)]
pub struct Preferences {
    pub dark: bool,
    pub inspector: bool,
    pub inspector_width: f64,
    pub config_path: String,
    pub window_width: f64,
    pub window_height: f64,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            dark: false,
            inspector: true,
            inspector_width: 320.,
            config_path: String::new(),
            window_width: 1280.,
            window_height: 720.,
        }
    }
}
#[derive(Clone, Serialize)]
pub struct PublicConfig {
    pub base_url: String,
    pub model: String,
    pub api_key_configured: bool,
    pub api_key_env: String,
    pub timeout_seconds: u64,
    pub batch_bytes: usize,
    pub context_tokens: Option<usize>,
    pub max_output_tokens: u32,
    pub response_format: String,
    pub token_parameter: String,
}
impl From<&core::ai::AiConfig> for PublicConfig {
    fn from(c: &core::ai::AiConfig) -> Self {
        Self {
            base_url: c.base_url.clone(),
            model: c.model.clone(),
            api_key_configured: !c.api_key.is_empty() || !c.api_key_env.is_empty(),
            api_key_env: if !c
                .api_key_env
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                String::new()
            } else {
                c.api_key_env.clone()
            },
            timeout_seconds: c.timeout_seconds,
            batch_bytes: c.batch_bytes,
            context_tokens: c.context_tokens,
            max_output_tokens: c.max_output_tokens,
            response_format: c.response_format.clone(),
            token_parameter: c.token_parameter.clone(),
        }
    }
}
#[derive(Clone, Deserialize)]
pub struct ConfigInput {
    pub base_url: String,
    pub model: String,
    pub api_key_env: String,
    pub timeout_seconds: u64,
    pub batch_bytes: usize,
    #[serde(default)]
    pub context_tokens: Option<usize>,
    pub max_output_tokens: u32,
    pub response_format: String,
    pub token_parameter: String,
    #[serde(default)]
    pub key_action: String,
    #[serde(default)]
    pub key_value: String,
}
impl ConfigInput {
    pub fn apply(self, previous: &core::ai::AiConfig) -> anyhow::Result<core::ai::AiConfig> {
        let key = match self.key_action.as_str() {
            "" | "keep" => previous.api_key.clone(),
            "replace" => self.key_value,
            "clear" => String::new(),
            _ => anyhow::bail!("无效的密钥操作"),
        };
        let c = core::ai::AiConfig {
            base_url: self.base_url,
            model: self.model,
            api_key: key,
            api_key_env: if self.key_action == "clear" {
                String::new()
            } else if self.key_action == "keep"
                && self.api_key_env.is_empty()
                && !previous
                    .api_key_env
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                previous.api_key_env.clone()
            } else {
                self.api_key_env
            },
            timeout_seconds: self.timeout_seconds,
            batch_bytes: self.batch_bytes,
            context_tokens: self.context_tokens,
            max_output_tokens: self.max_output_tokens,
            response_format: self.response_format,
            token_parameter: self.token_parameter,
        };
        c.validate()?;
        Ok(c)
    }
}
#[derive(Clone, Deserialize)]
pub struct ImportRequest {
    pub paths: Vec<String>,
    pub live: bool,
    pub auto_logs: bool,
    pub capture_dir: String,
    pub format: String,
    pub max_file_bytes: u64,
    pub max_records: usize,
    pub web_format: Option<String>,
}
impl ImportRequest {
    pub fn request(self) -> anyhow::Result<AnalysisRequest> {
        if cfg!(target_os = "macos") && self.auto_logs {
            anyhow::bail!("macOS 不支持本机通用日志加载，请导入离线日志");
        }
        Ok(AnalysisRequest {
            inputs: self
                .paths
                .into_iter()
                .map(|p| AnalysisInput::File(p.into()))
                .collect(),
            live_processes: self.live,
            auto_load: self.auto_logs,
            evidence_dir: self.capture_dir.into(),
            web_format_file: self
                .web_format
                .filter(|v| !v.trim().is_empty())
                .map(Into::into),
            ingest: IngestOptions {
                format: self.format.parse()?,
                max_file_bytes: self.max_file_bytes,
                max_records: self.max_records,
                ..Default::default()
            },
            ..Default::default()
        })
    }
}
#[derive(Clone, Deserialize)]
pub struct ViewRequest {
    pub session_id: u64,
    pub revision: u64,
    pub screen: Screen,
    pub filters: Filters,
    pub focus_id: Option<String>,
    pub commit_selection: bool,
    #[serde(default)]
    pub source_offset: usize,
    #[serde(default)]
    pub diagnostic_offset: usize,
    #[serde(default)]
    pub run_offset: usize,
}
#[derive(Serialize, Clone, Default)]
pub struct SelectionInfo {
    pub id: u64,
    pub count: usize,
    pub label: String,
}
#[derive(Serialize, Clone)]
pub struct RunSummary {
    pub index: usize,
    pub model: String,
    pub endpoint: String,
    pub batches: usize,
    pub completed: usize,
    pub analyzed: usize,
    pub selected: usize,
    pub include_payload: bool,
    pub local_summary: Option<String>,
}
#[derive(Serialize)]
pub struct ViewResponse {
    pub session_id: u64,
    pub revision: u64,
    pub overview: SessionOverview,
    pub records: Option<Page<RecordSummary>>,
    pub findings: Option<Page<Finding>>,
    pub flows: Option<Page<FlowSummary>>,
    pub process_rows: Vec<ProcessRow>,
    pub sources: Page<core::Source>,
    pub record_sources: BTreeMap<String, String>,
    pub diagnostics: Page<core::Diagnostic>,
    pub runs: Page<RunSummary>,
    pub outside: bool,
    pub offset: usize,
    pub selection: SelectionInfo,
}
#[derive(Serialize)]
pub struct DetailResponse {
    pub session_id: u64,
    pub record: Record,
    pub source: Option<core::Source>,
    pub related: Vec<Finding>,
}
#[derive(Clone, Serialize)]
pub struct TaskMessage {
    pub task_id: u64,
    pub session_id: Option<u64>,
    pub epoch: u64,
    pub revision: u64,
    pub kind: String,
    pub status: String,
    pub label: String,
    pub stage: Option<String>,
    pub completed: Option<usize>,
    pub total: Option<usize>,
    pub error: Option<String>,
    pub saved_paths: Vec<String>,
}
#[derive(Serialize)]
pub struct Bootstrap {
    pub preferences: Preferences,
    pub config: PublicConfig,
    pub config_loaded: bool,
    pub config_error: Option<String>,
    pub session_id: Option<u64>,
    pub selection: SelectionInfo,
    pub busy: Option<TaskMessage>,
    pub platform: String,
    pub elevated: Option<bool>,
    pub elevation_error: Option<String>,
    pub live_processes: bool,
    pub capture_dir: String,
    pub inputs: Vec<String>,
    pub qa: bool,
    pub qa_ai: bool,
}
#[derive(Clone, Deserialize)]
pub struct AiRequest {
    pub session_id: u64,
    pub scope: String,
    pub selection_id: Option<u64>,
    pub include_payload: bool,
    #[serde(default)]
    pub plan_id: Option<u64>,
}
#[derive(Serialize)]
pub struct AiPreview {
    pub id: u64,
    pub session_id: u64,
    pub plan: core::ai::AiPlan,
}
#[derive(Deserialize)]
pub struct ExportRequest {
    pub session_id: u64,
    pub selection_id: Option<u64>,
    pub path: String,
    pub html: bool,
    pub json: bool,
    pub overwrite: bool,
}
