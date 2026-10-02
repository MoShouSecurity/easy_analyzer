export type Screen =
  | "import"
  | "overview"
  | "logs"
  | "processes"
  | "network"
  | "ai"
  | "reports"
  | "settings";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ParseStatus = "parsed" | "unrecognized" | "malformed";
export interface Preferences {
  dark: boolean;
  inspector: boolean;
  inspector_width: number;
  config_path: string;
  window_width: number;
  window_height: number;
}
export interface PublicConfig {
  base_url: string;
  model: string;
  api_key_configured: boolean;
  api_key_env: string;
  timeout_seconds: number;
  batch_bytes: number;
  max_output_tokens: number;
  response_format: string;
  token_parameter: string;
}
export type ConfigInput = Omit<PublicConfig, "api_key_configured"> & {
  key_action: "keep" | "replace" | "clear";
  key_value: string;
};
export interface SelectionInfo {
  id: number;
  count: number;
  label: string;
}
export interface TaskMessage {
  task_id: number;
  session_id: number | null;
  epoch: number;
  revision: number;
  kind: string;
  status: string;
  label: string;
  stage: string | null;
  completed: number | null;
  total: number | null;
  error: string | null;
  saved_paths: string[];
}
export interface Bootstrap {
  preferences: Preferences;
  config: PublicConfig;
  config_loaded: boolean;
  config_error: string | null;
  session_id: number | null;
  selection: SelectionInfo;
  busy: TaskMessage | null;
  platform: string;
  elevated: boolean | null;
  elevation_error: string | null;
  live_processes: boolean;
  capture_dir: string;
  inputs: string[];
  qa: boolean;
  qa_ai: boolean;
}
export interface Filters {
  text: string;
  regex: boolean;
  suspicious: boolean;
  source: string | null;
  category: string | null;
  status: ParseStatus | null;
  protocol: string | null;
  offset: number;
  limit: number;
  tree: boolean;
  packets: boolean;
  flow: number | null;
  collapsed: string[];
  severity: Severity | null;
  origin: string;
}
export function defaultFilters(): Filters {
  return {
    text: "",
    regex: false,
    suspicious: false,
    source: null,
    category: null,
    status: null,
    protocol: null,
    offset: 0,
    limit: 100,
    tree: true,
    packets: false,
    flow: null,
    collapsed: [],
    severity: null,
    origin: "all",
  };
}
export interface Page<T> {
  offset: number;
  total: number;
  items: T[];
}
export interface Source {
  id: string;
  path: string;
  format: string;
  sha256: string;
  bytes: number;
}
export interface LogData {
  category: string;
  fields: Record<string, string>;
}
export interface ProcessData {
  pid: number;
  parent_pid: number | null;
  name: string;
  path: string | null;
  command: string[];
  user: string | null;
  status: string | null;
}
export interface PacketData {
  link_type: number;
  captured_bytes: number;
  original_bytes: number;
  source: string | null;
  destination: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  tcp_flags: number | null;
  application: Record<string, string>;
  payload_hex: string;
}
export type RecordData =
  | { kind: "log"; fields: LogData }
  | { kind: "process"; fields: ProcessData }
  | { kind: "packet"; fields: PacketData };
export interface RecordSummary {
  id: string;
  source_id: string;
  position: string;
  timestamp: string | null;
  status: ParseStatus;
  data: RecordData;
  summary: string;
}
export type EvidenceRecord = RecordSummary & { raw: string };
export interface Finding {
  id: string;
  origin: string;
  severity: Severity;
  title: string;
  description: string;
  evidence_ids: string[];
  confidence: number;
  recommendations: string[];
}
export interface Overview {
  sources: number;
  records: number;
  logs: number;
  processes: number;
  packets: number;
  flows: number;
  local_findings: number;
  ai_findings: number;
  suspicious: number;
  risks: number[];
  categories: string[];
  protocols: string[];
  parse_counts: number[];
}
export interface Flow {
  key: number;
  source_id: string;
  endpoint_a: string;
  endpoint_b: string;
  protocol: string;
  packets: number;
  matched_packets: number;
  bytes: number;
  first_seen: string | null;
  last_seen: string | null;
}
export interface ProcessRow {
  record_id: string;
  depth: number;
  context: boolean;
  orphan: boolean;
  cyclic: boolean;
  has_children: boolean;
}
export interface Diagnostic {
  level: "error" | "warning";
  source: string;
  position: string | null;
  message: string;
}
export interface RunSummary {
  index: number;
  model: string;
  endpoint: string;
  batches: number;
  completed: number;
  analyzed: number;
  selected: number;
  include_payload: boolean;
}
export interface AiBatch {
  index: number;
  evidence_ids: string[];
  attempts: { response: string | null; error: string | null }[];
  error: string | null;
}
export interface ViewResponse {
  session_id: number;
  revision: number;
  overview: Overview;
  records: Page<RecordSummary> | null;
  findings: Page<Finding> | null;
  flows: Page<Flow> | null;
  process_rows: ProcessRow[];
  sources: Page<Source>;
  record_sources: Record<string, string>;
  diagnostics: Page<Diagnostic>;
  runs: Page<RunSummary>;
  outside: boolean;
  offset: number;
  selection: SelectionInfo;
}
export interface DetailResponse {
  session_id: number;
  record: EvidenceRecord;
  source: Source | null;
  related: Finding[];
}
export interface ViewRequest {
  session_id: number;
  revision: number;
  screen: Screen;
  filters: Filters;
  focus_id: string | null;
  commit_selection: boolean;
  source_offset: number;
  diagnostic_offset: number;
  run_offset: number;
}
export interface ImportRequest {
  paths: string[];
  live: boolean;
  auto_logs: boolean;
  capture_dir: string;
  format: string;
  max_file_bytes: number;
  max_records: number;
  web_format: string | null;
}
export const severityLabel: Record<Severity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "信息",
};
export const statusLabel: Record<ParseStatus, string> = {
  parsed: "已解析",
  unrecognized: "未识别",
  malformed: "损坏",
};
export const screens: Screen[] = [
  "import",
  "overview",
  "logs",
  "processes",
  "network",
  "ai",
  "reports",
  "settings",
];
export const titles: Record<Screen, string> = {
  import: "导入分析",
  overview: "分析概览",
  logs: "日志证据",
  processes: "进程分析",
  network: "网络分析",
  ai: "AI 分析",
  reports: "报告与来源",
  settings: "设置",
};
export const evidenceScreen = (s: Screen) =>
  ["logs", "processes", "network"].includes(s);
