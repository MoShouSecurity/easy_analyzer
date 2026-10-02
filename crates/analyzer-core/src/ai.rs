use crate::execution::{ExecutionContext, ProgressEvent, Stage};
use crate::model::*;
use anyhow::{Context, Result, bail};
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

mod planning;
mod text;
pub use planning::{AiPlan, PreparedAi, prepare_with_context};
pub use text::{evidence_text, system_prompt};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    /// Legacy configurations may still explicitly select an environment variable.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub api_key_env: String,
    pub timeout_seconds: u64,
    /// UTF-8 byte budget for each evidence text batch, excluding prompts and transport encoding.
    pub batch_bytes: usize,
    /// None preserves legacy byte batching. Some enables context-based planning
    /// and cross-batch synthesis; this is the actual API's shared token limit.
    pub context_tokens: Option<usize>,
    pub max_output_tokens: u32,
    /// json_object, json_schema, or none, depending on provider compatibility.
    pub response_format: String,
    /// max_tokens or max_completion_tokens.
    pub token_parameter: String,
}
impl Default for AiConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.deepseek.com".into(),
            model: "deepseek-flash".into(),
            api_key: String::new(),
            api_key_env: String::new(),
            timeout_seconds: 300,
            batch_bytes: 98_304,
            context_tokens: None,
            max_output_tokens: 65_536,
            response_format: "json_object".into(),
            token_parameter: "max_tokens".into(),
        }
    }
}
impl std::fmt::Debug for AiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiConfig")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("api_key", &"[redacted]")
            .field("api_key_env", &"[redacted]")
            .field("timeout_seconds", &self.timeout_seconds)
            .field("batch_bytes", &self.batch_bytes)
            .field("context_tokens", &self.context_tokens)
            .field("max_output_tokens", &self.max_output_tokens)
            .field("response_format", &self.response_format)
            .field("token_parameter", &self.token_parameter)
            .finish()
    }
}
impl AiConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| {
            format!("cannot read AI config {} (run config init)", path.display())
        })?;
        let config: Self = toml::from_str(&text).map_err(|error: toml::de::Error| {
            let line = error.span().map_or(1, |span| {
                text.bytes()
                    .take(span.start)
                    .filter(|b| *b == b'\n')
                    .count()
                    + 1
            });
            anyhow::anyhow!(
                "AI 配置文件 TOML 格式或字段不正确（第 {line} 行）：{}；字符串值需要用双引号包围。",
                path.display()
            )
        })?;
        config.validate()?;
        Ok(config)
    }
    fn resolved_api_key(&self) -> Result<Option<String>> {
        let key = if !self.api_key.trim().is_empty() {
            Some(self.api_key.trim().to_owned())
        } else if !self.api_key_env.is_empty() {
            std::env::var(&self.api_key_env)
                .ok()
                .map(|key| key.trim().to_owned())
                .filter(|key| !key.is_empty())
        } else {
            None
        };
        if key.is_none() && self.endpoint()?.host_str() == Some("api.deepseek.com") {
            bail!("请在 config.toml 的 api_key 字段填写 DeepSeek API 密钥。");
        }
        Ok(key)
    }
    pub fn validate(&self) -> Result<()> {
        let _ = self.endpoint()?;
        if self.model.trim().is_empty() || self.model == "configure-your-model" {
            bail!("set model in the AI configuration");
        }
        if self.timeout_seconds == 0 || self.batch_bytes < 256 || self.max_output_tokens == 0 {
            bail!("invalid AI timeout/batch/output limits");
        }
        if let Some(context) = self.context_tokens {
            planning::input_budget(context, self.max_output_tokens)?;
        }
        if !["json_object", "json_schema", "none"].contains(&self.response_format.as_str()) {
            bail!("response_format must be json_object, json_schema, or none");
        }
        if !["max_tokens", "max_completion_tokens"].contains(&self.token_parameter.as_str()) {
            bail!("token_parameter must be max_tokens or max_completion_tokens");
        }
        Ok(())
    }
    pub fn endpoint(&self) -> Result<Url> {
        let mut url = Url::parse(&self.base_url).context("invalid AI base_url")?;
        if !["http", "https"].contains(&url.scheme()) || url.host_str().is_none() {
            bail!("AI endpoint must be an HTTP(S) URL");
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("AI base_url must not include credentials, query parameters, or fragments");
        }
        let path = url.path().trim_end_matches('/');
        if !path.ends_with("/chat/completions") {
            let path = format!("{path}/chat/completions");
            url.set_path(&path);
        }
        Ok(url)
    }
}
pub fn default_config_path() -> PathBuf {
    PathBuf::from("config.toml")
}
pub fn init_config(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("configuration already exists or path is not writable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(toml::to_string_pretty(&AiConfig::default())?.as_bytes())?;
    Ok(())
}

#[derive(Debug, Deserialize)]
// Providers may append explanatory fields; required fields and types stay enforced.
struct AiResponse {
    findings: Vec<AiFinding>,
    #[serde(default)]
    context: Vec<AiFinding>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AiFinding {
    severity: Severity,
    title: String,
    description: String,
    evidence_ids: Vec<String>,
    confidence: f64,
    recommendations: Vec<String>,
}

pub fn evidence_value(record: &Record, include_payload: bool) -> Value {
    let mut v = serde_json::to_value(record).expect("serializable record");
    if matches!(record.data, RecordData::Packet(_)) && !include_payload {
        v.as_object_mut().unwrap().remove("raw");
        v["data"]["fields"]
            .as_object_mut()
            .unwrap()
            .remove("payload_hex");
    }
    v
}
#[derive(Clone)]
struct TextEvidence {
    id: String,
    text: String,
}

#[cfg(test)]
fn batches(
    records: &[&Record],
    include_payload: bool,
    limit: usize,
) -> Result<Vec<Vec<TextEvidence>>> {
    Ok(prepare_with_context(
        records,
        &AiConfig {
            batch_bytes: limit,
            ..Default::default()
        },
        include_payload,
        &ExecutionContext::default(),
    )?
    .batches)
}

fn schema(context: bool) -> Value {
    let mut value = json!({"type":"object","additionalProperties":false,"required":["findings"],"properties":{"findings":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["severity","title","description","evidence_ids","confidence","recommendations"],"properties":{
        "severity":{"type":"string","enum":["info","low","medium","high","critical"]},"title":{"type":"string"},"description":{"type":"string"},"evidence_ids":{"type":"array","items":{"type":"string"}},"confidence":{"type":"number"},"recommendations":{"type":"array","items":{"type":"string"}}
    }}}}});
    if context {
        value["properties"]["context"] = value["properties"]["findings"].clone();
        value["required"] = json!(["findings", "context"]);
    }
    value
}
fn request(
    client: &Client,
    config: &AiConfig,
    key: Option<&str>,
    system: &str,
    user: &str,
) -> Result<String> {
    let mut body = json!({"model":config.model,"messages":[{"role":"system","content":system},{"role":"user","content":user}],"stream":false});
    body[&config.token_parameter] = json!(config.max_output_tokens);
    match config.response_format.as_str() {
        "json_object" => body["response_format"] = json!({"type":"json_object"}),
        "json_schema" => {
            body["response_format"] = json!({"type":"json_schema","json_schema":{"name":"incident_findings","strict":true,"schema":schema(config.context_tokens.is_some())}})
        }
        _ => {}
    }
    let mut req = client.post(config.endpoint()?).json(&body);
    if let Some(key) = key {
        req = req.bearer_auth(key);
    }
    let response = req.send().map_err(|e| {
        anyhow::anyhow!(
            "AI request failed: {}",
            if e.is_timeout() {
                "timeout"
            } else if e.is_connect() {
                "connection failure"
            } else {
                "transport error"
            }
        )
    })?;
    let status = response.status();
    // Do not include server error bodies: providers may echo credentials or evidence.
    if !status.is_success() {
        bail!(
            "AI server returned HTTP {status}; check endpoint, credentials, model and response_format"
        );
    }
    let mut bytes = vec![];
    response.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        bail!("AI response exceeded 4 MiB");
    }
    let v: Value = serde_json::from_slice(&bytes).context("AI returned invalid response JSON")?;
    let choice = v
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|v| v.first())
        .context("missing AI choices")?;
    if choice.get("finish_reason").and_then(Value::as_str) == Some("length") {
        bail!("AI output hit its token limit; increase max_output_tokens or reduce batch_bytes");
    }
    if choice["message"]["refusal"].as_str().is_some() {
        bail!("AI declined this analysis");
    }
    let content = choice["message"]["content"]
        .as_str()
        .context("missing AI message content")?;
    Ok(content.to_owned())
}
fn validate(content: &str, allowed: &HashSet<String>) -> Result<AiResponse> {
    let mut s = content.trim();
    if s.starts_with("```json") {
        s = s.strip_prefix("```json").unwrap().trim();
        s = s
            .strip_suffix("```")
            .context("unterminated AI JSON fence")?
            .trim();
    }
    let mut response: AiResponse =
        serde_json::from_str(s).context("AI findings do not match the required JSON schema")?;
    for f in response.findings.iter_mut().chain(&mut response.context) {
        if f.title.trim().is_empty()
            || f.description.trim().is_empty()
            || !f.confidence.is_finite()
            || !(0.0..=1.0).contains(&f.confidence)
            || f.evidence_ids.is_empty()
        {
            bail!("AI finding has empty text/evidence or invalid confidence");
        }
        if f.evidence_ids.iter().any(|id| !allowed.contains(id)) {
            bail!("AI cited an evidence ID outside the analyzed batch");
        }
        f.evidence_ids.sort();
        f.evidence_ids.dedup();
    }
    Ok(response)
}
/// Returns findings atomically: a failed batch never marks a partial analysis as complete.
pub fn analyze(
    records: &[&Record],
    config: &AiConfig,
    include_payload: bool,
) -> Result<(Vec<Finding>, AiRun)> {
    analyze_with_progress(records, config, include_payload, |_, _| {})
}

/// Calls `progress(index, total)` before each evidence request, using one-based batch indices.
/// Synthesis emits ExecutionContext events with a batch count for each summary round.
pub fn analyze_with_progress(
    records: &[&Record],
    config: &AiConfig,
    include_payload: bool,
    mut progress: impl FnMut(usize, usize),
) -> Result<(Vec<Finding>, AiRun)> {
    let result = analyze_report_with_progress(records, config, include_payload, |i, n, _| {
        progress(i, n);
    })?;
    if let Some(error) = result.error {
        bail!(error);
    }
    Ok((result.findings, result.run))
}

pub struct AiAnalysis {
    pub findings: Vec<Finding>,
    pub run: AiRun,
    pub error: Option<String>,
    /// Deterministic recap of accepted results on partial failure/cancellation.
    /// Stored by app as a diagnostic, never as a new model finding.
    pub local_summary: Option<String>,
}

pub struct ControlledAiAnalysis {
    pub analysis: AiAnalysis,
    pub cancelled: bool,
}

/// Preserves accepted results and raw replies if a later batch fails.
pub fn analyze_report_with_progress(
    records: &[&Record],
    config: &AiConfig,
    include_payload: bool,
    progress: impl FnMut(usize, usize, usize),
) -> Result<AiAnalysis> {
    Ok(analyze_report_with_context(
        records,
        config,
        include_payload,
        &ExecutionContext::default(),
        progress,
    )?
    .analysis)
}

/// Cancellation is cooperative: finish/validate an in-flight response, but do not
/// retry or start another request after cancellation. Accepted results stay available.
pub fn analyze_report_with_context(
    records: &[&Record],
    config: &AiConfig,
    include_payload: bool,
    ctx: &ExecutionContext,
    progress: impl FnMut(usize, usize, usize),
) -> Result<ControlledAiAnalysis> {
    let prepared = prepare_with_context(records, config, include_payload, ctx)?;
    analyze_prepared_with_context(prepared, ctx, progress)
}

/// Execute exactly the settings/evidence planned locally, without re-reading configuration.
pub fn analyze_prepared_with_context(
    prepared: PreparedAi,
    ctx: &ExecutionContext,
    mut progress: impl FnMut(usize, usize, usize),
) -> Result<ControlledAiAnalysis> {
    ctx.check()?;
    let PreparedAi {
        config,
        system,
        batches,
        plan,
        include_payload,
    } = prepared;
    let key = config.resolved_api_key()?;
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_seconds))
        .redirect(Policy::none())
        .build()?;
    let count = batches.len();
    let mut run = AiRun {
        model: config.model.clone(),
        endpoint: config.endpoint()?.to_string(),
        batches: count + usize::from(plan.summary_planned),
        analyzed_records: 0,
        include_payload,
        completed_batches: Some(0),
        selected_records: Some(plan.selected_records),
        batch_results: vec![],
    };
    let mut findings = vec![];
    let mut seen = HashSet::new();
    let mut clues = vec![];
    let mut failures = vec![];
    let mut failed_evidence = vec![];
    let mut neutral_count = 0;
    let mut neutral_preview = vec![];
    for (i, batch) in batches.into_iter().enumerate() {
        if ctx.cancellation.is_cancelled() {
            break;
        }
        let user = format!(
            "当前批次 batch: {}\n总证据批次 total_batches: {}\n当前批次记录数: {}\n包含网络原始包及载荷: {}\n\n{}",
            i + 1,
            count,
            batch.len(),
            include_payload,
            batch
                .iter()
                .map(|r| r.text.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        );
        let ids = batch.iter().map(|r| r.id.clone()).collect();
        let (batch_result, accepted) = send_batch(
            &client,
            &config,
            key.as_deref(),
            &system,
            &user,
            i + 1,
            ProgressEvent {
                stage: Stage::Ai,
                source: None,
                completed: i + 1,
                total: Some(count),
                attempt: None,
            },
            ids,
            ctx,
            &mut progress,
        );
        if batch_result.attempts.is_empty() {
            break;
        }
        if let Some(error) = &batch_result.error {
            failed_evidence.push(i + 1);
            failures.push(format!(
                "AI 第 {}/{} 证据批次失败：{}；已跳过此批次，继续处理其余批次。",
                i + 1,
                count,
                error
            ));
        }
        run.batch_results.push(batch_result);
        let Some(parsed) = accepted else { continue };
        run.completed_batches = Some(run.completed() + 1);
        run.analyzed_records += batch.len();
        neutral_count += parsed.context.len();
        neutral_preview.extend(
            parsed
                .context
                .iter()
                .take(5 - neutral_preview.len())
                .cloned(),
        );
        if plan.summary_planned {
            clues.extend(parsed.findings.iter().cloned());
            clues.extend(parsed.context);
        }
        append_findings(parsed.findings, &config, &mut findings, &mut seen)?;
    }
    let coverage = EvidenceCoverage {
        batches: count,
        completed: run.completed(),
        failed: failed_evidence,
        selected: run.selected(),
        analyzed: run.analyzed_records,
    };
    if plan.summary_planned && !ctx.cancellation.is_cancelled() {
        if clues.is_empty() {
            // No accepted facts to synthesize; no pointless API request.
            run.batches = count;
        } else if let Err(error) = synthesize(
            clues,
            &config,
            &client,
            key.as_deref(),
            &mut run,
            &mut findings,
            &mut seen,
            &coverage,
            ctx,
            &mut progress,
        ) {
            failures.push(format!(
                "跨批汇总未完成：{error:#}；证据批次有效结果与原始回复保留。"
            ));
        }
    }
    let cancelled = ctx.cancellation.is_cancelled();
    if cancelled {
        failures.push(format!(
            "AI 分析已取消（已完成 {}/{} 请求阶段）；已完成结果和原始回复保存在报告中，后续请求未发送。",
            run.completed(),
            run.batches
        ));
    }
    let local_summary = (!failures.is_empty()).then(|| {
        local_result_summary(
            &coverage,
            &findings,
            neutral_count,
            &neutral_preview,
            (run.completed(), run.batches, run.batch_results.len()),
        )
    });
    Ok(ControlledAiAnalysis {
        analysis: AiAnalysis {
            findings,
            run,
            error: failure_message(&failures),
            local_summary,
        },
        cancelled,
    })
}

struct EvidenceCoverage {
    batches: usize,
    completed: usize,
    failed: Vec<usize>,
    selected: usize,
    analyzed: usize,
}
impl EvidenceCoverage {
    fn description(&self) -> String {
        let indices = self
            .failed
            .iter()
            .take(20)
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join("、");
        format!(
            "范围 {} 条，成功分析 {} 条；证据批次成功 {}/{}，失败 {}，未执行 {}。{}",
            self.selected,
            self.analyzed,
            self.completed,
            self.batches,
            self.failed.len(),
            self.batches
                .saturating_sub(self.completed + self.failed.len()),
            if self.failed.is_empty() {
                String::new()
            } else {
                format!(
                    "失败证据批次：{indices}{}；缺失范围不能视为正常。",
                    if self.failed.len() > 20 {
                        "等（完整列表见运行历史）"
                    } else {
                        ""
                    }
                )
            }
        )
    }
}
fn failure_message(failures: &[String]) -> Option<String> {
    if failures.is_empty() {
        return None;
    }
    let mut message = failures
        .iter()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    if failures.len() > 8 {
        message.push_str(&format!(
            "\n另有 {} 次失败，完整错误见运行历史。",
            failures.len() - 8
        ));
    }
    Some(message)
}
fn local_result_summary(
    coverage: &EvidenceCoverage,
    findings: &[Finding],
    neutral_count: usize,
    neutral: &[AiFinding],
    request_counts: (usize, usize, usize),
) -> String {
    // Bounded display excerpts only. Complete replies/findings/IDs remain in the report.
    fn brief(text: &str) -> String {
        let mut chars = text.chars();
        let mut value: String = chars.by_ref().take(400).collect();
        if chars.next().is_some() {
            value.push('…');
        }
        value
    }
    fn references(ids: &[String]) -> String {
        let mut value = ids
            .iter()
            .take(5)
            .map(|id| brief(id))
            .collect::<Vec<_>>()
            .join("、");
        if ids.len() > 5 {
            value.push_str(&format!("（另 {} 个引用）", ids.len() - 5));
        }
        value
    }
    let (completed, total, attempted) = request_counts;
    let mut text = format!(
        "本地结果整理（不是新的 AI 关联推理）\n请求阶段成功 {}/{total}，失败 {}，未执行 {}（含跨批汇总）。\n{}\n仅整理已经通过 JSON 和证据引用校验的成功回复；失败回复不作为发现。\n已校验发现 {} 项，中性线索 {} 项。",
        completed,
        attempted.saturating_sub(completed),
        total.saturating_sub(attempted),
        coverage.description(),
        findings.len(),
        neutral_count
    );
    for finding in findings.iter().take(10) {
        text.push_str(&format!(
            "\n\n• {}\n{}\n证据：{}",
            brief(&finding.title),
            brief(&finding.description),
            references(&finding.evidence_ids)
        ));
    }
    for clue in neutral {
        text.push_str(&format!(
            "\n\n• 中性线索：{}\n{}\n证据：{}",
            brief(&clue.title),
            brief(&clue.description),
            references(&clue.evidence_ids)
        ));
    }
    if findings.len() > 10 || neutral_count > neutral.len() {
        text.push_str(
            "\n\n此处仅展示部分条目的摘要；完整发现、引用及原始回复保留在报告与运行历史中。",
        );
    }
    if coverage.completed == 0 {
        text.push_str("\n没有已校验的成功证据回复，无法形成内容总结。");
    }
    text
}

#[allow(clippy::too_many_arguments)]
fn send_batch(
    client: &Client,
    config: &AiConfig,
    key: Option<&str>,
    system: &str,
    user: &str,
    index: usize,
    batch_progress: ProgressEvent,
    ids: Vec<String>,
    ctx: &ExecutionContext,
    progress: &mut impl FnMut(usize, usize, usize),
) -> (AiBatch, Option<AiResponse>) {
    let allowed = ids.iter().cloned().collect();
    let mut result = AiBatch {
        index,
        evidence_ids: ids,
        attempts: vec![],
        error: None,
    };
    for attempt in 1..=3 {
        if ctx.cancellation.is_cancelled() {
            break;
        }
        if batch_progress.source.is_none()
            && let Some(total) = batch_progress.total
        {
            progress(index, total, attempt);
        }
        ctx.notify(ProgressEvent {
            attempt: Some(attempt),
            ..batch_progress.clone()
        });
        if ctx.cancellation.is_cancelled() {
            break;
        }
        let retry_user = if attempt == 1 {
            user.to_owned()
        } else {
            format!(
                "{user}\n上次回复未通过 JSON 或证据校验，这是第 {attempt} 次请求。请只返回完整合法 JSON，保持简洁，正确转义，只引用本次输入的证据编号。"
            )
        };
        if let Some(context) = config.context_tokens {
            let estimate = match planning::estimated_tokens(system, ctx).and_then(|n| {
                Ok(
                    n.saturating_add(planning::estimated_tokens(&retry_user, ctx)?)
                        .saturating_add(1024),
                )
            }) {
                Ok(n) => n,
                Err(_) => break,
            };
            if estimate > planning::input_budget(context, config.max_output_tokens).unwrap_or(0) {
                let error =
                    "完整请求的保守 token 估算超过输入预算；未发送，也未截断证据".to_owned();
                result.attempts.push(AiAttempt {
                    response: None,
                    error: Some(error.clone()),
                });
                result.error = Some(error);
                break;
            }
        }
        let content = match request(client, config, key, system, &retry_user) {
            Ok(content) => content,
            Err(error) => {
                let error = format!("{error:#}");
                result.attempts.push(AiAttempt {
                    response: None,
                    error: Some(error.clone()),
                });
                result.error = Some(error);
                break;
            }
        };
        match validate(&content, &allowed) {
            Ok(parsed) => {
                result.attempts.push(AiAttempt {
                    response: Some(content),
                    error: None,
                });
                result.error = None;
                return (result, Some(parsed));
            }
            Err(error) => {
                let error = format!("{error:#}");
                result.attempts.push(AiAttempt {
                    response: Some(content),
                    error: Some(error.clone()),
                });
                result.error = Some(error);
            }
        }
    }
    (result, None)
}

fn append_findings(
    parsed: Vec<AiFinding>,
    config: &AiConfig,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) -> Result<()> {
    for f in parsed {
        let signature = serde_json::to_string(&(&f.title, &f.severity, &f.evidence_ids))?;
        if seen.insert(signature) {
            findings.push(Finding {
                id: format!("ai:{}", findings.len() + 1),
                origin: format!("ai:{}", config.model),
                severity: f.severity,
                title: f.title,
                description: f.description,
                evidence_ids: f.evidence_ids,
                confidence: f.confidence,
                recommendations: f.recommendations,
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn synthesize(
    mut clues: Vec<AiFinding>,
    config: &AiConfig,
    client: &Client,
    key: Option<&str>,
    run: &mut AiRun,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
    coverage: &EvidenceCoverage,
    ctx: &ExecutionContext,
    progress: &mut impl FnMut(usize, usize, usize),
) -> Result<()> {
    let system = planning::summary_system();
    let budget = planning::input_budget(config.context_tokens.unwrap(), config.max_output_tokens)?;
    let capacity = budget
        .checked_sub(planning::estimated_tokens(system, ctx)? + 2048)
        .context("跨批汇总提示词超过输入预算")?;
    let mut failures = vec![];
    // Bounded hierarchical reduction; never silently discard/truncate a clue or an ID.
    for round in 0..4 {
        ctx.check()?;
        let mut groups: Vec<Vec<AiFinding>> = vec![];
        let mut group = vec![];
        let mut used = 0usize;
        for (i, clue) in clues.into_iter().enumerate() {
            ctx.tick(Stage::AiPreparing, Some("跨批汇总"), i, None)?;
            let weight =
                planning::estimated_tokens(&serde_json::to_string(&clue)?, ctx)?.saturating_add(1);
            if weight > capacity {
                bail!("单条关联线索超过汇总预算，请增大上下文或减小输出上限");
            }
            if used.saturating_add(weight) > capacity && !group.is_empty() {
                groups.push(std::mem::take(&mut group));
                used = 0;
            }
            used = used.saturating_add(weight);
            group.push(clue);
        }
        if !group.is_empty() {
            groups.push(group);
        }
        if groups.is_empty() {
            return Ok(());
        }
        let final_round = groups.len() == 1;
        run.batches += if round == 0 {
            groups.len() - 1
        } else {
            groups.len()
        };
        let mut next = vec![];
        let mut accepted_groups = 0;
        let round_batches = groups.len();
        for (group_index, group) in groups.into_iter().enumerate() {
            ctx.check()?;
            let ids: HashSet<String> = group
                .iter()
                .flat_map(|f| f.evidence_ids.iter().cloned())
                .collect();
            let user = format!(
                "阶段：跨批汇总，第 {} 轮。{} 以下为经过校验的分批发现与中性线索；不是原始日志。本组仅覆盖输入所列证据，不能代表缺失范围。\n{}",
                round + 1,
                coverage.description(),
                serde_json::to_string(&group)?
            );
            let (result, accepted) = send_batch(
                client,
                config,
                key,
                system,
                &user,
                run.batch_results.len() + 1,
                ProgressEvent {
                    stage: Stage::Ai,
                    source: Some(format!("跨批汇总（第 {} 轮）", round + 1)),
                    completed: group_index + 1,
                    total: Some(round_batches),
                    attempt: None,
                },
                ids.into_iter().collect(),
                ctx,
                progress,
            );
            let error = result.error.clone();
            if !result.attempts.is_empty() {
                run.batch_results.push(result);
            }
            let Some(parsed) = accepted else {
                if ctx.cancellation.is_cancelled() {
                    bail!("已取消");
                }
                failures.push(format!(
                    "第 {} 轮汇总分组 {}/{} 失败：{}",
                    round + 1,
                    group_index + 1,
                    round_batches,
                    error.unwrap_or_else(|| "无有效回复".into())
                ));
                // Carry validated input facts forward; never use a failed response as facts.
                next.extend(group);
                continue;
            };
            accepted_groups += 1;
            run.completed_batches = Some(run.completed() + 1);
            next.extend(parsed.findings.iter().cloned());
            next.extend(parsed.context);
            append_findings(parsed.findings, config, findings, seen)?;
        }
        if accepted_groups == 0 {
            bail!(
                "{}；本轮没有成功汇总回复，停止后续汇总。",
                failure_message(&failures).unwrap()
            );
        }
        if final_round || next.is_empty() {
            return failure_message(&failures).map_or(Ok(()), |error| {
                Err(anyhow::anyhow!(
                    "{error}；其余成功回复及保留线索已继续汇总。"
                ))
            });
        }
        clues = next;
    }
    // Represent unfinished synthesis in existing schema, preserving all accepted results.
    run.batches += 1;
    bail!("关联线索经四轮仍不能收敛到单次预算，未继续请求")
}

pub fn check(config: &AiConfig) -> Result<()> {
    config.validate()?;
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_seconds))
        .redirect(Policy::none())
        .build()?;
    let key = config.resolved_api_key()?;
    let response = request(
        &client,
        config,
        key.as_deref(),
        &system_prompt(&[], false),
        "连接检查，不提供证据。请返回 JSON：{\"findings\":[]}。",
    )?;
    validate(&response, &HashSet::new())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{make_record, source_for};
    #[test]
    fn payload_boundary_and_schema() {
        let s = source_for("pcap", "pcap", b"fixture");
        let r = make_record(
            &s,
            "offset:24".into(),
            None,
            "secret-raw".into(),
            ParseStatus::Parsed,
            RecordData::Packet(PacketData {
                payload_hex: "secret-payload".into(),
                ..Default::default()
            }),
        );
        let safe = evidence_value(&r, false).to_string();
        assert!(!safe.contains("secret"));
        assert!(evidence_value(&r, true).to_string().contains("secret"));
        assert!(validate(r#"{"findings":[{"severity":"high","title":"test","description":"test","evidence_ids":["fake"],"confidence":0.8,"recommendations":[]}]}"#,&HashSet::from([r.id])).is_err());
        assert!(validate(r#"{"findings":[],"extra":1}"#, &HashSet::new()).is_ok());
        assert!(validate(r#"{"findings":[],"context":[{"severity":"info","title":"neutral clue","description":"test","evidence_ids":["outside"],"confidence":0.8,"recommendations":[]}]}"#, &HashSet::new()).is_err());
    }
    fn mock(
        status: &str,
        body: String,
        delay: Duration,
    ) -> (String, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let status = status.to_owned();
        let join = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = vec![];
            let mut buf = [0; 4096];
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
                if let Some(pos) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..pos]);
                    let length = header
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .strip_prefix("content-length:")
                                .map(|n| n.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= pos + 4 + length {
                        break;
                    }
                }
            }
            std::thread::sleep(delay);
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            String::from_utf8(bytes).unwrap()
        });
        (url, join)
    }
    #[test]
    fn compatible_http_and_error_responses() {
        let body =
            json!({"choices":[{"finish_reason":"stop","message":{"content":"{\"findings\":[]}"}}]})
                .to_string();
        let (url, join) = mock("200 OK", body, Duration::ZERO);
        let c = AiConfig {
            base_url: url,
            model: "mock".into(),
            ..Default::default()
        };
        check(&c).unwrap();
        let req = join.join().unwrap();
        assert!(req.starts_with("POST /v1/chat/completions"));
        assert!(req.contains("json_object"));
        let (url, join) = mock("401 Unauthorized", "secret-echo".into(), Duration::ZERO);
        let c = AiConfig {
            base_url: url,
            model: "mock".into(),
            ..Default::default()
        };
        let err = check(&c).unwrap_err().to_string();
        assert!(err.contains("401"));
        assert!(!err.contains("secret"));
        join.join().unwrap();
    }
    #[test]
    fn timeout_and_invalid_result() {
        let (url, join) = mock("200 OK", "{}".into(), Duration::from_millis(1200));
        let c = AiConfig {
            base_url: url,
            model: "mock".into(),
            timeout_seconds: 1,
            ..Default::default()
        };
        assert!(check(&c).is_err());
        join.join().unwrap();
        let (url, join) = mock("200 OK", "{}".into(), Duration::ZERO);
        let c = AiConfig {
            base_url: url,
            model: "mock".into(),
            ..Default::default()
        };
        assert!(check(&c).is_err());
        join.join().unwrap();
    }
    #[test]
    fn batching_never_truncates() {
        let s = source_for("text", "text", b"x");
        let r = make_record(
            &s,
            "line:1".into(),
            None,
            "x".repeat(2000),
            ParseStatus::Parsed,
            RecordData::Log(LogData::default()),
        );
        assert!(batches(&[&r], false, 256).is_err());
        let b = batches(&[&r, &r], false, 3000).unwrap();
        assert_eq!(b.len(), 2);
        assert!(b[0][0].text.contains(&"x".repeat(2000)));
    }
    #[test]
    fn real_analysis_batches_and_payload_requests() {
        let source = source_for("fixture", "text", b"fixture");
        let r1 = make_record(
            &source,
            "line:1".into(),
            None,
            "a".repeat(1000),
            ParseStatus::Parsed,
            RecordData::Log(LogData::default()),
        );
        let r2 = make_record(
            &source,
            "line:2".into(),
            None,
            "b".repeat(1000),
            ParseStatus::Parsed,
            RecordData::Log(LogData::default()),
        );
        for record in [&r1, &r2] {
            let body=json!({"choices":[{"finish_reason":"stop","message":{"content":json!({"findings":[{"severity":"medium","title":"合成发现","description":"仅测试传输","evidence_ids":[record.id],"confidence":0.7,"recommendations":["核查"]}]}).to_string()}}]}).to_string();
            let (url, join) = mock("200 OK", body, Duration::ZERO);
            let config = AiConfig {
                base_url: url,
                model: "mock".into(),
                ..Default::default()
            };
            let (findings, run) = analyze(&[record], &config, false).unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].evidence_ids[0], record.id);
            assert_eq!(run.analyzed_records, 1);
            let request = join.join().unwrap();
            assert!(request.contains("total_batches"));
        }
        let r = make_record(
            &source,
            "offset:1".into(),
            None,
            "private-raw-packet".into(),
            ParseStatus::Parsed,
            RecordData::Packet(PacketData {
                payload_hex: "private-payload".into(),
                ..Default::default()
            }),
        );
        for include in [false, true] {
            let body = json!({"choices":[{"message":{"content":"{\"findings\":[]}"}}]}).to_string();
            let (url, join) = mock("200 OK", body, Duration::ZERO);
            let config = AiConfig {
                base_url: url,
                model: "mock".into(),
                ..Default::default()
            };
            analyze(&[&r], &config, include).unwrap();
            let request = join.join().unwrap();
            assert_eq!(request.contains("private-raw-packet"), include);
            assert_eq!(request.contains("private-payload"), include);
        }
        assert_eq!(batches(&[&r1, &r2], false, 2000).unwrap().len(), 2);
    }
    #[test]
    fn local_recap_preserves_neutral_facts_without_creating_findings() {
        let coverage = EvidenceCoverage {
            batches: 3,
            completed: 2,
            failed: vec![2],
            selected: 30,
            analyzed: 20,
        };
        let clue = AiFinding {
            severity: crate::Severity::Low,
            title: "中性登录线索".into(),
            description: "正常登录主机A".into(),
            evidence_ids: vec!["evidence-valid".into()],
            confidence: 0.7,
            recommendations: vec!["核对".into()],
        };
        let text = local_result_summary(&coverage, &[], 1, &[clue], (2, 4, 4));
        assert!(text.contains("请求阶段成功 2/4，失败 2，未执行 0"));
        assert!(text.contains("已校验发现 0 项，中性线索 1 项"));
        assert!(text.contains("中性登录线索"));
        assert!(text.contains("evidence-valid"));
        assert!(text.contains("失败证据批次：2"));
        assert!(text.contains("不是新的 AI 关联推理"));
    }
}
