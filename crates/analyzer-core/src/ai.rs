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

mod text;
pub use text::{evidence_text, system_prompt};

#[derive(Clone, Serialize, Deserialize)]
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
}
#[derive(Debug, Deserialize)]
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
struct TextEvidence {
    id: String,
    text: String,
}

fn batches(
    records: &[&Record],
    include_payload: bool,
    limit: usize,
) -> Result<Vec<Vec<TextEvidence>>> {
    let mut batches = vec![];
    let mut batch = vec![];
    let mut size = 0;
    for record in records {
        let text = evidence_text(record, include_payload);
        let n = text.len() + 1;
        if n > limit {
            bail!(
                "AI 证据 {} 需要 {} 字节，超过 batch_bytes={}；请增大 config.toml 中的 batch_bytes，或缩小分析范围。",
                record.position,
                n,
                limit
            );
        }
        if size + n > limit && !batch.is_empty() {
            batches.push(std::mem::take(&mut batch));
            size = 0;
        }
        size += n;
        batch.push(TextEvidence {
            id: record.id.clone(),
            text,
        });
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    Ok(batches)
}
fn schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["findings"],"properties":{"findings":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["severity","title","description","evidence_ids","confidence","recommendations"],"properties":{
        "severity":{"type":"string","enum":["info","low","medium","high","critical"]},"title":{"type":"string"},"description":{"type":"string"},"evidence_ids":{"type":"array","items":{"type":"string"}},"confidence":{"type":"number"},"recommendations":{"type":"array","items":{"type":"string"}}
    }}}}})
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
            body["response_format"] = json!({"type":"json_schema","json_schema":{"name":"incident_findings","strict":true,"schema":schema()}})
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
fn validate(content: &str, allowed: &HashSet<String>) -> Result<Vec<AiFinding>> {
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
    for f in &mut response.findings {
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
    Ok(response.findings)
}
/// Returns findings atomically: a failed batch never marks a partial analysis as complete.
pub fn analyze(
    records: &[&Record],
    config: &AiConfig,
    include_payload: bool,
) -> Result<(Vec<Finding>, AiRun)> {
    analyze_with_progress(records, config, include_payload, |_, _| {})
}

/// Calls `progress(index, total)` before each request, using one-based batch indices.
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
}

/// Preserves accepted results and raw replies if a later batch fails.
/// Progress reports one-based batch, total batch count, and attempt (1 through 3).
pub fn analyze_report_with_progress(
    records: &[&Record],
    config: &AiConfig,
    include_payload: bool,
    mut progress: impl FnMut(usize, usize, usize),
) -> Result<AiAnalysis> {
    config.validate()?;
    if records.is_empty() {
        bail!("no evidence selected for AI analysis");
    }
    let key = config.resolved_api_key()?;
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_seconds))
        .redirect(Policy::none())
        .build()?;
    let batches = batches(records, include_payload, config.batch_bytes)?;
    let count = batches.len();
    let mut run = AiRun {
        model: config.model.clone(),
        endpoint: config.endpoint()?.to_string(),
        batches: count,
        analyzed_records: 0,
        include_payload,
        completed_batches: Some(0),
        selected_records: Some(records.len()),
        batch_results: vec![],
    };
    let system = system_prompt(records, include_payload);
    let mut findings = vec![];
    let mut seen = HashSet::new();
    let mut failure = None;
    for (i, batch) in batches.into_iter().enumerate() {
        let allowed: HashSet<String> = batch.iter().map(|record| record.id.clone()).collect();
        let mut user = format!(
            "当前批次 batch: {}\n总批次 total_batches: {}\n当前批次记录数: {}\n包含网络原始包及载荷: {}\n\n",
            i + 1,
            count,
            batch.len(),
            include_payload
        );
        for record in &batch {
            user.push_str(&record.text);
            user.push('\n');
        }
        let mut batch_result = AiBatch {
            index: i + 1,
            evidence_ids: batch.iter().map(|record| record.id.clone()).collect(),
            attempts: vec![],
            error: None,
        };
        let mut accepted = None;
        for attempt in 1..=3 {
            progress(i + 1, count, attempt);
            let retry_user = if attempt == 1 {
                user.clone()
            } else {
                format!(
                    "{user}\n上次回复未通过 JSON 或证据校验，这是第 {attempt} 次请求。请重新分析同一批证据，只返回完整、合法的 JSON；保持描述简洁，正确转义引号和换行，只引用本批证据编号，不要添加注释或省略号。"
                )
            };
            let content = match request(&client, config, key.as_deref(), &system, &retry_user) {
                Ok(content) => content,
                Err(error) => {
                    let message = format!("{error:#}");
                    batch_result.attempts.push(AiAttempt {
                        response: None,
                        error: Some(message.clone()),
                    });
                    batch_result.error = Some(message);
                    break;
                }
            };
            match validate(&content, &allowed) {
                Ok(parsed) => {
                    batch_result.attempts.push(AiAttempt {
                        response: Some(content),
                        error: None,
                    });
                    batch_result.error = None;
                    accepted = Some(parsed);
                    break;
                }
                Err(error) => {
                    let message = format!("{error:#}");
                    batch_result.attempts.push(AiAttempt {
                        response: Some(content),
                        error: Some(message.clone()),
                    });
                    batch_result.error = Some(message);
                }
            }
        }
        if let Some(error) = &batch_result.error {
            failure = Some(format!(
                "AI 第 {}/{} 批失败（请求 {} 次，已完成 {}/{} 批）：{}；后续批次未执行，已完成结果和原始回复保存在报告中。",
                i + 1,
                count,
                batch_result.attempts.len(),
                run.completed(),
                count,
                error
            ));
        }
        run.batch_results.push(batch_result);
        let Some(parsed) = accepted else { break };
        run.completed_batches = Some(run.completed() + 1);
        run.analyzed_records += batch.len();
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
    }
    Ok(AiAnalysis {
        findings,
        run,
        error: failure,
    })
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
}
