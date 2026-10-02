use crate::execution::{ExecutionContext, Stage};
use crate::model::*;
use anyhow::Result;
use chrono::DateTime;
use regex::{Regex, RegexBuilder};
use std::collections::BTreeMap;

mod default_logs;
type LoginKey = (String, String, String, String);

pub fn query(records: &[Record], expression: &str, regex: bool) -> Result<Vec<String>> {
    query_with_context(records, expression, regex, &ExecutionContext::default())
}

pub fn query_with_context(
    records: &[Record],
    expression: &str,
    regex: bool,
    ctx: &ExecutionContext,
) -> Result<Vec<String>> {
    let pattern = if regex {
        expression.to_owned()
    } else {
        regex::escape(expression)
    };
    let search = RegexBuilder::new(&pattern).case_insensitive(true).build()?;
    let mut matches = vec![];
    for (i, record) in records.iter().enumerate() {
        ctx.tick(Stage::Query, None, i, Some(records.len()))?;
        if search.is_match(&record.raw)
            || search.is_match(&serde_json::to_string(&record.data).unwrap_or_default())
        {
            matches.push(record.id.clone());
        }
    }
    ctx.emit(Stage::Query, None, records.len(), Some(records.len()));
    ctx.check()?;
    Ok(matches)
}

fn finding(
    rule: &str,
    severity: Severity,
    title: &str,
    description: String,
    ids: Vec<String>,
    confidence: f64,
) -> Finding {
    Finding {
        id: format!("{rule}:{}", ids.first().cloned().unwrap_or_default()),
        origin: format!("local:{rule}"),
        severity,
        title: title.into(),
        description,
        evidence_ids: ids,
        confidence,
        recommendations: vec!["核对原始证据、资产用途及操作时间，结合其他来源确认。".into()],
    }
}
fn decoded(s: &str) -> String {
    let mut out = s.to_owned();
    for _ in 0..2 {
        let b = out.as_bytes();
        let mut v = vec![];
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%'
                && i + 2 < b.len()
                && let Ok(n) =
                    u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16)
            {
                v.push(n);
                i += 3;
                continue;
            }
            v.push(b[i]);
            i += 1;
        }
        out = String::from_utf8_lossy(&v).to_string();
    }
    out.to_lowercase()
}
pub fn analyze(report: &mut AnalysisReport) {
    analyze_with_context(report, &ExecutionContext::default()).expect("uncancelled rules");
}

pub fn analyze_with_context(report: &mut AnalysisReport, ctx: &ExecutionContext) -> Result<()> {
    ctx.emit(Stage::Rules, None, 0, Some(report.records.len()));
    ctx.check()?;
    report.findings.retain(|f| !f.origin.starts_with("local:"));
    default_logs::analyze(report, ctx)?;
    let web=Regex::new(r"(?i)(?:\.\./|/etc/passwd|/proc/self|union\s+(?:all\s+)?select|<script|\$\{|;\s*(?:curl|wget|bash)|/\.env(?:\?|$)|/\.git/)").unwrap();
    let command=Regex::new(r"(?i)(?:-(?:enc|encodedcommand)\b|frombase64string|(?:curl|wget)\b.*\|\s*(?:sh|bash)|/dev/tcp/)").unwrap();
    let processes: BTreeMap<_, _> = report
        .records
        .iter()
        .filter_map(|r| {
            if let RecordData::Process(p) = &r.data {
                Some(((r.source_id.as_str(), p.pid), (r, p)))
            } else {
                None
            }
        })
        .collect();
    let mut failures: BTreeMap<LoginKey, Vec<&Record>> = BTreeMap::new();
    let mut successes: BTreeMap<LoginKey, Vec<&Record>> = BTreeMap::new();
    for (i, r) in report.records.iter().enumerate() {
        ctx.tick(Stage::Rules, None, i, Some(report.records.len()))?;
        if r.status != ParseStatus::Parsed {
            continue;
        }
        match &r.data {
            RecordData::Log(l) => {
                let action = l.fields.get("action").map(String::as_str);
                let user = l.fields.get("user").cloned().unwrap_or_default();
                let ip = l.fields.get("client_ip").cloned().unwrap_or_default();
                let host = l.fields.get("host").cloned().unwrap_or_default();
                if action == Some("login_failure") || default_logs::authentication_event(l, "4625")
                {
                    failures
                        .entry((r.source_id.clone(), host.clone(), ip.clone(), user.clone()))
                        .or_default()
                        .push(r);
                }
                if action == Some("login_success") || default_logs::authentication_event(l, "4624")
                {
                    successes
                        .entry((r.source_id.clone(), host, ip.clone(), user.clone()))
                        .or_default()
                        .push(r);
                }
            }
            RecordData::Process(p) => {
                let cmd = p.command.join(" ");
                if command.is_match(&cmd) {
                    report.findings.push(finding(
                        "process-command",
                        Severity::High,
                        "进程命令包含高风险特征",
                        format!(
                            "PID {} ({}) 命令包含编码执行或下载后执行等特征。",
                            p.pid, p.name
                        ),
                        vec![r.id.clone()],
                        0.75,
                    ));
                }
                if let Some(path) = &p.path {
                    let low = path.replace('\\', "/").to_lowercase();
                    if low.starts_with("/tmp/")
                        || low.starts_with("/var/tmp/")
                        || low.starts_with("/dev/shm/")
                        || low.contains("/appdata/local/temp/")
                    {
                        report.findings.push(finding(
                            "process-temp-path",
                            Severity::Medium,
                            "进程从临时目录运行",
                            format!("PID {} 可执行路径：{path}", p.pid),
                            vec![r.id.clone()],
                            0.6,
                        ));
                    }
                }
                if let Some((parent, pp)) = p
                    .parent_pid
                    .and_then(|pid| processes.get(&(r.source_id.as_str(), pid)))
                {
                    let parent_name = pp.name.to_lowercase();
                    let name = p.name.to_lowercase();
                    if ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
                        .contains(&parent_name.as_str())
                        && [
                            "powershell.exe",
                            "pwsh.exe",
                            "cmd.exe",
                            "wscript.exe",
                            "cscript.exe",
                        ]
                        .contains(&name.as_str())
                    {
                        report.findings.push(finding(
                            "office-shell",
                            Severity::High,
                            "Office 进程启动脚本解释器",
                            format!("{} ({}) → {} ({})", pp.name, pp.pid, p.name, p.pid),
                            vec![parent.id.clone(), r.id.clone()],
                            0.8,
                        ));
                    }
                }
            }
            RecordData::Packet(p) => {
                if let Some(uri) = p.application.get("uri")
                    && web.is_match(&decoded(uri))
                {
                    report.findings.push(finding(
                        "network-web-probe",
                        Severity::Medium,
                        "流量包含可疑 HTTP 请求",
                        format!("捕获请求 URI：{uri}"),
                        vec![r.id.clone()],
                        0.7,
                    ));
                }
            }
        }
    }
    for ((source, host, ip, user), mut records) in failures {
        ctx.check()?;
        if ip.is_empty() || ip == "-" {
            continue;
        }
        records.sort_by_key(|r| {
            r.timestamp
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.timestamp())
        });
        let timed: Vec<_> = records
            .iter()
            .filter_map(|r| {
                r.timestamp
                    .as_deref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| (*r, t.timestamp()))
            })
            .collect();
        let mut suspicious = vec![];
        let mut left = 0;
        for right in 0..timed.len() {
            ctx.check()?;
            while timed[right].1 - timed[left].1 > 300 {
                left += 1;
            }
            if right + 1 - left >= 5 {
                suspicious = timed[left..=right]
                    .iter()
                    .map(|(r, _)| r.id.clone())
                    .collect();
                break;
            }
        }
        let desc = if !suspicious.is_empty() {
            Some(format!(
                "{ip} 对账号 {user} 在 5 分钟内有至少 5 次失败登录。"
            ))
        } else if records.len() >= 10 && timed.len() < records.len() {
            suspicious = records.iter().map(|r| r.id.clone()).collect();
            Some(format!(
                "{ip} 对账号 {user} 共 {} 次失败登录；没有足够时间字段证明连续攻击。",
                records.len()
            ))
        } else {
            None
        };
        if let Some(desc) = desc {
            report.findings.push(finding(
                "login-failures",
                Severity::High,
                "重复失败登录",
                desc,
                suspicious,
                0.8,
            ));
        }
        for success in successes
            .get(&(source, host, ip.clone(), user.clone()))
            .into_iter()
            .flatten()
        {
            ctx.check()?;
            let Some(t) = success
                .timestamp
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.timestamp())
            else {
                continue;
            };
            let right = timed.partition_point(|(_, ft)| *ft <= t);
            let left = timed.partition_point(|(_, ft)| *ft < t.saturating_sub(600));
            if right - left >= 5 {
                let mut ids: Vec<_> = timed[left..right]
                    .iter()
                    .map(|(r, _)| r.id.clone())
                    .collect();
                ids.push(success.id.clone());
                report.findings.push(finding(
                    "success-after-failures",
                    Severity::High,
                    "多次失败后登录成功",
                    format!("{ip} 对账号 {user} 的多次失败后出现成功登录；需核对是否账号失陷。"),
                    ids,
                    0.85,
                ));
                break;
            }
        }
    }
    report.flows = crate::network::flows_with_context(&report.records, ctx)?;
    report
        .findings
        .sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    ctx.emit(
        Stage::Rules,
        None,
        report.records.len(),
        Some(report.records.len()),
    );
    ctx.check()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyword_and_bruteforce_window() {
        let s = crate::ingest::source_for("auth", "text", b"fixture");
        let mut r = AnalysisReport::default();
        for i in 0..6 {
            r.records.push(crate::ingest::make_record(
                &s,
                format!("line:{i}"),
                Some(format!("2026-09-30T10:00:0{i}+00:00")),
                "FAILED password".into(),
                ParseStatus::Parsed,
                RecordData::Log(LogData {
                    category: "auth".into(),
                    fields: BTreeMap::from([
                        ("action".into(), "login_failure".into()),
                        ("user".into(), "demo".into()),
                        ("client_ip".into(), "192.0.2.1".into()),
                    ]),
                }),
            ));
        }
        analyze(&mut r);
        assert!(
            r.findings
                .iter()
                .any(|f| f.origin == "local:login-failures")
        );
        assert_eq!(query(&r.records, "failed", false).unwrap().len(), 6);
        assert!(query(&r.records, "[", true).is_err());
        assert!(decoded("/%252e%252e/etc/passwd").contains("../"));
    }
    #[test]
    fn spaced_failures_do_not_imply_a_burst() {
        let mut r = crate::ingest::ingest_bytes(
            "auth.log",
            include_bytes!("../../../tests/fixtures/auth.log"),
            &crate::IngestOptions::default(),
        )
        .unwrap();
        r.records.retain(|record|matches!(&record.data,RecordData::Log(l) if l.fields.get("action").map(String::as_str)==Some("login_failure")));
        let base = r.records[0].clone();
        r.records = (0..12)
            .map(|i| {
                let mut r = base.clone();
                r.id = format!("test:{i}");
                r.timestamp = Some(format!("2026-09-30T{:02}:00:00Z", i));
                r
            })
            .collect();
        analyze(&mut r);
        assert!(
            !r.findings
                .iter()
                .any(|f| f.origin == "local:login-failures")
        );
    }
}
