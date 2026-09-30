use crate::{collect::process_tree, model::*};
use std::fmt::Write;

fn ordered_findings(report: &AnalysisReport, apply_query: bool) -> Vec<&Finding> {
    let matches = report.query_matches.as_ref().map(|ids| {
        ids.iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>()
    });
    let mut findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            !apply_query
                || matches
                    .as_ref()
                    .is_none_or(|ids| f.evidence_ids.iter().any(|id| ids.contains(id.as_str())))
        })
        .collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    findings
}
fn risk_summary(findings: &[&Finding]) -> String {
    let mut counts = [0; 5];
    for f in findings {
        counts[f.severity.rank() as usize] += 1;
    }
    format!(
        "严重 {} | 高危 {} | 中危 {} | 低危 {} | 信息 {}",
        counts[4], counts[3], counts[2], counts[1], counts[0]
    )
}
fn compact_risk_summary(findings: &[&Finding]) -> String {
    let mut counts = [0; 5];
    for finding in findings {
        counts[finding.severity.rank() as usize] += 1;
    }
    [
        (4, "严重"),
        (3, "高危"),
        (2, "中危"),
        (1, "低危"),
        (0, "信息"),
    ]
    .into_iter()
    .filter(|(rank, _)| counts[*rank] != 0)
    .map(|(rank, label)| format!("{label} {}", counts[rank]))
    .collect::<Vec<_>>()
    .join("  ·  ")
}

pub fn terminal(report: &AnalysisReport, limit: usize, tree: bool) -> String {
    terminal_with_raw(report, limit, tree, false)
}

/// Add a compact overview while retaining the existing complete evidence schema.
pub fn json(report: &AnalysisReport) -> anyhow::Result<String> {
    let findings = ordered_findings(report, false);
    let mut counts = [0; 5];
    let mut evidence_ids = std::collections::HashSet::new();
    let mut ai_count = 0;
    for finding in &findings {
        counts[finding.severity.rank() as usize] += 1;
        evidence_ids.extend(finding.evidence_ids.iter());
        ai_count += usize::from(finding.origin.starts_with("ai:"));
    }
    let errors = report
        .diagnostics
        .iter()
        .filter(|d| d.level == DiagnosticLevel::Error)
        .count();
    let summary = serde_json::json!({
        "sources": report.sources.len(), "records": report.records.len(),
        "findings": findings.len(), "local_findings": findings.len() - ai_count, "ai_findings": ai_count,
        "findings_by_severity": {"critical":counts[4],"high":counts[3],"medium":counts[2],"low":counts[1],"info":counts[0]},
        "risk_summary": risk_summary(&findings),
        "unique_referenced_records": evidence_ids.len(), "flows": report.flows.len(),
        "diagnostics": {"errors":errors,"warnings":report.diagnostics.len()-errors},
        "query_matches":report.query_matches.as_ref().map(Vec::len),
        "priority_findings":findings.iter().take(5).map(|f| serde_json::json!({"id":f.id,"severity":f.severity,"title":f.title,"origin":f.origin,"evidence_count":f.evidence_ids.len(),"confidence":f.confidence})).collect::<Vec<_>>(),
        "ai_coverage":report.ai_runs.iter().map(|r|serde_json::json!({"model":r.model,"complete":r.is_complete(),"completed_batches":r.completed(),"total_batches":r.batches,"analyzed_records":r.analyzed_records,"selected_records":r.selected()})).collect::<Vec<_>>()
    });
    #[derive(serde::Serialize)]
    struct JsonReport<'a> {
        summary: serde_json::Value,
        #[serde(flatten)]
        report: &'a AnalysisReport,
    }
    Ok(serde_json::to_string_pretty(&JsonReport {
        summary,
        report,
    })?)
}

fn brief(text: &str) -> String {
    let mut result = String::new();
    let mut count = 0;
    let mut gap = false;
    for c in text.chars() {
        if c.is_whitespace() {
            gap = !result.is_empty();
            continue;
        }
        if count == 120 {
            result.push('…');
            break;
        }
        if gap {
            result.push(' ');
            count += 1;
            gap = false;
            if count == 120 {
                result.push('…');
                break;
            }
        }
        result.push(c);
        count += 1;
    }
    result
}
fn log_field<'a>(log: &'a LogData, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        log.fields
            .get(*name)
            .map(String::as_str)
            .or_else(|| {
                let suffix = format!(".{name}");
                let text_suffix = format!(".{name}.#text");
                log.fields.iter().find_map(|(key, value)| {
                    (key.ends_with(&suffix) || key.ends_with(&text_suffix))
                        .then_some(value.as_str())
                })
            })
            .filter(|value| !value.is_empty() && *value != "-")
    })
}
fn record_summary(record: &Record) -> String {
    match &record.data {
        RecordData::Log(log) => {
            let fields: &[(&str, &[&str])] = if log.category == "windows_event" {
                &[
                    ("事件", &["event_id", "EventID"]),
                    ("主机", &["host", "Computer"]),
                    ("账号", &["user", "TargetUserName"]),
                    ("域", &["TargetDomainName"]),
                    ("来源 IP", &["client_ip", "IpAddress", "ClientAddress"]),
                    ("登录类型", &["LogonType"]),
                    ("操作者", &["SubjectUserName"]),
                    (
                        "进程",
                        &["ProcessName", "NewProcessName", "CallerProcessName"],
                    ),
                    ("服务", &["ServiceName"]),
                    ("服务路径", &["ServiceFileName", "ImagePath"]),
                    ("任务", &["TaskName"]),
                    ("共享", &["ShareName"]),
                    ("目标文件", &["RelativeTargetName"]),
                    ("目标组/SID", &["TargetSid"]),
                    ("状态", &["Status", "FailureReason"]),
                    ("子状态", &["SubStatus"]),
                    ("命令摘要", &["CommandLine", "ScriptBlockText"]),
                ]
            } else if log.category == "web_access" || log.category == "web_error" {
                &[
                    ("来源 IP", &["client_ip"]),
                    ("方法", &["method"]),
                    ("路径", &["uri"]),
                    ("响应", &["status"]),
                    ("账号", &["user"]),
                    ("字节数", &["bytes"]),
                    ("客户端", &["user_agent"]),
                    ("级别", &["level"]),
                    ("错误摘要", &["message"]),
                ]
            } else {
                &[
                    ("行为", &["action"]),
                    ("账号", &["user"]),
                    ("来源", &["client_ip", "host"]),
                    ("终端", &["terminal"]),
                    ("PID", &["pid"]),
                ]
            };
            let values: Vec<_> = fields
                .iter()
                .filter_map(|(label, names)| {
                    log_field(log, names).map(|value| format!("{label}={}", brief(value)))
                })
                .collect();
            if values.is_empty() {
                "未提取到关键字段；使用 -R 查看原始内容。".into()
            } else {
                values.join(" · ")
            }
        }
        RecordData::Process(p) => {
            let mut summary = format!(
                "PID={} · 名称={} · 父 PID={}",
                p.pid,
                brief(&p.name),
                p.parent_pid
                    .map_or_else(|| "未知".into(), |v| v.to_string())
            );
            if let Some(path) = &p.path {
                let _ = write!(summary, " · 路径={}", brief(path));
            }
            if let Some(user) = &p.user {
                let _ = write!(summary, " · 用户={}", brief(user));
            }
            if !p.command.is_empty() {
                let _ = write!(summary, " · 命令={}", brief(&p.command.join(" ")));
            }
            summary
        }
        RecordData::Packet(p) => {
            let mut summary = format!(
                "{} · {}:{} → {}:{} · {} 字节",
                brief(&p.protocol),
                p.source.as_deref().unwrap_or("未知"),
                p.source_port.map_or_else(|| "-".into(), |v| v.to_string()),
                p.destination.as_deref().unwrap_or("未知"),
                p.destination_port
                    .map_or_else(|| "-".into(), |v| v.to_string()),
                p.original_bytes
            );
            for name in ["method", "uri", "host", "query", "protocol"] {
                if let Some(value) = p.application.get(name) {
                    let _ = write!(summary, " · {name}={}", brief(value));
                }
            }
            summary
        }
    }
}

pub fn terminal_with_raw(report: &AnalysisReport, limit: usize, tree: bool, raw: bool) -> String {
    let mut out = String::from("Easy Analyzer · 应急分析\n");
    if raw {
        let _ = writeln!(out, "生成时间：{}", report.generated_at);
    }
    let _ = write!(
        out,
        "来源 {}  ·  记录 {}",
        report.sources.len(),
        report.records.len()
    );
    if let Some(ids) = &report.query_matches {
        let _ = write!(out, "  ·  查询命中 {}", ids.len());
    }
    if !report.flows.is_empty() {
        let _ = write!(out, "  ·  网络会话 {}", report.flows.len());
    }
    if !report.diagnostics.is_empty() {
        let _ = write!(out, "  ·  诊断 {}", report.diagnostics.len());
    }
    out.push('\n');
    for run in &report.ai_runs {
        let _ = writeln!(
            out,
            "AI {} · {} · 已完成 {}/{} 批次 · 已验证 {}/{} 条记录",
            if run.is_complete() {
                "分析完成"
            } else {
                "分析未完成"
            },
            run.model,
            run.completed(),
            run.batches,
            run.analyzed_records,
            run.selected()
        );
    }
    for (index, s) in
        report
            .sources
            .iter()
            .enumerate()
            .take(if limit == 0 { usize::MAX } else { limit })
    {
        let _ = write!(
            out,
            "  来源 {} [{}] {} ({} bytes",
            index + 1,
            s.format,
            s.path,
            s.bytes
        );
        if raw {
            let _ = write!(out, ", SHA256 {}", s.sha256);
        }
        out.push_str(")\n");
    }
    if limit != 0 && report.sources.len() > limit {
        let _ = writeln!(
            out,
            "  其余 {} 个来源见 HTML/JSON 或 -n 0。",
            report.sources.len() - limit
        );
    }
    let source_numbers: std::collections::HashMap<_, _> = report
        .sources
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), i + 1))
        .collect();
    let records_by_id: std::collections::HashMap<_, _> =
        report.records.iter().map(|r| (r.id.as_str(), r)).collect();
    let location = |record: &Record| {
        format!(
            "来源 {}/{}",
            source_numbers
                .get(record.source_id.as_str())
                .map_or_else(|| "?".into(), |i| i.to_string()),
            record.position
        )
    };
    let matches = report.query_matches.as_ref().map(|ids| {
        ids.iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>()
    });
    let findings = ordered_findings(report, true);
    let _ = writeln!(out, "\n分析发现 · {} 项", findings.len());
    if !findings.is_empty() {
        let _ = writeln!(out, "{}", compact_risk_summary(&findings));
    }
    if findings.is_empty() {
        out.push_str("  当前范围未命中规则。\n");
    }
    let mut record_findings: std::collections::HashMap<&str, Vec<&Finding>> =
        std::collections::HashMap::new();
    let mut omitted_evidence = false;
    let mut previous_severity = None;
    let count_width = findings
        .iter()
        .map(|f| f.evidence_ids.len().to_string().len())
        .max()
        .unwrap_or(1);
    for f in &findings {
        for id in &f.evidence_ids {
            record_findings.entry(id).or_default().push(f);
        }
    }
    let shown_findings = if limit == 0 {
        findings.len()
    } else {
        limit.min(findings.len())
    };
    for f in findings.iter().take(shown_findings) {
        let ids: Vec<_> = f
            .evidence_ids
            .iter()
            .filter(|id| matches.as_ref().is_none_or(|m| m.contains(id.as_str())))
            .collect();
        if !raw {
            if previous_severity != Some(f.severity.rank()) {
                let _ = writeln!(out, "\n{}", f.severity.label());
                previous_severity = Some(f.severity.rank());
            }
            let _ = write!(
                out,
                "  {:>width$} 条  {}",
                ids.len(),
                brief(&f.title),
                width = count_width
            );
            if report.sources.len() > 1
                && let Some(record) = ids.first().and_then(|id| records_by_id.get(id.as_str()))
                && let Some(source) = report.sources.iter().find(|s| s.id == record.source_id)
            {
                let _ = write!(
                    out,
                    "  ·  {}",
                    brief(
                        source
                            .path
                            .rsplit(['/', '\\'])
                            .next()
                            .unwrap_or(&source.path)
                    )
                );
            }
            out.push('\n');
            // These findings need their actor/command context to remain actionable.
            if matches!(
                f.origin.as_str(),
                "local:login-failures"
                    | "local:success-after-failures"
                    | "local:process-command"
                    | "local:process-temp-path"
                    | "local:office-shell"
                    | "local:network-web-probe"
            ) || !f.origin.starts_with("local:")
            {
                let _ = writeln!(out, "        {}", brief(&f.description));
                if let Some(recommendation) = f.recommendations.first() {
                    let _ = writeln!(out, "        建议：{}", brief(recommendation));
                }
            }
            continue;
        }
        let shown = if limit == 0 {
            ids.len()
        } else {
            limit.min(ids.len())
        };
        let _ = write!(
            out,
            "  [{}] {} ({}, 置信度 {:.2})\n    {}\n    证据（当前范围 {} 条）：{}",
            f.severity.label(),
            f.title,
            f.origin,
            f.confidence,
            f.description,
            ids.len(),
            ids.iter()
                .take(shown)
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if shown < ids.len() {
            omitted_evidence = true;
            let _ = write!(out, "（另有 {} 条）", ids.len() - shown);
        }
        out.push('\n');
        for recommendation in
            f.recommendations
                .iter()
                .take(if limit == 0 { usize::MAX } else { limit })
        {
            let _ = writeln!(out, "    建议：{recommendation}");
        }
    }
    if shown_findings < findings.len() {
        let _ = writeln!(
            out,
            "\n  已显示 {shown_findings}/{} 项发现（风险优先），完整内容见 HTML/JSON 或 -n 0。",
            findings.len()
        );
    }
    if tree {
        out.push_str("\n进程树\n");
        let process_tree = process_tree(&report.records);
        let lines = process_tree.lines().count();
        for line in process_tree
            .lines()
            .take(if limit == 0 { usize::MAX } else { limit })
        {
            let _ = writeln!(out, "{line}");
        }
        if limit != 0 && lines > limit {
            let _ = writeln!(
                out,
                "  其余 {} 行进程关系见 HTML/JSON 或 -n 0。",
                lines - limit
            );
        }
    }
    out.push_str(if raw {
        "\n记录详情\n"
    } else {
        "\n记录摘要\n"
    });
    let mut selected: Vec<_> = report
        .records
        .iter()
        .filter(|r| {
            matches
                .as_ref()
                .is_none_or(|ids| ids.contains(r.id.as_str()))
        })
        .collect();
    if !record_findings.is_empty() {
        selected.sort_by_key(|r| {
            std::cmp::Reverse(
                record_findings
                    .get(r.id.as_str())
                    .map_or(0, |f| f[0].severity.rank()),
            )
        });
    }
    let n = if limit == 0 {
        selected.len()
    } else {
        limit.min(selected.len())
    };
    for r in selected.iter().take(n) {
        if raw {
            if let Some(found) = record_findings.get(r.id.as_str()) {
                let _ = writeln!(
                    out,
                    "  风险：{} · 规则：{}",
                    found[0].severity.label(),
                    found
                        .iter()
                        .map(|f| f.origin.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let _ = writeln!(
                out,
                "  {} [{}] {}\n    {}",
                location(r),
                match r.status {
                    ParseStatus::Parsed => "已解析",
                    ParseStatus::Unrecognized => "未识别",
                    ParseStatus::Malformed => "畸形记录",
                },
                r.timestamp.as_deref().unwrap_or("时间未知"),
                record_summary(r)
            );
            let _ = writeln!(out, "    证据 ID：{}\n    原始内容：\n{}", r.id, r.raw);
        } else {
            out.push_str("  ");
            if let Some(found) = record_findings.get(r.id.as_str()) {
                let _ = write!(out, "[{}] ", found[0].severity.label());
            }
            match r.status {
                ParseStatus::Parsed => {}
                ParseStatus::Unrecognized => out.push_str("[未识别] "),
                ParseStatus::Malformed => out.push_str("[畸形记录] "),
            }
            let _ = writeln!(out, "{}", record_summary(r));
        }
    }
    if selected.len() > n {
        let _ = writeln!(out, "  已显示 {n}/{} 条记录。", selected.len());
    }
    let mut diagnostics: std::collections::BTreeMap<(u8, &str, &str), (usize, &Diagnostic)> =
        std::collections::BTreeMap::new();
    for diagnostic in &report.diagnostics {
        let key = (
            u8::from(diagnostic.level != DiagnosticLevel::Error),
            diagnostic.source.as_str(),
            diagnostic.message.as_str(),
        );
        let group = diagnostics.entry(key).or_insert((0, diagnostic));
        group.0 += 1;
    }
    if !diagnostics.is_empty() {
        out.push_str("\n诊断（相同提示合并，错误优先）\n");
    }
    for (count, d) in diagnostics
        .values()
        .take(if limit == 0 { usize::MAX } else { limit })
    {
        let _ = writeln!(
            out,
            "  [{}] {} {}: {}（{} 次）",
            if d.level == DiagnosticLevel::Error {
                "错误"
            } else {
                "提醒"
            },
            d.source,
            d.position.as_deref().unwrap_or(""),
            if raw {
                d.message.clone()
            } else {
                brief(&d.message)
            },
            count
        );
    }
    if limit != 0 && diagnostics.len() > limit {
        let _ = writeln!(
            out,
            "其余 {} 类诊断已省略；完整内容见 HTML/JSON。",
            diagnostics.len() - limit
        );
    }
    if !raw && (!findings.is_empty() || !selected.is_empty()) {
        out.push_str("\n查看详情 -R  ·  全部摘要 -n 0  ·  导出报告 -j 路径 / -H 路径\n");
    } else if omitted_evidence
        || selected.len() > n
        || (limit != 0 && report.diagnostics.len() > limit)
    {
        out.push_str("\n全部记录与引用 -n 0  ·  导出报告 -j 路径 / -H 路径\n");
    }
    out.chars()
        .flat_map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn pre(s: &str) -> String {
    format!("<pre>{}</pre>", escape(s))
}
mod html;
pub use html::render as html;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_and_ai_text_cannot_inject_html() {
        let mut r = AnalysisReport::default();
        r.warn("<script>bad</script>", None, "<img src=x>");
        let page = html(&r);
        assert!(!page.contains("<script>bad"));
        assert!(page.contains("&lt;script&gt;bad"));
        assert!(page.contains("Content-Security-Policy"));
    }
}
