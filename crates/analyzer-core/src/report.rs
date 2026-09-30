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

pub fn terminal(report: &AnalysisReport, limit: usize, tree: bool) -> String {
    terminal_with_raw(report, limit, tree, false)
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
    let mut out = format!(
        "Easy Analyzer · {}\nSources: {} | Records: {} | Findings: {} | Flows: {} | Diagnostics: {}\n",
        report.generated_at,
        report.sources.len(),
        report.records.len(),
        report.findings.len(),
        report.flows.len(),
        report.diagnostics.len()
    );
    for (index, s) in report.sources.iter().enumerate() {
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
    out.push_str("\nFindings / 分析发现\n");
    let _ = writeln!(out, "  {}（分析发现项数）", risk_summary(&findings));
    if findings.is_empty() {
        out.push_str("  当前范围未命中规则。\n");
    }
    let mut record_findings: std::collections::HashMap<&str, Vec<&Finding>> =
        std::collections::HashMap::new();
    let mut omitted_evidence = false;
    for f in &findings {
        for id in &f.evidence_ids {
            record_findings.entry(id).or_default().push(f);
        }
        let ids: Vec<_> = f
            .evidence_ids
            .iter()
            .filter(|id| matches.as_ref().is_none_or(|m| m.contains(id.as_str())))
            .collect();
        let shown = if !raw {
            if limit == 0 {
                ids.len().min(3)
            } else {
                limit.min(ids.len()).min(3)
            }
        } else if limit == 0 {
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
                .map(|id| if raw {
                    id.to_string()
                } else {
                    records_by_id
                        .get(id.as_str())
                        .map_or_else(|| "未知证据".into(), |r| location(r))
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
        if shown < ids.len() {
            omitted_evidence = true;
            let _ = write!(out, "（另有 {} 条）", ids.len() - shown);
        }
        out.push('\n');
    }
    if tree {
        out.push_str("\nProcess tree / 进程树\n");
        out.push_str(&process_tree(&report.records));
    }
    out.push_str(if raw {
        "\n重要记录摘要及原始内容\n"
    } else {
        "\n重要记录摘要（-R 可查看原始内容）\n"
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
    if matches.is_some() {
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
    if let Some(ids) = &report.query_matches {
        let _ = writeln!(out, "Query matches: {}", ids.len());
    }
    for d in report
        .diagnostics
        .iter()
        .take(if limit == 0 { usize::MAX } else { limit })
    {
        let _ = writeln!(
            out,
            "{:?} {} {}: {}",
            d.level,
            d.source,
            d.position.as_deref().unwrap_or(""),
            d.message
        );
    }
    if limit != 0 && report.diagnostics.len() > limit {
        let _ = writeln!(
            out,
            "其余 {} 条诊断已省略。",
            report.diagnostics.len() - limit
        );
    }
    if omitted_evidence || selected.len() > n || (limit != 0 && report.diagnostics.len() > limit) {
        out.push_str("\n完整查看：-n 0 显示全部摘要；-R -n 0 显示全部引用及原始记录。JSON/HTML 保留完整证据。\n");
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
pub fn html(report: &AnalysisReport) -> String {
    let mut out = String::from(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'"><title>Easy Analyzer 应急响应报告</title><style>
body{font:15px/1.65 system-ui,sans-serif;color:#203046;background:#edf2f6;margin:0}main{max-width:1280px;margin:auto;padding:32px}h1{font-size:30px}h2{margin-top:32px}section,article{background:white;border:1px solid #dce4ec;border-radius:12px;padding:20px;margin:14px 0}table{width:100%;border-collapse:collapse;text-align:left}td,th{padding:10px;border-bottom:1px solid #e2e8f0;vertical-align:top;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 ui-monospace,monospace;background:#f4f7fa;padding:12px}a{color:#17649b}small{color:#607188}.high,.critical{border-left:5px solid #c74848}.medium{border-left:5px solid #d79928}.low,.info{border-left:5px solid #3187b3}details{margin:10px 0}summary{cursor:pointer}code{overflow-wrap:anywhere}@media print{body{background:white}main{padding:0}article,section{break-inside:avoid}}
</style></head><body><main><h1>Easy Analyzer · 应急响应报告</h1>"#,
    );
    let _ = write!(
        out,
        "<p>{} · Schema {}</p><section><strong>{} 个来源 / {} 条记录 / {} 项发现 / {} 个会话 / {} 条诊断</strong><p>分析结果用于线索核查；原始证据及对应来源哈希可在下方查看。</p></section>",
        escape(&report.generated_at),
        report.schema_version,
        report.sources.len(),
        report.records.len(),
        report.findings.len(),
        report.flows.len(),
        report.diagnostics.len()
    );
    out.push_str("<h2>证据来源</h2><section><table><tr><th>来源</th><th>格式 / 大小</th><th>SHA256 / 采集时间</th></tr>");
    for s in &report.sources {
        let _ = write!(
            out,
            "<tr><td>{}</td><td>{} / {}</td><td><code>{}</code><br>{}</td></tr>",
            escape(&s.path),
            escape(&s.format),
            s.bytes,
            escape(&s.sha256),
            escape(&s.collected_at)
        );
    }
    out.push_str("</table></section>");
    out.push_str("<h2>分析发现</h2>");
    let findings = ordered_findings(report, false);
    let _ = write!(
        out,
        "<section>{}（分析发现项数）</section>",
        risk_summary(&findings)
    );
    if report.findings.is_empty() {
        out.push_str("<section>未产生分析发现。未发现规则匹配不能证明主机安全。</section>");
    }
    for f in findings {
        let sev = serde_json::to_value(&f.severity)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let _ = write!(
            out,
            "<article class=\"{}\"><h3>[{}] {}</h3><small>{} · 置信度 {:.2}</small><p>{}</p><p>证据：",
            sev,
            f.severity.label(),
            escape(&f.title),
            escape(&f.origin),
            f.confidence,
            escape(&f.description)
        );
        for id in &f.evidence_ids {
            let _ = write!(out, "<a href=\"#{}\">{}</a> ", escape(id), escape(id));
        }
        out.push_str("</p><ul>");
        for recommendation in &f.recommendations {
            let _ = write!(out, "<li>{}</li>", escape(recommendation));
        }
        out.push_str("</ul></article>");
    }
    if !report.ai_runs.is_empty() {
        out.push_str("<h2>AI 分析范围</h2><section>");
        for run in &report.ai_runs {
            let _ = write!(
                out,
                "<p>{} · {} · {} 批次 / {} 条记录 · 包含载荷：{}</p>",
                escape(&run.model),
                escape(&run.endpoint),
                run.batches,
                run.analyzed_records,
                run.include_payload
            );
        }
        out.push_str("</section>");
    }
    let tree = process_tree(&report.records);
    if !tree.is_empty() {
        out.push_str("<h2>进程关系</h2><section>");
        out.push_str(&pre(&tree));
        out.push_str("</section>");
    }
    if !report.flows.is_empty() {
        out.push_str("<h2>网络会话</h2><section><table><tr><th>端点</th><th>协议</th><th>包 / 字节</th><th>时间</th></tr>");
        for f in &report.flows {
            let _ = write!(
                out,
                "<tr><td>{}<br>{}</td><td>{}</td><td>{} / {}</td><td>{}<br>{}</td></tr>",
                escape(&f.endpoint_a),
                escape(&f.endpoint_b),
                escape(&f.protocol),
                f.packets,
                f.bytes,
                escape(f.first_seen.as_deref().unwrap_or("未知")),
                escape(f.last_seen.as_deref().unwrap_or("未知"))
            );
        }
        out.push_str("</table></section>");
    }
    if let Some(ids) = &report.query_matches {
        let _ = write!(out, "<h2>查询匹配：{} 条</h2><section>", ids.len());
        for id in ids {
            let _ = write!(out, "<p><a href=\"#{}\">{}</a></p>", escape(id), escape(id));
        }
        out.push_str("</section>");
    }
    if !report.diagnostics.is_empty() {
        out.push_str("<h2>解析与采集诊断</h2><section><ul>");
        for d in &report.diagnostics {
            let _ = write!(
                out,
                "<li>{} {}：{}</li>",
                escape(&d.source),
                escape(d.position.as_deref().unwrap_or("")),
                escape(&d.message)
            );
        }
        out.push_str("</ul></section>");
    }
    out.push_str("<h2>全部证据记录</h2><section>");
    for r in &report.records {
        let _ = write!(
            out,
            "<details id=\"{}\"><summary>{} · {} · {:?}</summary><p>来源 ID：{} · {}</p>",
            escape(&r.id),
            escape(&r.position),
            escape(r.timestamp.as_deref().unwrap_or("时间未知")),
            r.status,
            escape(&r.source_id),
            escape(&r.id)
        );
        out.push_str(&pre(
            &serde_json::to_string_pretty(&r.data).unwrap_or_default()
        ));
        out.push_str("<strong>原始记录（文本 / JSON / 十六进制）</strong>");
        out.push_str(&pre(&r.raw));
        out.push_str("</details>");
    }
    out.push_str("</section></main></body></html>");
    out
}
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
