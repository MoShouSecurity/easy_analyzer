use crate::{collect::process_tree, model::*};
use std::fmt::Write;

pub fn terminal(report: &AnalysisReport, limit: usize, tree: bool) -> String {
    let mut out = format!(
        "Easy Analyzer · {}\nSources: {} | Records: {} | Findings: {} | Flows: {} | Diagnostics: {}\n",
        report.generated_at,
        report.sources.len(),
        report.records.len(),
        report.findings.len(),
        report.flows.len(),
        report.diagnostics.len()
    );
    for s in &report.sources {
        let _ = writeln!(
            out,
            "  [{}] {} ({} bytes, SHA256 {})",
            s.format, s.path, s.bytes, s.sha256
        );
    }
    out.push_str("\nFindings / 分析发现\n");
    for f in &report.findings {
        let _ = writeln!(
            out,
            "  [{:?}] {} ({}, confidence {:.2})\n    {}\n    Evidence: {}",
            f.severity,
            f.title,
            f.origin,
            f.confidence,
            f.description,
            f.evidence_ids.join(", ")
        );
    }
    if tree {
        out.push_str("\nProcess tree / 进程树\n");
        out.push_str(&process_tree(&report.records));
    }
    out.push_str("\nRecords / 记录\n");
    let matches = report.query_matches.as_ref().map(|ids| {
        ids.iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>()
    });
    let selected: Vec<_> = report
        .records
        .iter()
        .filter(|r| {
            matches
                .as_ref()
                .is_none_or(|ids| ids.contains(r.id.as_str()))
        })
        .collect();
    let n = if limit == 0 {
        selected.len()
    } else {
        limit.min(selected.len())
    };
    for r in selected.iter().take(n) {
        let _ = writeln!(
            out,
            "  {} [{:?}] {}\n    {}",
            r.id,
            r.status,
            r.timestamp.as_deref().unwrap_or("time unavailable"),
            match &r.data {
                RecordData::Log(l) => format!(
                    "{} {}",
                    l.category,
                    if l.fields.is_empty() {
                        r.raw.clone()
                    } else {
                        serde_json::to_string(&l.fields).unwrap_or_default()
                    }
                ),
                RecordData::Process(p) => format!(
                    "PID {} {} parent={:?} path={:?}",
                    p.pid, p.name, p.parent_pid, p.path
                ),
                RecordData::Packet(p) => format!(
                    "{} {:?}:{:?} → {:?}:{:?} {} bytes {:?}",
                    p.protocol,
                    p.source,
                    p.source_port,
                    p.destination,
                    p.destination_port,
                    p.original_bytes,
                    p.application
                ),
            }
        );
    }
    if selected.len() > n {
        let _ = writeln!(
            out,
            "  Displayed {n}/{} records; use --limit 0 or JSON/HTML for the full dataset.",
            selected.len()
        );
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
            "Additional {} diagnostics in JSON/HTML.",
            report.diagnostics.len() - limit
        );
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
    if report.findings.is_empty() {
        out.push_str("<section>未产生分析发现。未发现规则匹配不能证明主机安全。</section>");
    }
    for f in &report.findings {
        let sev = serde_json::to_value(&f.severity)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let _ = write!(
            out,
            "<article class=\"{}\"><h3>[{}] {}</h3><small>{} · 置信度 {:.2}</small><p>{}</p><p>证据：",
            sev,
            sev,
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
