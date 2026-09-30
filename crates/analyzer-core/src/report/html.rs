use super::{brief, escape, ordered_findings, pre, record_summary};
use crate::{collect::process_tree, model::*};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt::Write};

const STYLE: &str = include_str!("style.css");
const SCRIPT: &str = include_str!("navigation.js");

struct Context<'a> {
    records: HashMap<&'a str, (usize, &'a Record)>,
    sources: HashMap<&'a str, (usize, &'a Source)>,
}

fn severity_class(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}
fn badge(severity: &Severity) -> String {
    format!(
        "<span class=\"badge {}\">{}</span>",
        severity_class(severity),
        severity.label()
    )
}
fn filename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}
fn evidence_link(out: &mut String, id: &str, context: &Context<'_>) {
    if let Some((index, record)) = context.records.get(id) {
        let source = context
            .sources
            .get(record.source_id.as_str())
            .map_or_else(|| "未知来源".into(), |(n, _)| format!("S{}", n + 1));
        let _ = write!(
            out,
            "<a href=\"#evidence-{index}\">{} · {}</a>",
            source,
            escape(&record.position)
        );
    } else {
        let _ = write!(
            out,
            "<span class=\"muted\">未找到记录：{}</span>",
            escape(id)
        );
    }
}
fn links(out: &mut String, ids: &[String], context: &Context<'_>) {
    out.push_str("<div class=\"evidence-links\">");
    for id in ids.iter().take(3) {
        evidence_link(out, id, context);
    }
    out.push_str("</div>");
    if ids.len() > 3 {
        let _ = write!(
            out,
            "<details class=\"subfold\"><summary>展开全部 {} 条证据引用</summary><div class=\"scroll refs evidence-links\">",
            ids.len()
        );
        for id in ids {
            evidence_link(out, id, context);
        }
        out.push_str("</div></details>");
    }
}
fn findings(out: &mut String, items: &[(usize, &Finding)], context: &Context<'_>) {
    if items.is_empty() {
        out.push_str("<div class=\"panel empty\">当前范围未产生可用发现。</div>");
        return;
    }
    for level in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let group: Vec<_> = items.iter().filter(|(_, f)| f.severity == level).collect();
        if group.is_empty() {
            continue;
        }
        let _ = write!(
            out,
            "<details class=\"severity-group\"{}><summary>{}<span>{}项发现</span><span class=\"muted\">展开查看</span></summary><div class=\"group-body\">",
            if level.rank() >= 3 { " open" } else { "" },
            badge(&level),
            group.len()
        );
        for (index, finding) in group {
            let _ = write!(
                out,
                "<details class=\"finding\" id=\"finding-{index}\"><summary><span class=\"finding-title\">{}<small>{} · 置信度 {:.0}%</small></span><span class=\"count\">{} 条证据</span></summary><div class=\"finding-body\"><div class=\"reader\"><p>{}</p></div>",
                escape(&finding.title),
                if finding.origin.starts_with("ai:") {
                    "AI 发现"
                } else {
                    "本地规则"
                },
                finding.confidence * 100.0,
                finding.evidence_ids.len(),
                escape(&finding.description)
            );
            if !finding.recommendations.is_empty() {
                out.push_str("<h4>建议动作</h4><ul class=\"actions reader\">");
                for recommendation in &finding.recommendations {
                    let _ = write!(out, "<li>{}</li>", escape(recommendation));
                }
                out.push_str("</ul>");
            }
            out.push_str("<h4>关联证据</h4>");
            links(out, &finding.evidence_ids, context);
            let _ = write!(
                out,
                "<small>规则 / 模型：<code>{}</code> · 发现编号：<code>{}</code></small></div></details>",
                escape(&finding.origin),
                escape(&finding.id)
            );
        }
        out.push_str("</div></details>");
    }
}
fn section(out: &mut String, id: &str, title: &str, subtitle: &str, count: usize) {
    let _ = write!(
        out,
        "<div class=\"section-head\" id=\"{id}\"><div><h2>{title}</h2><p>{subtitle}</p></div><span>{count} 项</span></div>"
    );
}
fn script_hash() -> String {
    let digest = Sha256::digest(SCRIPT.as_bytes());
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in digest.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        result.push(alphabet[(n >> 18) as usize] as char);
        result.push(alphabet[((n >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 {
            alphabet[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            alphabet[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    result
}

pub fn render(report: &AnalysisReport) -> String {
    let context = Context {
        records: report
            .records
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.as_str(), (i, r)))
            .collect(),
        sources: report
            .sources
            .iter()
            .enumerate()
            .map(|(i, s)| (s.id.as_str(), (i, s)))
            .collect(),
    };
    let ordered = ordered_findings(report, false);
    let indexed: Vec<_> = ordered.iter().enumerate().map(|(i, f)| (i, *f)).collect();
    let (ai, local): (Vec<_>, Vec<_>) = indexed
        .iter()
        .copied()
        .partition(|(_, f)| f.origin.starts_with("ai:"));
    let has_ai = !report.ai_runs.is_empty()
        || !ai.is_empty()
        || report.diagnostics.iter().any(|d| d.source == "AI");
    let mut counts = [0; 5];
    for finding in &ordered {
        counts[finding.severity.rank() as usize] += 1;
    }
    let errors = report
        .diagnostics
        .iter()
        .filter(|d| d.level == DiagnosticLevel::Error)
        .count();
    let incomplete = report.ai_runs.iter().any(|run| !run.is_complete());
    let mut out = format!(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{}'; img-src 'none'; base-uri 'none'; form-action 'none'\"><title>Easy Analyzer · 应急响应报告</title><style>{STYLE}</style></head><body><main>",
        script_hash()
    );
    let _ = write!(
        out,
        "<header class=\"hero\"><div><div class=\"eyebrow\">EASY ANALYZER / INCIDENT REVIEW</div><h1>应急响应分析报告</h1><p>风险优先，证据可追溯。展开条目查看说明和取证详情。</p></div><div class=\"meta\"><strong>{}</strong>{}<br>离线报告 · 本地规则 {} 项 / AI {} 项</div></header>",
        if errors > 0 || incomplete {
            "分析部分完成"
        } else {
            "分析已完成"
        },
        escape(&report.generated_at),
        local.len(),
        ai.len()
    );
    out.push_str("<nav class=\"nav\" aria-label=\"报告导航\"><a href=\"#overview\">概览</a><a href=\"#local\">本地发现</a>");
    if has_ai {
        out.push_str("<a href=\"#ai\">AI 分析</a>");
    }
    out.push_str("<a href=\"#sources\">来源</a><a href=\"#evidence\">证据</a><a href=\"#diagnostics\">诊断</a></nav><div id=\"overview\" class=\"stats\">");
    for (value, label, class) in [
        (report.records.len(), "证据记录", ""),
        (ordered.len(), "分析发现", ""),
        (counts[4] + counts[3], "严重 / 高危发现", "hot"),
        (report.sources.len(), "证据来源", ""),
    ] {
        let _ = write!(
            out,
            "<div class=\"stat {class}\"><strong>{value}</strong><span>{label}</span></div>"
        );
    }
    out.push_str("</div>");
    if errors > 0 || incomplete {
        let _ = write!(
            out,
            "<aside class=\"alert\"><strong>部分分析未完成</strong> · {} 条错误。已完成的结果保留在本报告中，未完成范围不能视为已排除风险。<a href=\"#diagnostics\">查看具体原因 →</a></aside>",
            errors
        );
    }
    out.push_str(
        "<div class=\"split\"><section class=\"panel\"><h3>优先关注</h3><div class=\"risk-strip\">",
    );
    for level in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let _ = write!(
            out,
            "<span class=\"badge {}\">{} {}</span>",
            severity_class(&level),
            level.label(),
            counts[level.rank() as usize]
        );
    }
    out.push_str("</div>");
    for (index, finding) in indexed.iter().take(5) {
        let _ = write!(
            out,
            "<div class=\"focus-item\">{}<a href=\"#finding-{index}\">{}</a><small>{} 条证据 · {}</small></div>",
            badge(&finding.severity),
            escape(&finding.title),
            finding.evidence_ids.len(),
            if finding.origin.starts_with("ai:") {
                "AI"
            } else {
                "本地"
            }
        );
    }
    if indexed.is_empty() {
        out.push_str("<p class=\"empty\">当前范围没有可用发现。</p>");
    }
    if indexed.len() > 5 {
        let _ = write!(
            out,
            "<p class=\"note\">展示风险最高的 5 / {} 项，下方分组保留全部发现。</p>",
            indexed.len()
        );
    }
    out.push_str("</section><aside class=\"panel\"><h3>分析范围</h3><dl class=\"facts\">");
    let _ = write!(
        out,
        "<dt>输入来源</dt><dd>{} 个</dd><dt>离线会话</dt><dd>{} 个</dd><dt>查询范围</dt><dd>{}</dd><dt>诊断信息</dt><dd>{} 错误 / {} 提醒</dd><dt>AI 状态</dt><dd>{}</dd>",
        report.sources.len(),
        report.flows.len(),
        report.query_matches.as_ref().map_or_else(
            || "未应用查询".into(),
            |ids| format!("{} 条匹配", ids.len())
        ),
        errors,
        report.diagnostics.len() - errors,
        if incomplete {
            "部分完成"
        } else if report.ai_runs.is_empty() {
            if has_ai {
                "未产生有效运行"
            } else {
                "未启用"
            }
        } else {
            "已完成"
        }
    );
    out.push_str("</dl><p class=\"note\">发现项数与命中记录数不同，同一记录可能关联多项发现。规则和 AI 结果是核查线索，不等同于已确认入侵。</p></aside></div>");
    let mut actions = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for finding in &ordered {
        for recommendation in &finding.recommendations {
            if !recommendation.trim().is_empty() && seen.insert(recommendation.as_str()) {
                actions.push((recommendation, finding));
            }
            if actions.len() == 5 {
                break;
            }
        }
        if actions.len() == 5 {
            break;
        }
    }
    if !actions.is_empty() {
        out.push_str("<section class=\"panel\"><h3>建议优先执行</h3><ol class=\"actions\">");
        for (recommendation, finding) in actions {
            let _ = write!(
                out,
                "<li>{}<small>依据：{}</small></li>",
                escape(&brief(recommendation)),
                escape(&finding.title)
            );
        }
        out.push_str("</ol><small>完整建议可在各项发现中展开查看。</small></section>");
    }
    section(
        &mut out,
        "local",
        "本地规则分析",
        "按风险分组 · 单项展开查看说明、建议与完整引用",
        local.len(),
    );
    findings(&mut out, &local, &context);
    if has_ai {
        section(
            &mut out,
            "ai",
            "AI 分析",
            "通过结构与证据校验的发现 · 未验证回复单独保存",
            ai.len(),
        );
        out.push_str("<section class=\"panel\">");
        for run in &report.ai_runs {
            let _ = write!(
                out,
                "<div class=\"run\"><strong>{}</strong> · <span class=\"muted\">{}</span><p>完成 {}/{} 批次 · 已验证 {}/{} 条记录 · 原始包及载荷：{}</p><progress max=\"{}\" value=\"{}\" aria-label=\"AI 批次完成进度\"></progress><details class=\"subfold\"><summary>服务信息</summary><p>{}</p></details></div>",
                if run.is_complete() {
                    "分析完成"
                } else {
                    "分析未完成，已保留部分结果"
                },
                escape(&run.model),
                run.completed(),
                run.batches,
                run.analyzed_records,
                run.selected(),
                if run.include_payload {
                    "包含"
                } else {
                    "不包含"
                },
                run.batches.max(1),
                run.completed(),
                escape(&run.endpoint)
            );
        }
        if ai.is_empty() {
            out.push_str("<p class=\"empty\">没有可用 AI 发现。请结合完成范围和诊断判断，不能据此确认全部证据已排除风险。</p>");
        }
        out.push_str("</section>");
        findings(&mut out, &ai, &context);
        for run in &report.ai_runs {
            if run.batch_results.is_empty() {
                continue;
            }
            out.push_str("<section class=\"panel\"><details><summary>AI 各批次原始回复与诊断</summary><p class=\"note\">未通过校验的回复仅供排查，不作为结论。</p><div class=\"scroll\">");
            for batch in &run.batch_results {
                let _ = write!(
                    out,
                    "<details class=\"subfold\"><summary>第 {}/{} 批 · {} · {} 条记录 · 请求 {} 次</summary>",
                    batch.index,
                    run.batches,
                    if batch.error.is_some() {
                        "失败"
                    } else {
                        "已验证"
                    },
                    batch.evidence_ids.len(),
                    batch.attempts.len()
                );
                for (index, attempt) in batch.attempts.iter().enumerate() {
                    let _ = write!(
                        out,
                        "<details class=\"subfold\"><summary>第 {} 次回复 · {}</summary>",
                        index + 1,
                        if attempt.error.is_some() {
                            "未通过校验或请求失败"
                        } else {
                            "已验证"
                        }
                    );
                    if let Some(error) = &attempt.error {
                        let _ = write!(out, "<p class=\"note\">{}</p>", escape(error));
                    }
                    if let Some(response) = &attempt.response {
                        out.push_str(&pre(response));
                    }
                    out.push_str("</details>");
                }
                out.push_str("</details>");
            }
            out.push_str("</div></details></section>");
        }
    }
    section(
        &mut out,
        "sources",
        "证据来源",
        "文件信息、采集时间与完整 SHA256",
        report.sources.len(),
    );
    out.push_str("<section class=\"panel\"><div class=\"table-wrap\"><table class=\"source-table\"><thead><tr><th>来源</th><th>格式 / 大小</th><th>取证元数据</th></tr></thead><tbody>");
    for (i, source) in report.sources.iter().enumerate() {
        let _ = write!(
            out,
            "<tr><td><strong>S{} · {}</strong><small>{}</small></td><td>{}<small>{} 字节</small></td><td><details><summary>时间与哈希</summary><small>{}</small><code>{}</code></details></td></tr>",
            i + 1,
            escape(filename(&source.path)),
            escape(&source.path),
            escape(&source.format),
            source.bytes,
            escape(&source.collected_at),
            escape(&source.sha256)
        );
    }
    out.push_str("</tbody></table></div></section>");
    auxiliary(&mut out, report, &context);
    section(
        &mut out,
        "evidence",
        "全部证据",
        "按来源及每组 100 条分层收纳 · 点击引用自动定位并展开",
        report.records.len(),
    );
    evidence(&mut out, report, &context);
    diagnostics(&mut out, report);
    let _ = write!(
        out,
        "<footer class=\"footer\"><span>Easy Analyzer · Schema {} · 完整证据保留在本文件</span><span>生成于 {}</span></footer></main><script>{SCRIPT}</script></body></html>",
        report.schema_version,
        escape(&report.generated_at)
    );
    out
}

fn auxiliary(out: &mut String, report: &AnalysisReport, context: &Context<'_>) {
    if report
        .records
        .iter()
        .any(|r| matches!(r.data, RecordData::Process(_)))
    {
        out.push_str("<section class=\"panel\"><details><summary>进程父子关系</summary>");
        out.push_str(&pre(&process_tree(&report.records)));
        out.push_str("</details></section>");
    }
    if !report.flows.is_empty() {
        let _ = write!(
            out,
            "<section class=\"panel\"><details><summary>离线网络会话 · {} 个</summary><div class=\"table-wrap\"><table><thead><tr><th>端点</th><th>协议</th><th>包 / 字节</th><th>时间</th></tr></thead><tbody>",
            report.flows.len()
        );
        for flow in &report.flows {
            let _ = write!(
                out,
                "<tr><td>{}<br>{}</td><td>{}</td><td>{} / {}</td><td>{}<br>{}</td></tr>",
                escape(&flow.endpoint_a),
                escape(&flow.endpoint_b),
                escape(&flow.protocol),
                flow.packets,
                flow.bytes,
                escape(flow.first_seen.as_deref().unwrap_or("未知")),
                escape(flow.last_seen.as_deref().unwrap_or("未知"))
            );
        }
        out.push_str("</tbody></table></div></details></section>");
    }
    if let Some(ids) = &report.query_matches {
        let _ = write!(
            out,
            "<section class=\"panel\"><details><summary>查询匹配 · {} 条</summary><div class=\"scroll evidence-links\">",
            ids.len()
        );
        for id in ids {
            evidence_link(out, id, context);
        }
        out.push_str("</div></details></section>");
    }
}
fn evidence(out: &mut String, report: &AnalysisReport, context: &Context<'_>) {
    let mut groups: std::collections::BTreeMap<&str, Vec<(usize, &Record)>> =
        std::collections::BTreeMap::new();
    for (i, record) in report.records.iter().enumerate() {
        groups
            .entry(&record.source_id)
            .or_default()
            .push((i, record));
    }
    let mut ordered_groups = Vec::new();
    for source in &report.sources {
        if let Some(records) = groups.remove(source.id.as_str()) {
            ordered_groups.push((source.id.as_str(), records));
        }
    }
    ordered_groups.extend(groups);
    out.push_str("<section class=\"panel\">");
    if report.records.is_empty() {
        out.push_str("<p class=\"empty\">没有证据记录。</p>");
    }
    for (source_id, records) in ordered_groups {
        let label = context.sources.get(source_id).map_or_else(
            || "未知来源".into(),
            |(i, source)| format!("S{} · {}", i + 1, filename(&source.path)),
        );
        let _ = write!(
            out,
            "<details class=\"subfold\"><summary>{} · {} 条记录</summary><div class=\"scroll\">",
            escape(&label),
            records.len()
        );
        for (page, chunk) in records.chunks(100).enumerate() {
            let _ = write!(
                out,
                "<details class=\"subfold\"><summary>记录 {}–{}</summary>",
                page * 100 + 1,
                page * 100 + chunk.len()
            );
            for (index, record) in chunk {
                let status = match record.status {
                    ParseStatus::Parsed => "已解析",
                    ParseStatus::Unrecognized => "未识别",
                    ParseStatus::Malformed => "畸形记录",
                };
                let _ = write!(
                    out,
                    "<details class=\"record\" id=\"evidence-{index}\"><summary><span class=\"record-title\">{}<small class=\"muted\"> · {} · {}</small><br>{}</span></summary><div class=\"record-body\"><p><code>{}</code></p><h4>解析字段</h4>",
                    escape(&record.position),
                    escape(record.timestamp.as_deref().unwrap_or("时间未知")),
                    status,
                    escape(&brief(&record_summary(record))),
                    escape(&record.id)
                );
                out.push_str(&pre(
                    &serde_json::to_string_pretty(&record.data).unwrap_or_default()
                ));
                out.push_str("<details class=\"subfold\"><summary>原始记录（文本 / JSON / 十六进制）</summary>");
                out.push_str(&pre(&record.raw));
                out.push_str("</details></div></details>");
            }
            out.push_str("</details>");
        }
        out.push_str("</div></details>");
    }
    out.push_str("</section>");
}
fn diagnostics(out: &mut String, report: &AnalysisReport) {
    section(
        out,
        "diagnostics",
        "分析诊断",
        "错误优先 · 相同提示按来源与内容合并计数",
        report.diagnostics.len(),
    );
    out.push_str("<section class=\"panel\">");
    if report.diagnostics.is_empty() {
        out.push_str("<p class=\"empty\">无解析、采集或 AI 错误。</p>");
    }
    for level in [DiagnosticLevel::Error, DiagnosticLevel::Warning] {
        let mut groups: std::collections::BTreeMap<(&str, &str), Vec<&Diagnostic>> =
            std::collections::BTreeMap::new();
        for diagnostic in report.diagnostics.iter().filter(|d| d.level == level) {
            groups
                .entry((&diagnostic.source, &diagnostic.message))
                .or_default()
                .push(diagnostic);
        }
        if groups.is_empty() {
            continue;
        }
        let _ = write!(
            out,
            "<details{}><summary>{} · {} 类</summary><div class=\"scroll\">",
            if level == DiagnosticLevel::Error {
                " open"
            } else {
                ""
            },
            if level == DiagnosticLevel::Error {
                "错误"
            } else {
                "提醒"
            },
            groups.len()
        );
        for ((source, message), items) in groups {
            let _ = write!(
                out,
                "<details class=\"subfold {}\"><summary><span class=\"finding-title\">{}<small>{} · {} 次</small></span></summary><div class=\"reader\"><p>{}</p></div><details class=\"subfold\"><summary>全部位置</summary><ul class=\"row-list scroll refs\">",
                if level == DiagnosticLevel::Error {
                    "diagnostic-error"
                } else {
                    "diagnostic-warning"
                },
                escape(&brief(message)),
                escape(source),
                items.len(),
                escape(message)
            );
            for item in items {
                let _ = write!(
                    out,
                    "<li>{}</li>",
                    escape(item.position.as_deref().unwrap_or("未指定位置"))
                );
            }
            out.push_str("</ul></details></details>");
        }
        out.push_str("</div></details>");
    }
    out.push_str("</section>");
}
