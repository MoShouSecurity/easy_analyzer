//! Offline indicator parsing and boundary-aware matching. No storage or frontend dependency.
use crate::{Record, RecordData, execution::ExecutionContext, model::hex};
use anyhow::{Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::LazyLock,
};
use url::{Host, Url};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ip,
    Domain,
    Url,
}
impl IocType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Url => "url",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub id: String,
    pub kind: IocType,
    pub value: String,
    pub note: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocIssue {
    pub line: usize,
    pub message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocImport {
    pub indicators: Vec<Indicator>,
    pub issues: Vec<IocIssue>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorMatch {
    pub indicator_id: String,
    pub field: String,
    pub matched_value: String,
    pub byte_offset: Option<usize>,
}

fn domain(value: &str) -> Result<String> {
    let value = value.trim_end_matches('.');
    let Host::Domain(host) = Host::parse(value)? else {
        bail!("不是有效域名");
    };
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.starts_with('-')
                || s.ends_with('-')
                || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        bail!("不是有效域名");
    }
    Ok(host.to_ascii_lowercase())
}
fn normalized_url(value: &str) -> Result<String> {
    let mut url = Url::parse(value)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("URL 必须是完整的 HTTP/HTTPS 地址，且不包含账号密码");
    }
    if let Some(host) = url
        .host_str()
        .filter(|_| matches!(url.host(), Some(Host::Domain(_))))
    {
        let host = domain(host)?;
        url.set_host(Some(&host))?;
    }
    url.set_fragment(None);
    Ok(url.to_string())
}
pub fn indicator(value: &str, kind: Option<IocType>, note: &str) -> Result<Indicator> {
    let value = value.trim();
    if value.is_empty() {
        bail!("IOC 不能为空");
    }
    let kind = kind.unwrap_or_else(|| {
        if value.parse::<IpAddr>().is_ok() {
            IocType::Ip
        } else if value.to_ascii_lowercase().starts_with("http://")
            || value.to_ascii_lowercase().starts_with("https://")
        {
            IocType::Url
        } else {
            IocType::Domain
        }
    });
    let value = match kind {
        IocType::Ip => value.parse::<IpAddr>()?.to_string(),
        IocType::Domain => domain(value)?,
        IocType::Url => normalized_url(value)?,
    };
    let id = hex(&Sha256::digest(
        format!("{}\0{value}", kind.label()).as_bytes(),
    ));
    Ok(Indicator {
        id,
        kind,
        value,
        note: note.trim().into(),
    })
}
pub fn import_text(text: &str, csv: bool, ctx: &ExecutionContext) -> Result<IocImport> {
    let mut out = IocImport::default();
    if csv {
        let mut reader = csv::ReaderBuilder::new()
            .trim(csv::Trim::All)
            .from_reader(text.trim_start_matches('\u{feff}').as_bytes());
        let headers = reader.headers()?.clone();
        let column = |name: &str| headers.iter().position(|h| h.eq_ignore_ascii_case(name));
        let (Some(t), Some(v)) = (column("type"), column("value")) else {
            bail!("CSV 必须包含 type,value 列");
        };
        let note = column("note");
        for (i, row) in reader.records().enumerate() {
            ctx.check()?;
            let line = match &row {
                Ok(record) => record.position(),
                Err(error) => error.position(),
            }
            .map_or(i + 2, |p| p.line() as usize);
            let parsed = row.map_err(anyhow::Error::from).and_then(|row| {
                let kind = match row.get(t).unwrap_or_default().to_ascii_lowercase().as_str() {
                    "ip" => IocType::Ip,
                    "domain" => IocType::Domain,
                    "url" => IocType::Url,
                    _ => bail!("type 必须为 ip、domain 或 url"),
                };
                indicator(
                    row.get(v).unwrap_or_default(),
                    Some(kind),
                    note.and_then(|n| row.get(n)).unwrap_or_default(),
                )
            });
            match parsed {
                Ok(item) => out.indicators.push(item),
                Err(e) => out.issues.push(IocIssue {
                    line,
                    message: e.to_string(),
                }),
            }
        }
    } else {
        for (i, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
            ctx.check()?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match indicator(line, None, "") {
                Ok(item) => out.indicators.push(item),
                Err(e) => out.issues.push(IocIssue {
                    line: i + 1,
                    message: e.to_string(),
                }),
            }
        }
    }
    let mut unique = HashMap::<String, usize>::new();
    let mut indicators: Vec<Indicator> = Vec::new();
    for item in out.indicators {
        if let Some(&index) = unique.get(&item.id) {
            if indicators[index].note.is_empty() {
                indicators[index].note = item.note;
            }
        } else {
            unique.insert(item.id.clone(), indicators.len());
            indicators.push(item);
        }
    }
    out.indicators = indicators;
    Ok(out)
}

static URLS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)https?://[^\s<>\"'`]+"#).unwrap());
static HOSTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\p{L}0-9_.-]+").unwrap());
static IPV6: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-fA-F0-9:]*:[a-fA-F0-9:]+").unwrap());
pub struct IocMatcher {
    values: HashMap<(String, String), String>,
    subdomains: bool,
}
impl IocMatcher {
    pub fn new(items: &[Indicator], subdomains: bool) -> Self {
        Self {
            values: items
                .iter()
                .map(|i| ((i.kind.label().into(), i.value.clone()), i.id.clone()))
                .collect(),
            subdomains,
        }
    }
    fn candidate(
        &self,
        value: &str,
        field: &str,
        offset: Option<usize>,
        out: &mut Vec<IndicatorMatch>,
    ) {
        let mut candidates = vec![];
        if let Ok(ip) = value
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            candidates.push(("ip", ip.to_string()));
        }
        if let Ok(url) = normalized_url(value) {
            candidates.push(("url", url.clone()));
            if let Ok(u) = Url::parse(&url)
                && let Some(host) = u.host_str()
            {
                self.candidate(host, field, offset, out);
            }
        }
        if let Ok(mut host) = domain(value) {
            loop {
                candidates.push(("domain", host.clone()));
                if !self.subdomains {
                    break;
                }
                let Some((_, rest)) = host.split_once('.') else {
                    break;
                };
                host = rest.into();
            }
        }
        for (kind, normalized) in candidates {
            if let Some(id) = self.values.get(&(kind.into(), normalized)) {
                out.push(IndicatorMatch {
                    indicator_id: id.clone(),
                    field: field.into(),
                    matched_value: value.into(),
                    byte_offset: offset,
                });
            }
        }
    }
    fn text(
        &self,
        text: &str,
        field: &str,
        out: &mut Vec<IndicatorMatch>,
        ctx: &ExecutionContext,
    ) -> Result<()> {
        self.candidate(text.trim(), field, None, out);
        for m in URLS.find_iter(text) {
            ctx.check()?;
            self.candidate(m.as_str(), field, Some(m.start()), out);
        }
        for m in HOSTS.find_iter(text) {
            ctx.check()?;
            self.candidate(m.as_str(), field, Some(m.start()), out);
        }
        for m in IPV6.find_iter(text) {
            ctx.check()?;
            let boundary = |c: char| c.is_alphanumeric() || matches!(c, '.' | ':' | '_' | '-');
            if text[..m.start()].chars().next_back().is_some_and(boundary)
                || text[m.end()..].chars().next().is_some_and(boundary)
            {
                continue;
            }
            self.candidate(m.as_str(), field, Some(m.start()), out);
        }
        Ok(())
    }
    pub fn record(&self, record: &Record, ctx: &ExecutionContext) -> Result<Vec<IndicatorMatch>> {
        ctx.check()?;
        let mut out = vec![];
        match &record.data {
            RecordData::Log(log) => {
                for (name, value) in &log.fields {
                    ctx.check()?;
                    self.text(value, &format!("log.{name}"), &mut out, ctx)?;
                }
                if !matches!(log.category.as_str(), "utmp" | "wtmp" | "btmp") {
                    self.text(&record.raw, "raw", &mut out, ctx)?;
                }
                if let (Some(scheme), Some(host), Some(uri)) = (
                    log.fields.get("scheme"),
                    log.fields.get("host").or_else(|| log.fields.get("server")),
                    log.fields.get("uri"),
                ) {
                    self.text(&format!("{scheme}://{host}{uri}"), "log.url", &mut out, ctx)?;
                }
            }
            RecordData::Process(p) => {
                self.text(&p.name, "process.name", &mut out, ctx)?;
                if let Some(path) = &p.path {
                    self.text(path, "process.path", &mut out, ctx)?;
                }
                for (i, value) in p.command.iter().enumerate() {
                    ctx.check()?;
                    self.text(value, &format!("process.command[{i}]"), &mut out, ctx)?;
                }
                for (name, value) in [
                    ("user", &p.user),
                    ("start_time", &p.start_time),
                    ("status", &p.status),
                ] {
                    if let Some(value) = value {
                        self.text(value, &format!("process.{name}"), &mut out, ctx)?;
                    }
                }
            }
            RecordData::Packet(p) => {
                for (name, value) in [("source", &p.source), ("destination", &p.destination)] {
                    if let Some(value) = value {
                        self.candidate(value, name, None, &mut out);
                    }
                }
                for (name, value) in &p.application {
                    self.text(value, &format!("packet.{name}"), &mut out, ctx)?;
                }
                if p.application.get("protocol").is_some_and(|p| p == "HTTP")
                    && let (Some(host), Some(uri)) =
                        (p.application.get("host"), p.application.get("uri"))
                    && uri.starts_with('/')
                {
                    self.text(&format!("http://{host}{uri}"), "packet.url", &mut out, ctx)?;
                }
            }
        }
        let mut seen = HashSet::new();
        out.retain(|m| {
            seen.insert((
                m.indicator_id.clone(),
                m.field.clone(),
                m.matched_value.clone(),
            ))
        });
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ingest::{make_record, source_for},
        model::{LogData, ParseStatus},
    };
    use std::collections::BTreeMap;
    fn record(raw: &str) -> Record {
        make_record(
            &source_for("host-a.log", "text", raw.as_bytes()),
            "line:1".into(),
            None,
            raw.into(),
            ParseStatus::Parsed,
            RecordData::Log(LogData {
                category: "text".into(),
                fields: BTreeMap::new(),
            }),
        )
    }
    #[test]
    fn csv_continues_after_invalid_and_preserves_escaped_notes() {
        let result=import_text("type,value,note\ndomain,Example.COM,\"first, \"\"quoted\"\"\"\nip,not-ip,bad\nurl,HTTPS://Example.com:443/a?q=1#ignored,web\nip,2001:0db8::1,v6\ndomain,example.com,duplicate\n",true,&ExecutionContext::default()).unwrap();
        assert_eq!(result.indicators.len(), 3);
        assert_eq!(result.issues[0].line, 3);
        assert_eq!(result.indicators[0].note, "first, \"quoted\"");
        assert_eq!(result.indicators[1].value, "https://example.com/a?q=1");
        assert_eq!(result.indicators[2].value, "2001:db8::1");
        let multiline = import_text(
            "type,value,note\ndomain,example.com,\"first\nsecond\"\nip,invalid,\n",
            true,
            &ExecutionContext::default(),
        )
        .unwrap();
        assert_eq!(multiline.issues[0].line, 4);
    }
    #[test]
    fn boundaries_subdomains_ipv6_and_exact_urls() {
        let indicators=import_text("example.com\n192.0.2.1\n2001:db8::1\nhttps://example.com/a?q=1\nhttps://example.com/a?q=1;\n",false,&ExecutionContext::default()).unwrap().indicators;
        let matcher = IocMatcher::new(&indicators, true);
        let ctx = ExecutionContext::default();
        for raw in [
            "notexample.com",
            "example.com.evil",
            "x192.0.2.1",
            "192.0.2.10",
            "evil2001:db8::1evil",
        ] {
            assert!(
                matcher.record(&record(raw), &ctx).unwrap().is_empty(),
                "{raw}"
            );
        }
        assert_eq!(
            matcher
                .record(&record("a.example.com"), &ctx)
                .unwrap()
                .len(),
            1
        );
        assert!(
            IocMatcher::new(&indicators, false)
                .record(&record("a.example.com"), &ctx)
                .unwrap()
                .is_empty()
        );
        assert!(
            !matcher
                .record(&record("[2001:db8::1]"), &ctx)
                .unwrap()
                .is_empty()
        );
        let hits = matcher
            .record(&record("HTTPS://EXAMPLE.COM:443/a?q=1#fragment"), &ctx)
            .unwrap();
        assert!(hits.iter().any(|h| h.indicator_id == indicators[3].id));
        for raw in [
            "https://example.com/a?q=2",
            "http://example.com/a?q=1",
            "https://example.com/b?q=1",
            "https://example.com/a?q=1;",
        ] {
            let hits = matcher.record(&record(raw), &ctx).unwrap();
            assert!(
                !hits.iter().any(|h| h.indicator_id == indicators[3].id),
                "{raw}"
            );
        }
    }
    #[test]
    fn does_not_scan_binary_hex_and_rejects_unsupported_values() {
        let matcher = IocMatcher::new(
            &[indicator("deadbeef", Some(IocType::Domain), "").unwrap()],
            true,
        );
        let mut r = record("deadbeef");
        if let RecordData::Log(log) = &mut r.data {
            log.category = "wtmp".into();
        }
        assert!(
            matcher
                .record(&r, &ExecutionContext::default())
                .unwrap()
                .is_empty()
        );
        for value in [
            "10.0.0.0/8",
            "*.example.com",
            "https://user:pass@example.com/",
            "ftp://example.com/",
        ] {
            assert!(indicator(value, None, "").is_err(), "{value}");
        }
    }
}
