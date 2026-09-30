//! Compile Apache LogFormat / Nginx log_format definitions into anchored parsers.
use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::BTreeMap;

pub struct WebParser {
    regex: Regex,
    names: Vec<String>,
    json_escape: bool,
}

impl WebParser {
    pub fn common() -> Self {
        Self::compile(r#"%h %l %u %t \"%r\" %>s %b"#).expect("constant format")
    }
    pub fn combined() -> Self {
        Self::compile(r#"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""#)
            .expect("constant format")
    }
    pub fn compile(definition: &str) -> Result<Self> {
        let format = extract_format(definition)?;
        let chars: Vec<char> = format.chars().collect();
        let mut regex = String::from("^");
        let mut names = vec![];
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '%' {
                i += 1;
                if i >= chars.len() {
                    bail!("dangling % in Apache format");
                }
                if chars[i] == '%' {
                    regex.push('%');
                    i += 1;
                    continue;
                }
                if chars[i] == '>' || chars[i] == '<' {
                    i += 1;
                }
                let mut header = None;
                if chars.get(i) == Some(&'{') {
                    let start = i + 1;
                    i += 1;
                    while i < chars.len() && chars[i] != '}' {
                        i += 1;
                    }
                    if i == chars.len() {
                        bail!("unterminated Apache field");
                    }
                    header = Some(chars[start..i].iter().collect::<String>());
                    i += 1;
                }
                let token = *chars.get(i).context("missing Apache field type")?;
                i += 1;
                let name = match (token, header.as_deref()) {
                    ('h' | 'a', _) => "client_ip".into(),
                    ('l', _) => "ident".into(),
                    ('u', _) => "user".into(),
                    ('t', _) => "time".into(),
                    ('r', _) => "request".into(),
                    ('s', _) => "status".into(),
                    ('b' | 'B', _) => "bytes".into(),
                    ('m', _) => "method".into(),
                    ('U', _) => "uri".into(),
                    ('q', _) => "query".into(),
                    ('D' | 'T', _) => "duration".into(),
                    ('v' | 'V', _) => "server".into(),
                    ('p', _) => "port".into(),
                    ('H', _) => "protocol".into(),
                    ('i', Some(h)) if h.eq_ignore_ascii_case("user-agent") => "user_agent".into(),
                    ('i', Some(h)) if h.eq_ignore_ascii_case("referer") => "referer".into(),
                    ('i' | 'o' | 'C' | 'e', Some(h)) => format!("{token}:{h}"),
                    _ => {
                        bail!("unsupported Apache directive %{token}; supply a supported LogFormat")
                    }
                };
                names.push(name);
                if token == 't' && header.is_none() {
                    regex.push_str(r"\[([^\]]*)\]");
                } else {
                    regex.push_str("(.*?)");
                }
            } else if chars[i] == '$' {
                i += 1;
                let braced = chars.get(i) == Some(&'{');
                if braced {
                    i += 1;
                }
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                if i == start {
                    bail!("missing Nginx variable name");
                }
                let token: String = chars[start..i].iter().collect();
                if braced {
                    if chars.get(i) != Some(&'}') {
                        bail!("unterminated Nginx variable");
                    }
                    i += 1;
                }
                let name = match token.as_str() {
                    "remote_addr" => "client_ip",
                    "remote_user" => "user",
                    "time_local" | "time_iso8601" => "time",
                    "request" => "request",
                    "status" => "status",
                    "body_bytes_sent" | "bytes_sent" => "bytes",
                    "http_referer" => "referer",
                    "http_user_agent" => "user_agent",
                    "request_method" => "method",
                    "request_uri" | "uri" => "uri",
                    "args" => "query",
                    "request_time" => "duration",
                    _ => &token,
                };
                names.push(name.to_string());
                regex.push_str("(.*?)");
            } else {
                regex.push_str(&regex::escape(&chars[i].to_string()));
                i += 1;
            }
        }
        if names.is_empty() {
            bail!("format must contain Apache directives or Nginx variables");
        }
        regex.push('$');
        Ok(Self {
            regex: Regex::new(&regex)?,
            names,
            json_escape: definition.trim().starts_with("log_format ")
                && definition.contains("escape=json"),
        })
    }
    pub fn parse(&self, line: &str) -> Option<BTreeMap<String, String>> {
        let caps = self.regex.captures(line)?;
        let mut fields = BTreeMap::new();
        for (i, name) in self.names.iter().enumerate() {
            let value = caps[i + 1].to_string();
            let value = if self.json_escape {
                serde_json::from_str::<String>(&format!("\"{value}\"")).ok()?
            } else {
                value
            };
            fields.insert(name.clone(), value);
        }
        if let Some(request) = fields.get("request").cloned() {
            let parts: Vec<_> = request.split_whitespace().collect();
            if parts.len() >= 2 {
                fields.insert("method".into(), parts[0].into());
                fields.insert("uri".into(), parts[1].into());
            }
        }
        Some(fields)
    }
}

fn extract_format(definition: &str) -> Result<String> {
    let s = definition.trim();
    if !s.starts_with("LogFormat ") && !s.starts_with("log_format ") {
        return Ok(s.replace(r#"\""#, "\""));
    }
    let nginx = s.starts_with("log_format ");
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        if c == '\'' || c == '"' {
            quoted = true;
            let quote = c;
            let mut closed = false;
            while let Some(c) = chars.next() {
                if c == quote {
                    closed = true;
                    break;
                }
                if c == '\\' {
                    let next = chars.next().context("trailing escape in format")?;
                    if next == quote || next == '\\' {
                        out.push(next);
                    } else {
                        out.push('\\');
                        out.push(next);
                    }
                } else {
                    out.push(c);
                }
            }
            if !closed {
                bail!("unterminated format string");
            }
            if !nginx {
                break;
            }
        }
    }
    if !quoted {
        bail!("service format definition must contain a quoted format string");
    }
    Ok(out)
}

/// Common Apache and Nginx error logs; timestamps without timezone stay unnormalized.
pub struct WebErrorParser {
    nginx: Regex,
    apache: Regex,
    client: Regex,
    request: Regex,
}
impl Default for WebErrorParser {
    fn default() -> Self {
        Self {
            nginx: Regex::new(
                r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]+)\] (\d+)#\d+: (.*)$",
            )
            .unwrap(),
            apache: Regex::new(r"^\[([^\]]+)\] \[([^\]]+)\](?: \[pid ([^\]]+)\])? (.*)$").unwrap(),
            client: Regex::new(r"(?:client: |\[client )([^,\] ]+)").unwrap(),
            request: Regex::new("request: \"([^\"]*)\"").unwrap(),
        }
    }
}
impl WebErrorParser {
    pub fn parse(&self, line: &str) -> Option<BTreeMap<String, String>> {
        let mut fields = BTreeMap::new();
        if let Some(c) = self.nginx.captures(line) {
            fields.insert("time".into(), c[1].into());
            fields.insert("level".into(), c[2].into());
            fields.insert("pid".into(), c[3].into());
            fields.insert("message".into(), c[4].into());
        } else {
            let c = self.apache.captures(line)?;
            fields.insert("time".into(), c[1].into());
            fields.insert("level".into(), c[2].into());
            fields.insert("message".into(), c[4].into());
            if let Some(pid) = c.get(3) {
                fields.insert("pid".into(), pid.as_str().into());
            }
        }
        if let Some(c) = self.client.captures(line) {
            fields.insert("client_ip".into(), c[1].into());
        }
        if let Some(c) = self.request.captures(line) {
            fields.insert("request".into(), c[1].into());
            let parts: Vec<_> = c[1].split_whitespace().collect();
            if parts.len() >= 2 {
                fields.insert("method".into(), parts[0].into());
                fields.insert("uri".into(), parts[1].into());
            }
        }
        Some(fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_definitions() {
        let p = WebParser::compile(r#"LogFormat "%h %l %u %t \"%r\" %>s %b" common"#).unwrap();
        let f = p
            .parse(r#"192.0.2.1 - - [29/Sep/2026:10:00:00 +0800] "GET /index HTTP/1.1" 200 20"#)
            .unwrap();
        assert_eq!(f["uri"], "/index");
        assert_eq!(f["status"], "200");
        let p = WebParser::compile(
            "log_format custom '$remote_addr [$time_local] '
            '\"$request\" $status $body_bytes_sent';",
        )
        .unwrap();
        assert!(
            p.parse("192.0.2.1 [29/Sep/2026:10:00:00 +0800] \"GET / HTTP/1.1\" 200 4")
                .is_some()
        );
        assert!(p.parse("broken").is_none());
        assert!(WebParser::compile("%{bad").is_err());
    }
    #[test]
    fn error_logs_and_json_escaping() {
        let p = WebErrorParser::default();
        let nginx=p.parse(r#"2026/09/30 10:00:00 [error] 123#123: *1 demo error, client: 192.0.2.10, request: "GET /.env HTTP/1.1""#).unwrap();
        assert_eq!(nginx["uri"], "/.env");
        assert!(
            p.parse("[Wed Sep 30 10:00:00 2026] [core:error] [pid 123] [client 192.0.2.1:42] demo")
                .is_some()
        );
        let p=WebParser::compile(r#"log_format custom escape=json '{"ip":"$remote_addr","agent":"$http_user_agent","status":$status}';"#).unwrap();
        let f = p
            .parse(r#"{"ip":"192.0.2.1","agent":"Demo\"Browser","status":200}"#)
            .unwrap();
        assert_eq!(f["user_agent"], "Demo\"Browser");
        assert_eq!(f["status"], "200");
    }
}
