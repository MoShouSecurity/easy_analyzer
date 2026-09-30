//! Bounded, endian-aware PCAP/PCAPNG and basic IP transport decoding.
use crate::{ingest::make_record, model::*};
use anyhow::{Result, bail};
use chrono::DateTime;
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

pub fn is_capture(b: &[u8]) -> bool {
    b.len() >= 4
        && matches!(
            &b[..4],
            [0xd4, 0xc3, 0xb2, 0xa1]
                | [0xa1, 0xb2, 0xc3, 0xd4]
                | [0x4d, 0x3c, 0xb2, 0xa1]
                | [0xa1, 0xb2, 0x3c, 0x4d]
                | [0x0a, 0x0d, 0x0d, 0x0a]
        )
}
fn u16_at(b: &[u8], p: usize, le: bool) -> u16 {
    let a = [b[p], b[p + 1]];
    if le {
        u16::from_le_bytes(a)
    } else {
        u16::from_be_bytes(a)
    }
}
fn u32_at(b: &[u8], p: usize, le: bool) -> u32 {
    let a = [b[p], b[p + 1], b[p + 2], b[p + 3]];
    if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}
fn time(seconds: i64, nanos: u32) -> Option<String> {
    DateTime::from_timestamp(seconds, nanos).map(|t| t.to_rfc3339())
}

pub fn parse_capture(b: &[u8], s: &Source, max: usize, r: &mut AnalysisReport) -> Result<()> {
    if b.is_empty() {
        r.warn(&s.path, None, "empty capture");
        return Ok(());
    }
    if !is_capture(b) {
        bail!("invalid PCAP/PCAPNG magic");
    }
    if b.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        return parse_ng(b, s, max, r);
    }
    if b.len() < 24 {
        bail!("truncated PCAP global header");
    }
    let le = matches!(&b[..4], [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1]);
    let nano = matches!(&b[..4], [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d]);
    if u16_at(b, 4, le) != 2 || u16_at(b, 6, le) != 4 {
        bail!("unsupported PCAP version");
    }
    let link = u32_at(b, 20, le) & 0xffff;
    let mut p = 24;
    while p < b.len() {
        if r.records.len() >= max {
            bail!("capture exceeds max records ({max})");
        }
        if b.len() - p < 16 {
            malformed(s, p, &b[p..], "truncated PCAP packet header", r);
            break;
        }
        let cap = u32_at(b, p + 8, le) as usize;
        let original = u32_at(b, p + 12, le);
        if cap > b.len() - p - 16 {
            malformed(s, p, &b[p..], "truncated PCAP packet data", r);
            break;
        }
        let fraction = u32_at(b, p + 4, le);
        let stamp = if fraction < if nano { 1_000_000_000 } else { 1_000_000 } {
            time(
                u32_at(b, p, le) as i64,
                if nano { fraction } else { fraction * 1000 },
            )
        } else {
            None
        };
        if stamp.is_none() {
            r.warn(
                &s.path,
                Some(format!("offset:{p}")),
                "invalid capture timestamp",
            );
        }
        packet(s, p, &b[p + 16..p + 16 + cap], link, original, stamp, r);
        p += 16 + cap;
    }
    Ok(())
}
#[derive(Clone)]
struct Interface {
    link: u32,
    resolution: u8,
    snaplen: u32,
    offset: i64,
}
fn parse_ng(b: &[u8], s: &Source, max: usize, r: &mut AnalysisReport) -> Result<()> {
    let mut p = 0;
    let mut le = true;
    let mut interfaces: Vec<Interface> = vec![];
    while p < b.len() {
        if b.len() - p < 12 {
            malformed(s, p, &b[p..], "truncated PCAPNG block", r);
            break;
        }
        if b[p..p + 4] == [0x0a, 0x0d, 0x0d, 0x0a] {
            if b.len() - p < 28 {
                malformed(s, p, &b[p..], "truncated PCAPNG section", r);
                break;
            }
            le = match &b[p + 8..p + 12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => true,
                [0x1a, 0x2b, 0x3c, 0x4d] => false,
                _ => bail!("invalid PCAPNG byte order magic at {p}"),
            };
            interfaces.clear();
        }
        let kind = u32_at(b, p, le);
        let len = u32_at(b, p + 4, le) as usize;
        if len < 12 || !len.is_multiple_of(4) || len > b.len() - p {
            malformed(s, p, &b[p..], "invalid PCAPNG block length", r);
            break;
        }
        if u32_at(b, p + len - 4, le) as usize != len {
            malformed(
                s,
                p,
                &b[p..p + len],
                "PCAPNG repeated block lengths disagree",
                r,
            );
            break;
        }
        let block = &b[p..p + len];
        match kind {
            0x0a0d0d0a => {
                if len < 28 {
                    malformed(s, p, block, "short section header", r);
                    break;
                }
                if u16_at(block, 12, le) != 1 {
                    bail!("unsupported PCAPNG section version");
                }
            }
            1 => {
                if len < 20 {
                    malformed(s, p, block, "short interface block", r);
                } else {
                    let mut iface = Interface {
                        link: u16_at(block, 8, le) as u32,
                        resolution: 6,
                        snaplen: u32_at(block, 12, le),
                        offset: 0,
                    };
                    let mut q = 16;
                    while q + 4 <= len - 4 {
                        let code = u16_at(block, q, le);
                        let n = u16_at(block, q + 2, le) as usize;
                        q += 4;
                        if code == 0 {
                            break;
                        }
                        if n > len - 4 - q {
                            r.warn(
                                &s.path,
                                Some(format!("offset:{p}")),
                                "truncated interface option",
                            );
                            break;
                        }
                        if code == 9 && n == 1 {
                            let v = block[q];
                            iface.resolution = v;
                        }
                        if code == 14 && n == 8 {
                            let a: [u8; 8] = block[q..q + 8].try_into().unwrap();
                            iface.offset = if le {
                                i64::from_le_bytes(a)
                            } else {
                                i64::from_be_bytes(a)
                            };
                        }
                        q += (n + 3) & !3;
                    }
                    interfaces.push(iface);
                }
            }
            6 => {
                if r.records.len() >= max {
                    bail!("capture exceeds max records ({max})");
                }
                if len < 32 {
                    malformed(s, p, block, "short enhanced packet block", r);
                } else {
                    let idx = u32_at(block, 8, le) as usize;
                    let cap = u32_at(block, 20, le) as usize;
                    if ((cap + 3) & !3) > len - 32 {
                        malformed(s, p, block, "truncated enhanced packet", r);
                    } else if let Some(iface) = interfaces.get(idx) {
                        let ticks =
                            ((u32_at(block, 12, le) as u64) << 32) | u32_at(block, 16, le) as u64;
                        let base: u128 = if iface.resolution & 0x80 != 0 { 2 } else { 10 };
                        let stamp = base.checked_pow((iface.resolution & 0x7f) as u32).and_then(
                            |denominator| {
                                let ticks = ticks as u128;
                                let seconds = i64::try_from(ticks / denominator).ok()?;
                                let nanos =
                                    ((ticks % denominator) * 1_000_000_000 / denominator) as u32;
                                time(iface.offset.checked_add(seconds)?, nanos)
                            },
                        );
                        if stamp.is_none() {
                            r.warn(
                                &s.path,
                                Some(format!("offset:{p}")),
                                "unsupported or invalid PCAPNG timestamp resolution",
                            );
                        }
                        packet(
                            s,
                            p,
                            &block[28..28 + cap],
                            iface.link,
                            u32_at(block, 24, le),
                            stamp,
                            r,
                        );
                    } else {
                        malformed(s, p, block, "packet refers to missing interface", r);
                    }
                }
            }
            3 => {
                if r.records.len() >= max {
                    bail!("capture exceeds max records ({max})");
                }
                if len < 16 {
                    malformed(s, p, block, "short simple packet block", r);
                } else if let Some(iface) = interfaces.first() {
                    let original = u32_at(block, 8, le);
                    let cap = if iface.snaplen == 0 {
                        original as usize
                    } else {
                        original.min(iface.snaplen) as usize
                    };
                    if ((cap + 3) & !3) != len - 16 {
                        malformed(
                            s,
                            p,
                            block,
                            "simple packet length disagrees with interface snaplen",
                            r,
                        );
                    } else {
                        packet(s, p, &block[12..12 + cap], iface.link, original, None, r);
                    }
                } else {
                    malformed(s, p, block, "simple packet without interface", r);
                }
            }
            2 => {
                r.warn(
                    &s.path,
                    Some(format!("offset:{p}")),
                    "obsolete PCAPNG packet block is unsupported",
                );
            }
            _ => {}
        }
        p += len;
        if r.records.len() > max {
            bail!("capture exceeds max records ({max})");
        }
    }
    Ok(())
}
fn malformed(s: &Source, p: usize, b: &[u8], message: &str, r: &mut AnalysisReport) {
    r.warn(&s.path, Some(format!("offset:{p}")), message);
    r.records.push(make_record(
        s,
        format!("offset:{p}"),
        None,
        hex(b),
        ParseStatus::Malformed,
        RecordData::Packet(PacketData::default()),
    ));
}
fn packet(
    s: &Source,
    p: usize,
    b: &[u8],
    link: u32,
    original: u32,
    stamp: Option<String>,
    r: &mut AnalysisReport,
) {
    let mut data = PacketData {
        link_type: link,
        captured_bytes: b.len() as u32,
        original_bytes: original,
        ..Default::default()
    };
    let status = match decode(b, &mut data) {
        Ok(()) => ParseStatus::Parsed,
        Err(e) => {
            r.warn(&s.path, Some(format!("offset:{p}")), e.to_string());
            ParseStatus::Unrecognized
        }
    };
    if b.len() as u32 > original {
        r.warn(
            &s.path,
            Some(format!("offset:{p}")),
            "captured length exceeds original length",
        );
    }
    r.records.push(make_record(
        s,
        format!("offset:{p}"),
        stamp,
        hex(b),
        status,
        RecordData::Packet(data),
    ));
}
fn decode(b: &[u8], d: &mut PacketData) -> Result<()> {
    let (mut ip, mut ether) = match d.link_type {
        1 => {
            if b.len() < 14 {
                bail!("short Ethernet header");
            }
            (&b[14..], u16_at(b, 12, false))
        }
        101 => {
            if b.is_empty() {
                bail!("empty raw IP packet");
            }
            (b, if b[0] >> 4 == 6 { 0x86dd } else { 0x0800 })
        }
        113 => {
            if b.len() < 16 {
                bail!("short Linux cooked header");
            }
            (&b[16..], u16_at(b, 14, false))
        }
        276 => {
            if b.len() < 20 {
                bail!("short Linux cooked v2 header");
            }
            (&b[20..], u16_at(b, 0, false))
        }
        228 => (b, 0x0800),
        229 => (b, 0x86dd),
        _ => bail!("unsupported link type {}", d.link_type),
    };
    for _ in 0..2 {
        if ether == 0x8100 || ether == 0x88a8 {
            if ip.len() < 4 {
                bail!("short VLAN tag");
            }
            ether = u16_at(ip, 2, false);
            ip = &ip[4..];
        }
    }
    let transport;
    let proto;
    match ether {
        0x0800 => {
            if ip.len() < 20 || ip[0] >> 4 != 4 {
                bail!("invalid IPv4 header");
            }
            let ihl = ((ip[0] & 15) * 4) as usize;
            let length = u16_at(ip, 2, false) as usize;
            if ihl < 20 || ihl > ip.len() || length < ihl {
                bail!("invalid IPv4 lengths");
            }
            d.source = Some(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]).to_string());
            d.destination = Some(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]).to_string());
            proto = ip[9];
            if u16_at(ip, 6, false) & 0x3fff != 0 {
                d.protocol = format!("IPv4-fragment/{proto}");
                return Ok(());
            }
            transport = &ip[ihl..length.min(ip.len())];
        }
        0x86dd => {
            if ip.len() < 40 || ip[0] >> 4 != 6 {
                bail!("invalid IPv6 header");
            }
            d.source = Some(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24])?).to_string());
            d.destination = Some(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40])?).to_string());
            let end = (40 + u16_at(ip, 4, false) as usize).min(ip.len());
            let mut next = ip[6];
            let mut q = 40;
            for _ in 0..8 {
                if !matches!(next, 0 | 43 | 60 | 51 | 44) {
                    break;
                }
                if next == 44 {
                    d.protocol = "IPv6-fragment".into();
                    return Ok(());
                }
                if q + 2 > end {
                    bail!("truncated IPv6 extension");
                }
                let size = if next == 51 {
                    (ip[q + 1] as usize + 2) * 4
                } else {
                    (ip[q + 1] as usize + 1) * 8
                };
                next = ip[q];
                q += size;
                if q > end {
                    bail!("invalid IPv6 extension length");
                }
            }
            proto = next;
            transport = &ip[q..end];
        }
        0x0806 => {
            d.protocol = "ARP".into();
            return Ok(());
        }
        _ => {
            d.protocol = format!("EtherType:{ether:04x}");
            bail!("unsupported Ethernet protocol {ether:04x}");
        }
    }
    let payload = match proto {
        6 => {
            d.protocol = "TCP".into();
            if transport.len() < 20 {
                bail!("truncated TCP header");
            }
            let h = ((transport[12] >> 4) * 4) as usize;
            if h < 20 || h > transport.len() {
                bail!("invalid TCP header length");
            }
            d.source_port = Some(u16_at(transport, 0, false));
            d.destination_port = Some(u16_at(transport, 2, false));
            d.tcp_flags = Some(transport[13]);
            &transport[h..]
        }
        17 => {
            d.protocol = "UDP".into();
            if transport.len() < 8 {
                bail!("truncated UDP header");
            }
            let n = u16_at(transport, 4, false) as usize;
            if n < 8 {
                bail!("invalid UDP length");
            }
            d.source_port = Some(u16_at(transport, 0, false));
            d.destination_port = Some(u16_at(transport, 2, false));
            &transport[8..n.min(transport.len())]
        }
        1 => {
            d.protocol = "ICMP".into();
            transport
        }
        58 => {
            d.protocol = "ICMPv6".into();
            transport
        }
        n => {
            d.protocol = format!("IP:{n}");
            transport
        }
    };
    d.payload_hex = hex(payload);
    application(payload, d);
    Ok(())
}
fn application(b: &[u8], d: &mut PacketData) {
    if let Ok(text) = std::str::from_utf8(b) {
        let first = text.lines().next().unwrap_or_default();
        let parts: Vec<_> = first.split_whitespace().collect();
        if parts.len() >= 3
            && matches!(
                parts[0],
                "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT"
            )
        {
            d.application.insert("protocol".into(), "HTTP".into());
            d.application.insert("method".into(), parts[0].into());
            d.application.insert("uri".into(), parts[1].into());
            for line in text.lines().skip(1).take_while(|l| !l.is_empty()) {
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("host")
                {
                    d.application.insert("host".into(), value.trim().into());
                }
            }
        } else if parts.len() >= 2 && parts[0].starts_with("HTTP/") {
            d.application.insert("protocol".into(), "HTTP".into());
            d.application.insert("status".into(), parts[1].into());
        }
    }
    if b.len() >= 3 && b[0] == 22 && b[1] == 3 {
        d.application.insert("protocol".into(), "TLS".into());
    }
    if d.protocol == "UDP"
        && (d.source_port == Some(53) || d.destination_port == Some(53))
        && b.len() >= 12
    {
        d.application.insert("protocol".into(), "DNS".into());
        if u16_at(b, 4, false) > 0
            && let Some(name) = dns_name(b, 12)
        {
            d.application.insert("query".into(), name);
        }
    }
}
fn dns_name(b: &[u8], mut p: usize) -> Option<String> {
    let mut labels = vec![];
    let mut visited = std::collections::HashSet::new();
    for _ in 0..128 {
        if !visited.insert(p) {
            return None;
        }
        let n = *b.get(p)? as usize;
        p += 1;
        if n == 0 {
            return Some(labels.join("."));
        }
        if n & 0xc0 == 0xc0 {
            p = ((n & 0x3f) << 8) | *b.get(p)? as usize;
            continue;
        }
        if n > 63 || p + n > b.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&b[p..p + n]).to_string());
        p += n;
    }
    None
}
pub fn flows(records: &[Record]) -> Vec<NetworkFlow> {
    let mut flows: BTreeMap<(String, String, String, String), NetworkFlow> = BTreeMap::new();
    for record in records {
        let RecordData::Packet(p) = &record.data else {
            continue;
        };
        let (Some(src), Some(dst)) = (&p.source, &p.destination) else {
            continue;
        };
        let mut a = format!(
            "[{src}]:{}",
            p.source_port.map(|n| n.to_string()).unwrap_or_default()
        );
        let mut b = format!(
            "[{dst}]:{}",
            p.destination_port
                .map(|n| n.to_string())
                .unwrap_or_default()
        );
        if a > b {
            std::mem::swap(&mut a, &mut b);
        }
        let f = flows
            .entry((
                record.source_id.clone(),
                a.clone(),
                b.clone(),
                p.protocol.clone(),
            ))
            .or_insert_with(|| NetworkFlow {
                endpoint_a: a,
                endpoint_b: b,
                protocol: p.protocol.clone(),
                packets: 0,
                bytes: 0,
                first_seen: None,
                last_seen: None,
                evidence_ids: vec![],
            });
        f.packets += 1;
        f.bytes += p.original_bytes as u64;
        f.evidence_ids.push(record.id.clone());
        if let Some(stamp) = &record.timestamp {
            if f.first_seen.as_ref().is_none_or(|t| t > stamp) {
                f.first_seen = Some(stamp.clone());
            }
            if f.last_seen.as_ref().is_none_or(|t| t < stamp) {
                f.last_seen = Some(stamp.clone());
            }
        }
    }
    flows.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn capture() -> Vec<u8> {
        let mut b = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        b.extend([0; 12]);
        b.extend(1u32.to_le_bytes());
        let mut p = vec![0; 14 + 20 + 8];
        p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        p[14] = 0x45;
        p[16..18].copy_from_slice(&28u16.to_be_bytes());
        p[23] = 17;
        p[26..30].copy_from_slice(&[192, 0, 2, 1]);
        p[30..34].copy_from_slice(&[192, 0, 2, 2]);
        p[34..36].copy_from_slice(&123u16.to_be_bytes());
        p[36..38].copy_from_slice(&53u16.to_be_bytes());
        p[38..40].copy_from_slice(&8u16.to_be_bytes());
        b.extend(1_700_000_000u32.to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend((p.len() as u32).to_le_bytes());
        b.extend((p.len() as u32).to_le_bytes());
        b.extend(p);
        b
    }
    #[test]
    fn pcap_and_damage() {
        let mut b = capture();
        let s = crate::ingest::source_for("fixture", "pcap", &b);
        let mut r = AnalysisReport::default();
        parse_capture(&b, &s, 10, &mut r).unwrap();
        if let RecordData::Packet(p) = &r.records[0].data {
            assert_eq!(p.source.as_deref(), Some("192.0.2.1"));
            assert_eq!(p.destination_port, Some(53));
        } else {
            panic!();
        }
        assert_eq!(flows(&r.records).len(), 1);
        b.push(1);
        let mut r = AnalysisReport::default();
        parse_capture(&b, &s, 10, &mut r).unwrap();
        assert_eq!(r.records[1].status, ParseStatus::Malformed);
    }
    #[test]
    fn malformed_packets_never_panic() {
        for n in 0..100 {
            for link in [1, 101, 113, 276, 228, 229] {
                let _ = decode(
                    &vec![0xff; n],
                    &mut PacketData {
                        link_type: link,
                        ..Default::default()
                    },
                );
            }
        }
        assert!(dns_name(&[0xc0, 0], 0).is_none());
    }
}
