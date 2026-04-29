use crate::model::FirewallEvent;
use regex::Regex;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::LazyLock;
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("body shape mismatch")]
    BodyShape,
    #[error("bad ip in {0}: {1}")]
    BadIp(&'static str, String),
    #[error("bad port in {0}: {1}")]
    BadPort(&'static str, String),
}

static BODY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        ^.*\s
        (?P<prefix>\S+)\s+
        (?P<chain>forward|input|output):\s+
        in:(?P<in>[^,\s]*)\s+
        out:(?P<out>[^,\s]*),\s+
        connection-state:\S+\s+
        src-mac\s+(?P<mac>\S+),\s+
        proto\s+(?P<proto>[A-Z][A-Z0-9]*)(?:\s+\([^)]*\))?,\s+
        (?P<sip>[^:\s]+):(?P<sport>\d+)->(?P<dip>[^:\s]+):(?P<dport>\d+),\s+
        len\s+(?P<len>\d+)\s*$
        ",
    )
    .expect("body regex must compile")
});

const SEVERITY_NAMES: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

pub fn extract(
    line: &str,
    fallback_router: &str,
    received_at: OffsetDateTime,
) -> Result<FirewallEvent, ExtractError> {
    let caps = BODY_RE.captures(line).ok_or(ExtractError::BodyShape)?;

    let syslog = syslog_loose::parse_message(line, syslog_loose::Variant::Either);
    let mikrotik_ts = syslog
        .timestamp
        .and_then(chrono_to_time)
        .unwrap_or(received_at);
    let syslog_host = syslog
        .hostname
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let severity = parse_priority(line)
        .map(severity_from_priority)
        .unwrap_or("")
        .to_string();

    let log_prefix = caps["prefix"].to_string();
    let chain = caps["chain"].to_string();
    let in_iface = caps["in"].to_string();
    let out_iface = caps["out"].to_string();
    let src_mac = caps["mac"].to_ascii_lowercase().replace('-', ":");
    let proto = caps["proto"].to_ascii_uppercase();
    let src_ip = parse_ip("sip", &caps["sip"])?;
    let dst_ip = parse_ip("dip", &caps["dip"])?;
    let src_port = parse_port("sport", &caps["sport"])?;
    let dst_port = parse_port("dport", &caps["dport"])?;
    let len = caps["len"].parse::<u32>().unwrap_or(0);

    let router = syslog_host.unwrap_or_else(|| fallback_router.to_string());

    Ok(FirewallEvent {
        ts: received_at,
        received_at,
        mikrotik_ts,
        router,
        chain,
        log_prefix,
        severity,
        in_iface,
        out_iface,
        src_mac,
        proto,
        src_ip: to_v6(src_ip),
        src_port,
        dst_ip: to_v6(dst_ip),
        dst_port,
        len,
        raw: line.to_string(),
    })
}

fn parse_priority(line: &str) -> Option<u8> {
    let rest = line.strip_prefix('<')?;
    let end = rest.find('>')?;
    rest[..end].parse::<u8>().ok()
}

fn severity_from_priority(prio: u8) -> &'static str {
    SEVERITY_NAMES[(prio & 7) as usize]
}

fn chrono_to_time(dt: chrono::DateTime<chrono::FixedOffset>) -> Option<OffsetDateTime> {
    let nanos = dt.timestamp_nanos_opt()?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos as i128).ok()
}

fn parse_ip(field: &'static str, s: &str) -> Result<IpAddr, ExtractError> {
    s.parse::<IpAddr>()
        .map_err(|_| ExtractError::BadIp(field, s.to_string()))
}

fn parse_port(field: &'static str, s: &str) -> Result<u16, ExtractError> {
    s.parse::<u16>()
        .map_err(|_| ExtractError::BadPort(field, s.to_string()))
}

fn to_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn ref_time() -> OffsetDateTime {
        datetime!(2026-04-29 19:00:00 UTC)
    }

    #[test]
    fn parses_iso_timestamp_tcp() {
        let line = "<134>2026-04-29T19:13:57.0000+0000 MikroTik conn-new forward: in:ether2 out:ether1, connection-state:new src-mac 52:54:00:00:02:01, proto TCP (SYN), 192.168.88.254:57102->34.107.243.93:443, len 60";
        let ev = extract(line, "fallback", ref_time()).unwrap();
        assert_eq!(ev.log_prefix, "conn-new");
        assert_eq!(ev.chain, "forward");
        assert_eq!(ev.in_iface, "ether2");
        assert_eq!(ev.out_iface, "ether1");
        assert_eq!(ev.src_mac, "52:54:00:00:02:01");
        assert_eq!(ev.proto, "TCP");
        assert_eq!(ev.src_port, 57102);
        assert_eq!(ev.dst_port, 443);
        assert_eq!(ev.len, 60);
        assert_eq!(ev.severity, "info");
        assert_eq!(
            ev.src_ip,
            "::ffff:192.168.88.254".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            ev.dst_ip,
            "::ffff:34.107.243.93".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn parses_bsd_timestamp_tcp() {
        let line = "<134>Apr 29 19:13:35 MikroTik conn-new forward: in:ether2 out:ether1, connection-state:new src-mac 52:54:00:00:02:01, proto TCP (SYN), 192.168.88.254:48954->34.107.221.82:80, len 60";
        let ev = extract(line, "fallback", ref_time()).unwrap();
        assert_eq!(ev.proto, "TCP");
        assert_eq!(ev.src_port, 48954);
        assert_eq!(ev.dst_port, 80);
        assert_eq!(ev.router, "MikroTik");
    }

    #[test]
    fn parses_udp_proto_no_flags() {
        let line = "<134>2026-04-29T19:13:58.0000+0000 MikroTik conn-new forward: in:ether2 out:ether1, connection-state:new src-mac 52:54:00:00:02:01, proto UDP, 192.168.88.254:57036->34.107.243.93:443, len 1280";
        let ev = extract(line, "fallback", ref_time()).unwrap();
        assert_eq!(ev.proto, "UDP");
        assert_eq!(ev.len, 1280);
    }

    #[test]
    fn icmp_falls_through_to_raw() {
        let line = "<134>2026-04-29T19:16:14.0000+0000 MikroTik conn-new forward: in:ether2 out:ether1, connection-state:new src-mac 52:54:00:00:02:01, proto ICMP (type 8, code 0), 192.168.88.254->1.1.1.1, len 84";
        let result = extract(line, "fallback", ref_time());
        assert!(matches!(result, Err(ExtractError::BodyShape)));
    }

    #[test]
    fn severity_from_priority_byte() {
        assert_eq!(severity_from_priority(134), "info");
        assert_eq!(severity_from_priority(131), "err");
        assert_eq!(severity_from_priority(128), "emerg");
        assert_eq!(severity_from_priority(135), "debug");
    }

    #[test]
    fn smac_normalized_dashes_to_colons() {
        let line = "<134>2026-04-29T19:00:00.0000+0000 MikroTik conn-new forward: in:ether2 out:ether1, connection-state:new src-mac AA-BB-CC-DD-EE-FF, proto TCP (SYN), 1.2.3.4:1->5.6.7.8:2, len 1";
        let ev = extract(line, "fallback", ref_time()).unwrap();
        assert_eq!(ev.src_mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn rejects_garbage() {
        let result = extract("not a syslog line at all", "fallback", ref_time());
        assert!(matches!(result, Err(ExtractError::BodyShape)));
    }
}
