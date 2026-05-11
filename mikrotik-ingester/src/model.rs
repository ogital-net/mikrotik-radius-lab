use clickhouse::Row;
use serde::Serialize;
use std::net::Ipv6Addr;
use time::OffsetDateTime;

#[derive(Debug, Row, Serialize)]
pub struct RawLogRow {
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub received_at: OffsetDateTime,
    pub router: String,
    pub raw: String,
    pub parse_error: String,
}

#[derive(Debug, Row, Serialize)]
pub struct FirewallEvent {
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub ts: OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub received_at: OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub mikrotik_ts: OffsetDateTime,
    pub router: String,
    pub chain: String,
    pub log_prefix: String,
    pub severity: String,
    pub in_iface: String,
    pub out_iface: String,
    pub src_mac: String,
    pub proto: String,
    pub src_ip: Ipv6Addr,
    pub src_port: u16,
    pub dst_ip: Ipv6Addr,
    pub dst_port: u16,
    pub len: u32,
    pub raw: String,
}

#[derive(Debug, Row, Serialize)]
pub struct FlowEvent {
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub ts: OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub received_at: OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub flow_start: OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub flow_end: OffsetDateTime,
    pub router: String,
    pub observation_domain: u32,
    pub sampling_interval: u32,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub tcp_flags: u16,
    pub octets: u64,
    pub packets: u64,
    pub ingress_if: u32,
    pub egress_if: u32,
    pub src_mac: String,
    pub dst_mac: String,
    pub next_hop: Ipv6Addr,
}

#[derive(Debug)]
pub enum Message {
    Firewall(FirewallEvent),
    Raw(RawLogRow),
    Flow(FlowEvent),
}
