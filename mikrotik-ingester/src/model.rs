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

#[derive(Debug)]
pub enum Message {
    Firewall(FirewallEvent),
    Raw(RawLogRow),
}
