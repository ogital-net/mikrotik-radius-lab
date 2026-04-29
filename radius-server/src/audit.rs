use clickhouse::{Client, Row};
use log::{error, info, warn};
use serde::Serialize;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;

#[derive(Debug, Row, Serialize, Clone)]
pub struct SessionEvent {
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub ts: OffsetDateTime,
    pub event: String,
    pub acct_session_id: String,
    pub nas_ip: Ipv6Addr,
    pub username: String,
    pub mac: String,
    pub framed_ip: Ipv6Addr,
    pub session_time: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub terminate_cause: String,
}

pub fn channel() -> (mpsc::Sender<SessionEvent>, mpsc::Receiver<SessionEvent>) {
    mpsc::channel(10_000)
}

pub fn normalize_mac(s: &str) -> String {
    s.to_ascii_lowercase().replace('-', ":")
}

pub fn parse_v6(s: &str) -> Ipv6Addr {
    s.parse::<IpAddr>()
        .map(|addr| match addr {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        })
        .unwrap_or(Ipv6Addr::UNSPECIFIED)
}

pub async fn run(client: Client, mut rx: mpsc::Receiver<SessionEvent>) {
    let mut ins = client
        .inserter::<SessionEvent>("radius_session_events")
        .with_period(Some(Duration::from_secs(5)))
        .with_max_rows(100_000)
        .with_max_bytes(50_000_000);
    info!("radius audit inserter started");

    loop {
        let timeout = ins
            .time_left()
            .unwrap_or(Duration::from_secs(5))
            .max(Duration::from_millis(50));

        tokio::select! {
            maybe_ev = rx.recv() => {
                match maybe_ev {
                    Some(ev) => {
                        if let Err(e) = ins.write(&ev).await {
                            error!("audit write failed: {}", e);
                        }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(timeout) => {}
        }

        match ins.commit().await {
            Ok(stats) if stats.rows > 0 => {
                info!("audit committed rows={} bytes={}", stats.rows, stats.bytes);
            }
            Ok(_) => {}
            Err(e) => warn!("audit commit failed: {}", e),
        }
    }

    match ins.end().await {
        Ok(stats) => info!("audit final flush rows={}", stats.rows),
        Err(e) => error!("audit final flush failed: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_mac_handles_common_formats() {
        assert_eq!(normalize_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(normalize_mac(""), "");
    }

    #[test]
    fn parse_v6_handles_inputs() {
        assert_eq!(parse_v6(""), Ipv6Addr::UNSPECIFIED);
        assert_eq!(parse_v6("not-an-ip"), Ipv6Addr::UNSPECIFIED);
        assert_eq!(
            parse_v6("192.168.1.10"),
            std::net::Ipv4Addr::new(192, 168, 1, 10).to_ipv6_mapped()
        );
        assert_eq!(parse_v6("::1"), Ipv6Addr::LOCALHOST);
    }
}
