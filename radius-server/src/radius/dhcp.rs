use super::{response, spike};
use crate::subscribers::{self, Addressing, Authorization};
use log::{info, warn};
use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::core::request::Request;
use radius::dict::{mikrotik, rfc2865, rfc2869};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::io;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const TRANSACTION_TTL: Duration = Duration::from_secs(60);

static MAC_TO_CIRCUIT: OnceLock<Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();

fn transaction_cache() -> &'static Mutex<HashMap<String, (String, Instant)>> {
    MAC_TO_CIRCUIT.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_transaction(mac: &str, circuit_id: &str) {
    if mac.is_empty() {
        return;
    }
    let mut g = transaction_cache().lock().unwrap();
    let now = Instant::now();
    g.retain(|_, (_, ts)| now.duration_since(*ts) < TRANSACTION_TTL);
    g.insert(mac.to_string(), (circuit_id.to_string(), now));
}

fn recall_transaction(mac: &str) -> Option<String> {
    if mac.is_empty() {
        return None;
    }
    let g = transaction_cache().lock().unwrap();
    g.get(mac).and_then(|(cid, ts)| {
        if Instant::now().duration_since(*ts) < TRANSACTION_TTL {
            Some(cid.clone())
        } else {
            None
        }
    })
}

const HEADER_LEN: usize = 20;
const VENDOR_SPECIFIC: u8 = 26;
const ATTR_CALLED_STATION_ID: u8 = 30;
const ATTR_NAS_PORT_ID: u8 = 87;
const ATTR_DHCP_AGENT_CIRCUIT_ID: u8 = 82;
const VENDOR_MIKROTIK: u32 = 14988;
const VENDOR_DSL_FORUM: u32 = 3561;
const DSL_FORUM_AGENT_CIRCUIT_ID: u8 = 1;
const DSL_FORUM_AGENT_REMOTE_ID: u8 = 2;
const ACCT_INTERIM_INTERVAL_SECS: u32 = 300;

pub async fn handle(conn: &UdpSocket, req: &Request, db: &SqlitePool) -> Result<(), io::Error> {
    let req_packet = req.packet();

    spike::dump("dhcp Access-Request", req_packet);

    let mac = rfc2865::lookup_user_name(req_packet)
        .and_then(|r| r.ok())
        .unwrap_or_default();

    let circuit_id = match extract_circuit_id(req_packet) {
        Some(c) => c,
        None => match recall_transaction(&mac) {
            Some(c) => {
                info!(
                    "dhcp Access-Request from {} has no Circuit-Id; recovering from in-flight transaction for mac='{}' → circuit='{}'",
                    req.remote_addr(),
                    mac,
                    c
                );
                c
            }
            None => {
                warn!(
                    "dhcp Access-Request from {} carries no recognizable Circuit-Id and no cached transaction for mac='{}' — rejecting",
                    req.remote_addr(),
                    mac
                );
                let bytes = response::encode(req_packet, Code::AccessReject);
                conn.send_to(&bytes, req.remote_addr()).await?;
                return Ok(());
            }
        },
    };

    info!("dhcp lookup circuit_id='{}'", circuit_id);
    let authz = subscribers::authorize(db, &circuit_id).await;

    let bytes = match authz {
        Authorization::Accept {
            addressing,
            rate_limit,
            session_timeout,
            plan,
        } => {
            info!(
                "dhcp ACCEPT circuit_id='{}' plan='{}' addressing={:?}",
                circuit_id, plan, addressing
            );
            remember_transaction(&mac, &circuit_id);
            let mut resp = response::make(req_packet, Code::AccessAccept);
            apply_addressing(&mut resp, &addressing);
            if let Some(rl) = rate_limit.as_deref() {
                mikrotik::add_mikrotik_rate_limit(&mut resp, rl);
            }
            rfc2865::add_session_timeout(&mut resp, session_timeout);
            rfc2869::add_acct_interim_interval(&mut resp, ACCT_INTERIM_INTERVAL_SECS);
            response::finalize(resp, req_packet.authenticator())
        }
        Authorization::WalledGarden {
            pool,
            session_timeout,
            plan,
        } => {
            info!(
                "dhcp WALLED-GARDEN circuit_id='{}' plan='{}' pool='{}'",
                circuit_id, plan, pool
            );
            remember_transaction(&mac, &circuit_id);
            let mut resp = response::make(req_packet, Code::AccessAccept);
            rfc2869::add_framed_pool(&mut resp, &pool);
            rfc2865::add_session_timeout(&mut resp, session_timeout);
            rfc2869::add_acct_interim_interval(&mut resp, ACCT_INTERIM_INTERVAL_SECS);
            response::finalize(resp, req_packet.authenticator())
        }
        Authorization::Reject(reason) => {
            warn!(
                "dhcp REJECT circuit_id='{}' reason={:?}",
                circuit_id, reason
            );
            response::encode(req_packet, Code::AccessReject)
        }
    };

    conn.send_to(&bytes, req.remote_addr()).await?;
    Ok(())
}

fn apply_addressing(resp: &mut Packet, addressing: &Addressing) {
    match addressing {
        Addressing::FixedIp(ip) => rfc2865::add_framed_ip_address(resp, ip),
        Addressing::Pool(pool) => rfc2869::add_framed_pool(resp, pool),
    }
}

fn extract_circuit_id(req_packet: &Packet) -> Option<String> {
    let bytes = req_packet.encode().ok()?;
    if bytes.len() <= HEADER_LEN {
        return None;
    }

    if let Some(s) = scan_vsa_string(&bytes, VENDOR_DSL_FORUM, DSL_FORUM_AGENT_CIRCUIT_ID) {
        return Some(s);
    }
    if let Some(s) = scan_vsa_string(&bytes, VENDOR_DSL_FORUM, DSL_FORUM_AGENT_REMOTE_ID) {
        return Some(s);
    }
    if let Some(s) =
        scan_attribute(&bytes, ATTR_DHCP_AGENT_CIRCUIT_ID).and_then(parse_option82_circuit_id)
    {
        return Some(s);
    }
    if let Some(s) = scan_mikrotik_vsa_for_circuit(&bytes) {
        return Some(s);
    }
    None
}

fn scan_vsa_string(bytes: &[u8], target_vendor: u32, target_sub_type: u8) -> Option<String> {
    let mut i = HEADER_LEN;
    while i + 2 <= bytes.len() {
        let typ = bytes[i];
        let len = bytes[i + 1] as usize;
        if len < 2 || i + len > bytes.len() {
            return None;
        }
        if typ == VENDOR_SPECIFIC && len >= 6 {
            let value = &bytes[i + 2..i + len];
            let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            if vendor_id == target_vendor {
                let mut j = 4;
                while j + 2 <= value.len() {
                    let sub_typ = value[j];
                    let sub_len = value[j + 1] as usize;
                    if sub_len < 2 || j + sub_len > value.len() {
                        break;
                    }
                    if sub_typ == target_sub_type {
                        let raw = &value[j + 2..j + sub_len];
                        if let Ok(s) = std::str::from_utf8(raw) {
                            return Some(s.to_string());
                        }
                    }
                    j += sub_len;
                }
            }
        }
        i += len;
    }
    None
}

fn scan_attribute(bytes: &[u8], target: u8) -> Option<Vec<u8>> {
    let mut i = HEADER_LEN;
    while i + 2 <= bytes.len() {
        let typ = bytes[i];
        let len = bytes[i + 1] as usize;
        if len < 2 || i + len > bytes.len() {
            return None;
        }
        if typ == target {
            return Some(bytes[i + 2..i + len].to_vec());
        }
        i += len;
    }
    None
}

fn parse_option82_circuit_id(value: Vec<u8>) -> Option<String> {
    if let Ok(s) = std::str::from_utf8(&value) {
        if !s.is_empty() && s.chars().all(|c| !c.is_control()) {
            return Some(s.to_string());
        }
    }
    let mut j = 0;
    while j + 2 <= value.len() {
        let sub_typ = value[j];
        let sub_len = value[j + 1] as usize;
        if sub_len < 2 || j + sub_len > value.len() {
            return None;
        }
        if sub_typ == 1 {
            return std::str::from_utf8(&value[j + 2..j + sub_len])
                .ok()
                .map(|s| s.to_string());
        }
        j += sub_len;
    }
    None
}

fn scan_mikrotik_vsa_for_circuit(bytes: &[u8]) -> Option<String> {
    let mut i = HEADER_LEN;
    while i + 2 <= bytes.len() {
        let typ = bytes[i];
        let len = bytes[i + 1] as usize;
        if len < 2 || i + len > bytes.len() {
            return None;
        }
        if typ == VENDOR_SPECIFIC && len >= 6 {
            let value = &bytes[i + 2..i + len];
            let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            if vendor_id == VENDOR_MIKROTIK {
                let mut j = 4;
                while j + 2 <= value.len() {
                    let sub_len = value[j + 1] as usize;
                    if sub_len < 2 || j + sub_len > value.len() {
                        break;
                    }
                    let sub_value = &value[j + 2..j + sub_len];
                    if let Ok(s) = std::str::from_utf8(sub_value) {
                        let lower = s.to_ascii_lowercase();
                        if lower.contains("circuit") || lower.starts_with("acc") {
                            return Some(s.to_string());
                        }
                    }
                    j += sub_len;
                }
            }
        }
        i += len;
    }
    None
}
