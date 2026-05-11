use super::{first_text, first_vsa, mikrotik_attrs, spike};
use crate::subscribers::{self, Addressing, Authorization};
use log::{info, warn};
use radius_tokio::dict::generated::rfc::attrs;
use radius_tokio::server::{HandlerResult, Request};
use radius_tokio::{Code, Reply};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

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

const ATTR_DHCP_AGENT_CIRCUIT_ID: u8 = 82;
const VENDOR_MIKROTIK: u32 = 14988;
const ACCT_INTERIM_INTERVAL_SECS: u32 = 300;

pub async fn handle(request: &Request<'_>, db: &SqlitePool) -> HandlerResult {
    spike::dump("dhcp Access-Request", request);

    let mac = first_text(request, attrs::USER_NAME).unwrap_or_default();

    let circuit_id = match extract_circuit_id(request) {
        Some(c) => c,
        None => match recall_transaction(&mac) {
            Some(c) => {
                info!(
                    "dhcp Access-Request from {} has no Circuit-Id; recovering from in-flight transaction for mac='{}' → circuit='{}'",
                    request.src(),
                    mac,
                    c
                );
                c
            }
            None => {
                warn!(
                    "dhcp Access-Request from {} carries no recognizable Circuit-Id and no cached transaction for mac='{}' — rejecting",
                    request.src(),
                    mac
                );
                return HandlerResult::Reply(request.reply(Code::ACCESS_REJECT));
            }
        },
    };

    info!("dhcp lookup circuit_id='{}'", circuit_id);
    let authz = subscribers::authorize(db, &circuit_id).await;

    let reply = match authz {
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
            let mut reply = request.reply(Code::ACCESS_ACCEPT);
            apply_addressing(&mut reply, &addressing);
            if let Some(rl) = rate_limit.as_deref() {
                let _ = reply.add_vsa(mikrotik_attrs::MIKROTIK_RATE_LIMIT, rl);
            }
            let _ = reply.add(attrs::SESSION_TIMEOUT, session_timeout);
            let _ = reply.add(attrs::ACCT_INTERIM_INTERVAL, ACCT_INTERIM_INTERVAL_SECS);
            reply
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
            let mut reply = request.reply(Code::ACCESS_ACCEPT);
            let _ = reply.add(attrs::FRAMED_POOL, pool.as_str());
            let _ = reply.add(attrs::SESSION_TIMEOUT, session_timeout);
            let _ = reply.add(attrs::ACCT_INTERIM_INTERVAL, ACCT_INTERIM_INTERVAL_SECS);
            reply
        }
        Authorization::Reject(reason) => {
            warn!(
                "dhcp REJECT circuit_id='{}' reason={:?}",
                circuit_id, reason
            );
            request.reply(Code::ACCESS_REJECT)
        }
    };

    HandlerResult::Reply(reply)
}

fn apply_addressing(reply: &mut Reply, addressing: &Addressing) {
    match addressing {
        Addressing::FixedIp(ip) => {
            let _ = reply.add(attrs::FRAMED_IP_ADDRESS, *ip);
        }
        Addressing::Pool(pool) => {
            let _ = reply.add(attrs::FRAMED_POOL, pool.as_str());
        }
    }
}

fn extract_circuit_id(request: &Request<'_>) -> Option<String> {
    if let Some(bytes) = first_vsa(request, attrs::ADSL_AGENT_CIRCUIT_ID) {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return Some(s.to_string());
        }
    }
    if let Some(bytes) = first_vsa(request, attrs::ADSL_AGENT_REMOTE_ID) {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return Some(s.to_string());
        }
    }
    if let Some(s) = scan_attribute_82(request) {
        return Some(s);
    }
    if let Some(s) = scan_mikrotik_vsa_for_circuit(request) {
        return Some(s);
    }
    None
}

fn scan_attribute_82(request: &Request<'_>) -> Option<String> {
    let raw = request.first_raw(ATTR_DHCP_AGENT_CIRCUIT_ID).ok().flatten()?;
    parse_option82_circuit_id(raw.value())
}

fn parse_option82_circuit_id(value: &[u8]) -> Option<String> {
    if let Ok(s) = std::str::from_utf8(value) {
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

fn scan_mikrotik_vsa_for_circuit(request: &Request<'_>) -> Option<String> {
    for slot in request.attributes_iter() {
        let raw = slot.ok()?;
        if raw.attribute_type() != 26 {
            continue;
        }
        let value = raw.value();
        if value.len() < 6 {
            continue;
        }
        let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        if vendor_id != VENDOR_MIKROTIK {
            continue;
        }
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
    None
}
