use super::{first, first_text};
use crate::audit;
use log::{error, info, warn};
use radius_tokio::dict::generated::rfc::attrs;
use radius_tokio::server::{AcctStatusType, HandlerResult, Request};
use radius_tokio::Code;
use sqlx::SqlitePool;
use time::OffsetDateTime;
use tokio::sync::mpsc;

pub async fn handle(
    request: &Request<'_>,
    db: &SqlitePool,
    audit_tx: &mpsc::Sender<audit::SessionEvent>,
) -> HandlerResult {
    let status = request.acct_status_type();
    let session_id = first_text(request, attrs::ACCT_SESSION_ID).unwrap_or_default();
    let username = first_text(request, attrs::USER_NAME).unwrap_or_default();
    let mac = first_text(request, attrs::CALLING_STATION_ID).unwrap_or_default();
    let ip = first(request, attrs::FRAMED_IP_ADDRESS)
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    let nas_ip = first(request, attrs::NAS_IP_ADDRESS)
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    let session_time = first(request, attrs::ACCT_SESSION_TIME).unwrap_or(0);
    let bytes_in = first(request, attrs::ACCT_INPUT_OCTETS).unwrap_or(0);
    let bytes_out = first(request, attrs::ACCT_OUTPUT_OCTETS).unwrap_or(0);
    let cause_str: &str = match first(request, attrs::ACCT_TERMINATE_CAUSE) {
        None => "",
        Some(1) => "User-Request",
        Some(4) => "Idle-Timeout",
        Some(5) => "Session-Timeout",
        Some(6) => "Admin-Reset",
        Some(7) => "Admin-Reboot",
        Some(11) => "NAS-Reboot",
        Some(2) => "Lost-Carrier",
        Some(10) => "NAS-Request",
        Some(9) => "NAS-Error",
        Some(8) => "Port-Error",
        Some(_) => "Unknown",
    };

    match status {
        Some(AcctStatusType::Start) => {
            info!(
                "Accounting START session='{}' user='{}' mac='{}' ip='{}'",
                session_id, username, mac, ip
            );
            let _ = sqlx::query(
                "INSERT INTO sessions (acct_session_id, username, mac_address, ip_address, nas_ip, started_at, status)
                 VALUES (?, ?, ?, ?, ?, datetime('now'), 'active')",
            )
            .bind(&session_id)
            .bind(&username)
            .bind(&mac)
            .bind(&ip)
            .bind(&nas_ip)
            .execute(db)
            .await
            .map_err(|e| error!("accounting start db error: {}", e));
        }
        Some(AcctStatusType::InterimUpdate) => {
            info!(
                "Accounting INTERIM session='{}' user='{}' time={}s in={} out={}",
                session_id, username, session_time, bytes_in, bytes_out
            );
            let _ = sqlx::query(
                "UPDATE sessions SET session_time = ?, bytes_in = ?, bytes_out = ?
                 WHERE acct_session_id = ? AND nas_ip = ? AND status = 'active'",
            )
            .bind(session_time)
            .bind(bytes_in)
            .bind(bytes_out)
            .bind(&session_id)
            .bind(&nas_ip)
            .execute(db)
            .await
            .map_err(|e| error!("accounting interim db error: {}", e));
        }
        Some(AcctStatusType::Stop) => {
            info!(
                "Accounting STOP session='{}' user='{}' time={}s in={} out={} cause='{}'",
                session_id, username, session_time, bytes_in, bytes_out, cause_str
            );
            let _ = sqlx::query(
                "UPDATE sessions SET session_time = ?, bytes_in = ?, bytes_out = ?,
                 stopped_at = datetime('now'), terminate_cause = ?, status = 'closed'
                 WHERE acct_session_id = ? AND nas_ip = ? AND status = 'active'",
            )
            .bind(session_time)
            .bind(bytes_in)
            .bind(bytes_out)
            .bind(cause_str)
            .bind(&session_id)
            .bind(&nas_ip)
            .execute(db)
            .await
            .map_err(|e| error!("accounting stop db error: {}", e));
        }
        Some(AcctStatusType::AccountingOn) => {
            info!(
                "Accounting ON from NAS '{}' — closing stale sessions",
                nas_ip
            );
            let _ = sqlx::query(
                "UPDATE sessions SET stopped_at = datetime('now'), terminate_cause = 'NAS-Reboot', status = 'closed'
                 WHERE nas_ip = ? AND status = 'active'",
            )
            .bind(&nas_ip)
            .execute(db)
            .await
            .map_err(|e| error!("accounting-on db error: {}", e));
        }
        Some(AcctStatusType::AccountingOff) => {
            info!("Accounting OFF from NAS '{}'", nas_ip);
        }
        other => {
            info!(
                "Accounting unknown status={:?} session='{}'",
                other, session_id
            );
        }
    }

    let kind: Option<&str> = match status {
        Some(AcctStatusType::Start) => Some("start"),
        Some(AcctStatusType::InterimUpdate) => Some("interim"),
        Some(AcctStatusType::Stop) => Some("stop"),
        Some(AcctStatusType::AccountingOn) => Some("on"),
        Some(AcctStatusType::AccountingOff) => Some("off"),
        _ => None,
    };
    if let Some(kind) = kind {
        let event = audit::SessionEvent {
            ts: OffsetDateTime::now_utc(),
            event: kind.to_string(),
            acct_session_id: session_id.clone(),
            nas_ip: audit::parse_v6(&nas_ip),
            username: username.clone(),
            mac: audit::normalize_mac(&mac),
            framed_ip: audit::parse_v6(&ip),
            session_time,
            bytes_in: u64::from(bytes_in),
            bytes_out: u64::from(bytes_out),
            terminate_cause: cause_str.to_string(),
        };
        if let Err(e) = audit_tx.try_send(event) {
            warn!("audit channel send dropped: {}", e);
        }
    }

    HandlerResult::Reply(request.reply(Code::ACCOUNTING_RESPONSE))
}
