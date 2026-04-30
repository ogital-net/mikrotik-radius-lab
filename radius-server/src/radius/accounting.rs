use super::response;
use crate::audit;
use log::{error, info, warn};
use radius::core::code::Code;
use radius::core::request::Request;
use radius::dict::{rfc2865, rfc2866};
use sqlx::SqlitePool;
use std::io;
use time::OffsetDateTime;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub async fn handle(
    conn: &UdpSocket,
    req: &Request,
    db: &SqlitePool,
    audit_tx: &mpsc::Sender<audit::SessionEvent>,
) -> Result<(), io::Error> {
    let req_packet = req.packet();

    let status_type = rfc2866::lookup_acct_status_type(req_packet)
        .and_then(|r| r.ok())
        .unwrap_or(0);
    let session_id = rfc2866::lookup_acct_session_id(req_packet)
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let username = rfc2865::lookup_user_name(req_packet)
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let mac = rfc2865::lookup_calling_station_id(req_packet)
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let ip = rfc2865::lookup_framed_ip_address(req_packet)
        .map(|r| r.ok().map(|addr| addr.to_string()).unwrap_or_default())
        .unwrap_or_default();
    let nas_ip = rfc2865::lookup_nas_ip_address(req_packet)
        .map(|r| r.ok().map(|addr| addr.to_string()).unwrap_or_default())
        .unwrap_or_default();
    let session_time = rfc2866::lookup_acct_session_time(req_packet)
        .and_then(|r| r.ok())
        .unwrap_or(0);
    let bytes_in = rfc2866::lookup_acct_input_octets(req_packet)
        .and_then(|r| r.ok())
        .unwrap_or(0);
    let bytes_out = rfc2866::lookup_acct_output_octets(req_packet)
        .and_then(|r| r.ok())
        .unwrap_or(0);
    let cause_str: &str =
        match rfc2866::lookup_acct_terminate_cause(req_packet).and_then(|r| r.ok()) {
            None => "",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_USER_REQUEST) => "User-Request",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT) => "Idle-Timeout",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT) => "Session-Timeout",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_ADMIN_RESET) => "Admin-Reset",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_ADMIN_REBOOT) => "Admin-Reboot",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_NAS_REBOOT) => "NAS-Reboot",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_LOST_CARRIER) => "Lost-Carrier",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_NAS_REQUEST) => "NAS-Request",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_NAS_ERROR) => "NAS-Error",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_PORT_ERROR) => "Port-Error",
            Some(_) => "Unknown",
        };

    match status_type {
        rfc2866::ACCT_STATUS_TYPE_START => {
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
        rfc2866::ACCT_STATUS_TYPE_INTERIM_UPDATE => {
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
        rfc2866::ACCT_STATUS_TYPE_STOP => {
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
        rfc2866::ACCT_STATUS_TYPE_ACCOUNTING_ON => {
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
        rfc2866::ACCT_STATUS_TYPE_ACCOUNTING_OFF => {
            info!("Accounting OFF from NAS '{}'", nas_ip);
        }
        _ => {
            info!(
                "Accounting unknown status_type={} session='{}'",
                status_type, session_id
            );
        }
    }

    let kind: Option<&str> = match status_type {
        rfc2866::ACCT_STATUS_TYPE_START => Some("start"),
        rfc2866::ACCT_STATUS_TYPE_INTERIM_UPDATE => Some("interim"),
        rfc2866::ACCT_STATUS_TYPE_STOP => Some("stop"),
        rfc2866::ACCT_STATUS_TYPE_ACCOUNTING_ON => Some("on"),
        rfc2866::ACCT_STATUS_TYPE_ACCOUNTING_OFF => Some("off"),
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
            session_time: session_time as u32,
            bytes_in: bytes_in as u64,
            bytes_out: bytes_out as u64,
            terminate_cause: cause_str.to_string(),
        };
        if let Err(e) = audit_tx.try_send(event) {
            warn!("audit channel send dropped: {}", e);
        }
    }

    let bytes = response::encode(req_packet, Code::AccountingResponse);
    conn.send_to(&bytes, req.remote_addr()).await?;
    Ok(())
}
