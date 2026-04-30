use crate::audit;
use log::info;
use radius::core::code::Code;
use radius::core::request::Request;
use radius::dict::rfc2865;
use radius::server::{RequestHandler, SecretProvider, SecretProviderError};
use sqlx::SqlitePool;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub mod accounting;
pub mod dhcp;
pub mod hotspot;
pub mod response;
pub mod spike;

pub const SECRET: &[u8] = b"secret";

#[derive(Debug, Clone, Copy)]
pub enum AccessKind {
    Hotspot,
    Dhcp,
}

pub fn classify(req: &radius::core::packet::Packet) -> AccessKind {
    let user_name = rfc2865::lookup_user_name(req)
        .and_then(|r| r.ok())
        .unwrap_or_default();
    if is_mac_string(&user_name) {
        return AccessKind::Dhcp;
    }
    if rfc2865::lookup_user_password(req).is_some() {
        AccessKind::Hotspot
    } else {
        AccessKind::Dhcp
    }
}

fn is_mac_string(s: &str) -> bool {
    let b = s.as_bytes();
    match b.len() {
        12 => b.iter().all(|c| c.is_ascii_hexdigit()),
        17 => {
            let sep = b[2];
            if sep != b':' && sep != b'-' {
                return false;
            }
            for i in 0..6 {
                let off = i * 3;
                if !b[off].is_ascii_hexdigit() || !b[off + 1].is_ascii_hexdigit() {
                    return false;
                }
                if i < 5 && b[off + 2] != sep {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

pub struct Handler {
    pub db: SqlitePool,
    pub audit_tx: mpsc::Sender<audit::SessionEvent>,
}

impl RequestHandler<(), io::Error> for Handler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();
        info!("RADIUS {:?} from {}", req_packet.code(), req.remote_addr());

        match req_packet.code() {
            Code::AccessRequest => match classify(req_packet) {
                AccessKind::Hotspot => hotspot::handle(conn, req, &self.db).await,
                AccessKind::Dhcp => dhcp::handle(conn, req, &self.db).await,
            },
            Code::AccountingRequest => {
                accounting::handle(conn, req, &self.db, &self.audit_tx).await
            }
            other => {
                info!("ignoring unsupported RADIUS code {:?}", other);
                Ok(())
            }
        }
    }
}

pub struct StaticSecret;

impl SecretProvider for StaticSecret {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        Ok(SECRET.to_vec())
    }
}
