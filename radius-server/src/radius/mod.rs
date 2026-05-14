use crate::audit;
use radius_tokio::dict::generated::rfc::attrs;
use radius_tokio::server::{Handler, HandlerResult, Request};
use radius_tokio::typed::{Attr, VsaAttr, WText, WireType};
use radius_tokio::Code;
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use tracing::{debug, info};

pub mod accounting;
pub mod dhcp;
pub mod hotspot;
pub mod spike;

#[derive(Debug, Clone, Copy)]
pub enum AccessKind {
    Hotspot,
    Dhcp,
}

pub fn classify(request: &Request<'_>) -> AccessKind {
    let user_name = first_text(request, attrs::USER_NAME).unwrap_or_default();
    if is_mac_string(&user_name) {
        return AccessKind::Dhcp;
    }
    if request.first_raw(2).ok().flatten().is_some() {
        AccessKind::Hotspot
    } else {
        AccessKind::Dhcp
    }
}

pub fn first<'a, T: WireType>(request: &Request<'a>, attr: Attr<T>) -> Option<T::View<'a>> {
    for slot in request.attributes_iter() {
        let raw = slot.ok()?;
        if let Some(v) = raw.get(attr) {
            return Some(v);
        }
    }
    None
}

pub fn first_vsa<'a, T: WireType>(request: &Request<'a>, attr: VsaAttr<T>) -> Option<T::View<'a>> {
    for slot in request.attributes_iter() {
        let raw = slot.ok()?;
        if let Some(v) = raw.get_vsa(attr) {
            return Some(v);
        }
    }
    None
}

pub fn first_text(request: &Request<'_>, attr: Attr<WText>) -> Option<String> {
    first(request, attr).map(str::to_owned)
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

#[derive(Clone)]
pub struct AppHandler {
    pub db: SqlitePool,
    pub audit_tx: mpsc::Sender<audit::SessionEvent>,
}

impl Handler for AppHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        info!("RADIUS {:?} from {}", request.code(), request.src());

        if tracing::enabled!(tracing::Level::DEBUG) {
            use std::fmt::Write;
            let mut buf = format!(
                "RADIUS dissect — code={:?} id={} from {} auth={:02x?}",
                request.code(),
                request.identifier(),
                request.src(),
                request.authenticator()
            );
            for raw in request.attributes_iter().filter_map(Result::ok) {
                let _ = write!(buf, "\n    {}", raw.dissect());
            }
            debug!("{}", buf);
        }

        match request.code() {
            Code::ACCESS_REQUEST => match classify(&request) {
                AccessKind::Hotspot => hotspot::handle(&request, &self.db).await,
                AccessKind::Dhcp => dhcp::handle(&request, &self.db).await,
            },
            Code::ACCOUNTING_REQUEST => {
                accounting::handle(&request, &self.db, &self.audit_tx).await
            }
            other => {
                info!("ignoring unsupported RADIUS code {:?}", other);
                HandlerResult::Drop
            }
        }
    }
}

pub use radius_tokio::dict::generated::mikrotik::attrs as mikrotik_attrs;
