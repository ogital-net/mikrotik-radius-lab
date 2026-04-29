use crate::mikrotik;
use crate::model::{Message, RawLogRow};
use anyhow::Context;
use std::net::SocketAddr;
use time::OffsetDateTime;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub async fn run(
    listen: SocketAddr,
    tx: mpsc::Sender<Message>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    info!(%listen, "listening for syslog/UDP");

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                info!("listener stopping (cancellation)");
                break;
            }
            res = socket.recv_from(&mut buf) => {
                let (n, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(?e, "recv_from error");
                        continue;
                    }
                };

                let line = match std::str::from_utf8(&buf[..n]) {
                    Ok(s) => s.trim_end_matches(['\n', '\r', '\0']).to_string(),
                    Err(e) => {
                        debug!(%peer, ?e, "non-utf8 datagram");
                        continue;
                    }
                };

                let received_at = OffsetDateTime::now_utc();
                let fallback_router = peer.ip().to_string();
                let msg = match mikrotik::extract(&line, &fallback_router, received_at) {
                    Ok(ev) => Message::Firewall(ev),
                    Err(e) => {
                        debug!(%peer, ?e, "parse failed -> raw_log");
                        Message::Raw(RawLogRow {
                            received_at,
                            router: fallback_router,
                            raw: line,
                            parse_error: e.to_string(),
                        })
                    }
                };

                if tx.send(msg).await.is_err() {
                    warn!("pipeline channel closed; stopping listener");
                    break;
                }
            }
        }
    }
    Ok(())
}
