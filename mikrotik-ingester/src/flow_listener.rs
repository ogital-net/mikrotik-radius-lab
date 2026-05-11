use crate::ipfix::IpfixParser;
use crate::model::Message;
use anyhow::Context;
use std::net::SocketAddr;
use time::OffsetDateTime;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub async fn run(
    listen: SocketAddr,
    default_sampling_interval: u32,
    tx: mpsc::Sender<Message>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("binding ipfix {listen}"))?;
    info!(%listen, default_sampling_interval, "listening for ipfix/UDP");

    let mut parser = IpfixParser::new(default_sampling_interval);
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                info!("ipfix listener stopping (cancellation)");
                break;
            }
            res = socket.recv_from(&mut buf) => {
                let (n, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(?e, "ipfix recv_from error");
                        continue;
                    }
                };

                let received_at = OffsetDateTime::now_utc();
                let flows = parser.parse_datagram(&buf[..n], peer.ip(), received_at);

                for flow in flows {
                    if tx.send(Message::Flow(flow)).await.is_err() {
                        warn!("pipeline channel closed; stopping ipfix listener");
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}
