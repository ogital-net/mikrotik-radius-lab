use crate::model::{FirewallEvent, Message, RawLogRow};
use clickhouse::{Client, inserter::Inserter};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info};

pub fn channel() -> (mpsc::Sender<Message>, mpsc::Receiver<Message>) {
    mpsc::channel(10_000)
}

pub async fn run(client: Client, mut rx: mpsc::Receiver<Message>) -> anyhow::Result<()> {
    let mut fw = client
        .inserter::<FirewallEvent>("firewall_connections")?
        .with_period(Some(Duration::from_secs(5)))
        .with_max_rows(100_000)
        .with_max_bytes(50_000_000);
    let mut raw = client
        .inserter::<RawLogRow>("raw_log")?
        .with_period(Some(Duration::from_secs(5)))
        .with_max_rows(100_000)
        .with_max_bytes(50_000_000);

    info!("inserters started");

    loop {
        let timeout = min_left(&mut fw, &mut raw);

        tokio::select! {
            maybe_msg = rx.recv() => {
                match maybe_msg {
                    Some(Message::Firewall(ev)) => {
                        if let Err(e) = fw.write(&ev) {
                            error!(?e, "fw.write failed");
                        }
                    }
                    Some(Message::Raw(row)) => {
                        if let Err(e) = raw.write(&row) {
                            error!(?e, "raw.write failed");
                        }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(timeout) => {}
        }

        commit("firewall_connections", &mut fw).await;
        commit("raw_log", &mut raw).await;
    }

    let s_fw = fw.end().await?;
    let s_raw = raw.end().await?;
    info!(fw_rows = s_fw.rows, raw_rows = s_raw.rows, "final flush");
    Ok(())
}

fn min_left<A, B>(a: &mut Inserter<A>, b: &mut Inserter<B>) -> Duration
where
    A: clickhouse::Row,
    B: clickhouse::Row,
{
    let fallback = Duration::from_secs(5);
    let ta = a.time_left().unwrap_or(fallback);
    let tb = b.time_left().unwrap_or(fallback);
    ta.min(tb).max(Duration::from_millis(50))
}

async fn commit<T>(name: &str, ins: &mut Inserter<T>)
where
    T: clickhouse::Row,
{
    match ins.commit().await {
        Ok(stats) if stats.rows > 0 => {
            info!(
                table = name,
                rows = stats.rows,
                bytes = stats.bytes,
                "committed"
            );
        }
        Ok(_) => {}
        Err(e) => error!(table = name, ?e, "commit failed"),
    }
}
