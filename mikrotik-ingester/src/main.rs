mod config;
mod listener;
mod migrate;
mod mikrotik;
mod model;
mod pipeline;

use anyhow::Context;
use clickhouse::Client;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mikrotik_ingester=info,clickhouse=warn".into()),
        )
        .init();

    let cfg = config::Config::from_env().context("loading config")?;
    info!(?cfg, "starting mikrotik-ingester");

    let client = Client::default()
        .with_url(&cfg.clickhouse_url)
        .with_user(&cfg.clickhouse_user)
        .with_password(&cfg.clickhouse_password)
        .with_database(&cfg.clickhouse_db);

    let version: String = client
        .query("SELECT version()")
        .fetch_one()
        .await
        .context("connecting to ClickHouse")?;
    info!(clickhouse_version = %version, "connected");

    migrate::run(&client).await.context("running migrations")?;
    info!("migrations applied");

    let shutdown = CancellationToken::new();
    let (tx, rx) = pipeline::channel();

    let pipeline_handle = tokio::spawn(pipeline::run(client.clone(), rx));
    let listener_handle = tokio::spawn(listener::run(cfg.listen_addr, tx, shutdown.clone()));

    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received; draining in-flight events");
    shutdown.cancel();

    let drain = async move {
        if let Err(e) = listener_handle.await {
            error!(?e, "listener task panicked");
        }
        match pipeline_handle.await {
            Ok(Ok(())) => info!("pipeline drained cleanly"),
            Ok(Err(e)) => error!(?e, "pipeline error during drain"),
            Err(e) => error!(?e, "pipeline task panicked"),
        }
    };

    match tokio::time::timeout(Duration::from_secs(15), drain).await {
        Ok(()) => info!("shutdown complete"),
        Err(_) => warn!("drain timeout; some events may be lost"),
    }

    Ok(())
}
