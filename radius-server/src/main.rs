mod audit;
mod db;
mod radius;
mod subscribers;
mod web;

use std::process;

use clickhouse::Client;
use log::{info, warn};
use tokio::signal;

use ::radius::server::Server;

const WEB_PORT: u16 = 8080;
const RADIUS_PORT: u16 = 1812;

#[tokio::main]
async fn main() {
    env_logger::init();

    let pool = db::connect("sqlite:latigo.db?mode=rwc").await;

    let ch_url = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into());
    let ch_user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "ingester".into());
    let ch_password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "ingester".into());
    let ch_db = std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "mikrotik".into());
    let ch_client = Client::default()
        .with_url(&ch_url)
        .with_user(&ch_user)
        .with_password(&ch_password)
        .with_database(&ch_db);
    info!(
        "clickhouse audit target {} db={} user={}",
        ch_url, ch_db, ch_user
    );

    let (audit_tx, audit_rx) = audit::channel();
    let audit_handle = tokio::spawn(audit::run(ch_client, audit_rx));

    let app = web::router(web::AppState { db: pool.clone() });
    let web_addr = format!("0.0.0.0:{}", WEB_PORT);
    let listener = tokio::net::TcpListener::bind(&web_addr).await.unwrap();
    info!("web server listening on {}", web_addr);
    let web_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut server = Server::listen(
        "0.0.0.0",
        RADIUS_PORT,
        radius::Handler {
            db: pool.clone(),
            audit_tx,
        },
        radius::StaticSecret,
    )
    .await
    .unwrap();
    server.set_buffer_size(1500);
    server.set_skip_authenticity_validation(false);

    info!("RADIUS server listening on 0.0.0.0:{}", RADIUS_PORT);

    let result = server.run(signal::ctrl_c()).await;
    info!("RADIUS shutdown: {:?}", result);

    drop(server);
    web_handle.abort();

    match tokio::time::timeout(std::time::Duration::from_secs(15), audit_handle).await {
        Ok(_) => info!("audit drain complete"),
        Err(_) => warn!("audit drain timed out; some events may be lost"),
    }

    if result.is_err() {
        process::exit(1);
    }
}
