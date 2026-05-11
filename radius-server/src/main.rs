mod audit;
mod db;
mod radius;
mod subscribers;
mod web;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process;
use std::sync::Arc;

use clickhouse::Client;
use log::{info, warn};
use radius_tokio::server::{Client as RadiusClient, IpCidr, Server, StaticClients};
use tokio::signal;

const SECRET: &[u8] = b"secret";
const WEB_PORT: u16 = 8080;
const RADIUS_AUTH_PORT: u16 = 1812;
const RADIUS_ACCT_PORT: u16 = 1813;

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

    let handler = radius::AppHandler {
        db: pool.clone(),
        audit_tx,
    };

    let shared = Arc::new(RadiusClient::new(SECRET));
    let clients = StaticClients::builder()
        .add(
            IpCidr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap(),
            Arc::clone(&shared),
        )
        .add(
            IpCidr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap(),
            shared,
        )
        .build();

    let server = Server::builder()
        .clients(clients)
        .handler(handler)
        .listen_udp(format!("0.0.0.0:{}", RADIUS_AUTH_PORT).parse().unwrap())
        .listen_udp(format!("0.0.0.0:{}", RADIUS_ACCT_PORT).parse().unwrap())
        .build()
        .unwrap();
    let shutdown = server.shutdown_handle();

    info!("RADIUS auth listening on 0.0.0.0:{}", RADIUS_AUTH_PORT);
    info!(
        "RADIUS accounting listening on 0.0.0.0:{}",
        RADIUS_ACCT_PORT
    );

    tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        shutdown.shutdown();
    });

    let radius_result = server.run().await;
    info!("RADIUS shutdown: {:?}", radius_result);

    web_handle.abort();

    match tokio::time::timeout(std::time::Duration::from_secs(15), audit_handle).await {
        Ok(_) => info!("audit drain complete"),
        Err(_) => warn!("audit drain timed out; some events may be lost"),
    }

    if radius_result.is_err() {
        process::exit(1);
    }
}
