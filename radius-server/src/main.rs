mod audit;
mod db;
mod radius;
mod subscribers;
mod web;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process;
use std::sync::Arc;

use clickhouse::Client;
use radius_tokio::server::{Client as RadiusClient, ClientStore, IpCidr, Server, StaticClients};
use radius_tokio::tls::{PeerCertificate, TlsContext};
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const SECRET: &[u8] = b"secret";
const RADSEC_SECRET: &[u8] = b"radsec";
const WEB_PORT: u16 = 8080;
const RADIUS_AUTH_PORT: u16 = 1812;
const RADIUS_ACCT_PORT: u16 = 1813;
const RADSEC_PORT_DEFAULT: u16 = 2083;

struct RadsecConfig {
    client: Arc<RadiusClient>,
    expected_hostname: Option<String>,
}

struct MixedStore {
    udp: StaticClients,
    radsec: Option<RadsecConfig>,
}

impl ClientStore for MixedStore {
    fn lookup_udp(
        &self,
        src: SocketAddr,
    ) -> impl Future<Output = Option<Arc<RadiusClient>>> + Send {
        self.udp.lookup_udp(src)
    }

    fn admit_radsec(&self, _src: SocketAddr) -> impl Future<Output = bool> + Send {
        let allow = self.radsec.is_some();
        async move { allow }
    }

    fn lookup_radsec_by_cert(
        &self,
        _src: SocketAddr,
        peer: &PeerCertificate,
    ) -> impl Future<Output = Option<Arc<RadiusClient>>> + Send {
        let resolved = self
            .radsec
            .as_ref()
            .and_then(|cfg| match &cfg.expected_hostname {
                Some(name) if peer.matches_hostname(name, false) => Some(Arc::clone(&cfg.client)),
                None => Some(Arc::clone(&cfg.client)),
                _ => None,
            });
        async move { resolved }
    }
}

fn load_radsec_from_env() -> Result<Option<(RadsecConfig, TlsContext, SocketAddr)>, anyhow::Error> {
    let (Ok(cert_path), Ok(key_path), Ok(ca_path)) = (
        std::env::var("RADSEC_SERVER_CERT"),
        std::env::var("RADSEC_SERVER_KEY"),
        std::env::var("RADSEC_CLIENT_CA"),
    ) else {
        return Ok(None);
    };

    let cert_pem = std::fs::read(&cert_path)?;
    let key_pem = std::fs::read(&key_path)?;
    let ca_pem = std::fs::read(&ca_path)?;
    let tls = TlsContext::server(&cert_pem, &key_pem, &ca_pem)?;

    let port: u16 = std::env::var("RADSEC_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(RADSEC_PORT_DEFAULT);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);

    let cfg = RadsecConfig {
        client: Arc::new(RadiusClient::new(RADSEC_SECRET)),
        expected_hostname: std::env::var("RADSEC_CLIENT_NAME").ok(),
    };

    Ok(Some((cfg, tls, addr)))
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

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
    let udp = StaticClients::builder()
        .add(
            IpCidr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap(),
            Arc::clone(&shared),
        )
        .add(
            IpCidr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap(),
            shared,
        )
        .build();

    let (radsec_cfg, radsec_listener) = match load_radsec_from_env()? {
        Some((cfg, tls, addr)) => (Some(cfg), Some((tls, addr))),
        None => (None, None),
    };

    let store = MixedStore {
        udp,
        radsec: radsec_cfg,
    };

    let mut builder = Server::builder()
        .clients(store)
        .handler(handler)
        .listen_udp(format!("0.0.0.0:{}", RADIUS_AUTH_PORT).parse().unwrap())
        .listen_udp(format!("0.0.0.0:{}", RADIUS_ACCT_PORT).parse().unwrap());

    if let Some((tls, addr)) = radsec_listener {
        builder = builder.listen_radsec(addr, tls);
        info!("RadSec (RFC 6614) listening on {}", addr);
    }

    let server = builder.build().unwrap();
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
    Ok(())
}
