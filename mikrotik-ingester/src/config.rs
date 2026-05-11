use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub ipfix_listen_addr: SocketAddr,
    pub ipfix_enabled: bool,
    pub default_sampling_interval: u32,
    pub clickhouse_url: String,
    pub clickhouse_user: String,
    pub clickhouse_password: String,
    pub clickhouse_db: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            listen_addr: env_or("INGESTER_LISTEN", "0.0.0.0:5140")?.parse()?,
            ipfix_listen_addr: env_or("INGESTER_IPFIX_LISTEN", "0.0.0.0:4739")?.parse()?,
            ipfix_enabled: env_or("INGESTER_IPFIX_ENABLED", "true")?.eq_ignore_ascii_case("true"),
            default_sampling_interval: env_or("INGESTER_IPFIX_SAMPLING", "100")?.parse()?,
            clickhouse_url: env_or("CLICKHOUSE_URL", "http://localhost:8123")?,
            clickhouse_user: env_or("CLICKHOUSE_USER", "ingester")?,
            clickhouse_password: env_or("CLICKHOUSE_PASSWORD", "ingester")?,
            clickhouse_db: env_or("CLICKHOUSE_DB", "mikrotik")?,
        })
    }
}

fn env_or(key: &str, default: &str) -> anyhow::Result<String> {
    Ok(std::env::var(key).unwrap_or_else(|_| default.to_string()))
}
