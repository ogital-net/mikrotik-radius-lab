use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub clickhouse_url: String,
    pub clickhouse_user: String,
    pub clickhouse_password: String,
    pub clickhouse_db: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            listen_addr: env_or("INGESTER_LISTEN", "0.0.0.0:5140")?.parse()?,
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
