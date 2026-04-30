use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

pub async fn connect(url: &str) -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await
        .expect("failed to connect to database");
    init(&pool).await;
    pool
}

async fn init(db: &SqlitePool) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(db)
    .await
    .expect("failed to create users table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            acct_session_id TEXT NOT NULL,
            username TEXT NOT NULL,
            mac_address TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            nas_ip TEXT DEFAULT '',
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            stopped_at DATETIME,
            session_time INTEGER DEFAULT 0,
            bytes_in INTEGER DEFAULT 0,
            bytes_out INTEGER DEFAULT 0,
            terminate_cause TEXT DEFAULT '',
            status TEXT DEFAULT 'active'
        )",
    )
    .execute(db)
    .await
    .expect("failed to create sessions table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS subscriber_lines (
            circuit_id        TEXT PRIMARY KEY,
            plan              TEXT NOT NULL,
            fixed_ip          TEXT,
            pool_name         TEXT,
            rate_limit        TEXT,
            session_timeout   INTEGER NOT NULL DEFAULT 3600,
            status            TEXT NOT NULL DEFAULT 'active',
            created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes             TEXT
        )",
    )
    .execute(db)
    .await
    .expect("failed to create subscriber_lines table");

    let seeded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscriber_lines")
        .fetch_one(db)
        .await
        .unwrap_or(0);
    if seeded == 0 {
        sqlx::query(
            "INSERT INTO subscriber_lines
             (circuit_id, plan, fixed_ip, pool_name, rate_limit, session_timeout, status, notes)
             VALUES
             (?, ?, ?, NULL, ?, ?, 'active', ?),
             (?, ?, NULL, ?, ?, ?, 'active', ?)",
        )
        .bind("ether2")
        .bind("100mbps-static")
        .bind("192.168.50.10")
        .bind("100M/100M")
        .bind(3600_i64)
        .bind("Lab line A — fixed-IP. circuit_id is the bridge default (ingress port name) since RouterOS 7.21.4 has no per-port dhcp-snooping-circuit-id property to override it.")
        .bind("ether3")
        .bind("50mbps-pool")
        .bind("lab-pool-50")
        .bind("50M/50M")
        .bind(3600_i64)
        .bind("Lab line B — pool. Same Circuit-Id-from-port-name caveat as line A.")
        .execute(db)
        .await
        .expect("failed to seed subscriber_lines");
    }

    log::info!("database initialized");
}
