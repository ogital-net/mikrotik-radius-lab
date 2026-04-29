use anyhow::{Context, Result, bail};
use clickhouse::Client;
use tracing::{info, warn};

struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "init",
    sql: include_str!("../migrations/V001__init.sql"),
}];

pub async fn run(client: &Client) -> Result<()> {
    client
        .query(
            "CREATE TABLE IF NOT EXISTS _schema_migrations (
                version UInt32,
                name    String,
                applied DateTime DEFAULT now()
            ) ENGINE = MergeTree ORDER BY version",
        )
        .execute()
        .await
        .context("creating _schema_migrations")?;

    let applied: Vec<u32> = client
        .query("SELECT version FROM _schema_migrations ORDER BY version")
        .fetch_all()
        .await
        .context("reading _schema_migrations")?;

    for m in MIGRATIONS {
        if applied.contains(&m.version) {
            continue;
        }
        info!(version = m.version, name = m.name, "applying migration");
        for stmt in split_statements(m.sql) {
            if stmt.trim().is_empty() {
                continue;
            }
            client.query(stmt).execute().await.with_context(|| {
                format!("V{:03} {}: failing statement: {}", m.version, m.name, stmt)
            })?;
        }
        client
            .query("INSERT INTO _schema_migrations (version, name) VALUES (?, ?)")
            .bind(m.version)
            .bind(m.name)
            .execute()
            .await
            .context("recording migration")?;
    }

    let last: Option<u32> = MIGRATIONS.iter().map(|m| m.version).max();
    let mut prev = 0u32;
    for m in MIGRATIONS {
        if m.version <= prev {
            bail!("migrations not strictly increasing at V{:03}", m.version);
        }
        prev = m.version;
    }
    if let Some(v) = last {
        if applied.iter().any(|a| *a > v) {
            warn!("database has migrations newer than this binary knows about");
        }
    }
    Ok(())
}

fn split_statements(sql: &str) -> impl Iterator<Item = &str> {
    sql.split(';').map(str::trim).filter(|s| !s.is_empty())
}
