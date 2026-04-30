use std::net::Ipv4Addr;

use sqlx::SqlitePool;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SubscriberLine {
    pub circuit_id: String,
    pub plan: String,
    pub fixed_ip: Option<String>,
    pub pool_name: Option<String>,
    pub rate_limit: Option<String>,
    pub session_timeout: i64,
    pub status: String,
}

#[derive(Debug)]
pub enum Authorization {
    Accept {
        addressing: Addressing,
        rate_limit: Option<String>,
        session_timeout: u32,
        plan: String,
    },
    WalledGarden {
        pool: String,
        session_timeout: u32,
        plan: String,
    },
    Reject(RejectReason),
}

#[derive(Debug)]
pub enum Addressing {
    FixedIp(Ipv4Addr),
    Pool(String),
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum RejectReason {
    UnknownCircuit,
    DataError(&'static str),
    InvalidFixedIp(String),
}

pub async fn authorize(db: &SqlitePool, circuit_id: &str) -> Authorization {
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            i64,
            String,
        ),
    >(
        "SELECT circuit_id, plan, fixed_ip, pool_name, rate_limit, session_timeout, status
         FROM subscriber_lines WHERE circuit_id = ?",
    )
    .bind(circuit_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    let line = match row {
        Some((circuit_id, plan, fixed_ip, pool_name, rate_limit, session_timeout, status)) => {
            SubscriberLine {
                circuit_id,
                plan,
                fixed_ip,
                pool_name,
                rate_limit,
                session_timeout,
                status,
            }
        }
        None => return Authorization::Reject(RejectReason::UnknownCircuit),
    };

    if line.status == "suspended" {
        return Authorization::WalledGarden {
            pool: "walled-garden".to_string(),
            session_timeout: line.session_timeout as u32,
            plan: line.plan,
        };
    }

    let addressing = match (&line.fixed_ip, &line.pool_name) {
        (Some(ip), None) => match ip.parse::<Ipv4Addr>() {
            Ok(addr) => Addressing::FixedIp(addr),
            Err(_) => return Authorization::Reject(RejectReason::InvalidFixedIp(ip.clone())),
        },
        (None, Some(pool)) => Addressing::Pool(pool.clone()),
        (None, None) => {
            return Authorization::Reject(RejectReason::DataError(
                "subscriber_lines row has neither fixed_ip nor pool_name",
            ));
        }
        (Some(_), Some(_)) => {
            return Authorization::Reject(RejectReason::DataError(
                "subscriber_lines row has both fixed_ip and pool_name; exactly one must be set",
            ));
        }
    };

    Authorization::Accept {
        addressing,
        rate_limit: line.rate_limit,
        session_timeout: line.session_timeout as u32,
        plan: line.plan,
    }
}
