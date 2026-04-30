use super::response;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use log::info;
use radius::{
    core::{code::Code, request::Request},
    dict::{mikrotik, rfc2865},
};
use sqlx::SqlitePool;
use std::io;
use tokio::net::UdpSocket;

pub async fn handle(conn: &UdpSocket, req: &Request, db: &SqlitePool) -> Result<(), io::Error> {
    let req_packet = req.packet();

    let user_name = match rfc2865::lookup_user_name(req_packet).and_then(|r| r.ok()) {
        Some(s) => s,
        None => {
            info!(
                "hotspot Access-Request without User-Name from {}; rejecting",
                req.remote_addr()
            );
            let bytes = response::encode(req_packet, Code::AccessReject);
            conn.send_to(&bytes, req.remote_addr()).await?;
            return Ok(());
        }
    };
    let user_password = match rfc2865::lookup_user_password(req_packet).and_then(|r| r.ok()) {
        Some(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                info!("hotspot Access-Request with non-UTF8 User-Password; rejecting");
                let bytes = response::encode(req_packet, Code::AccessReject);
                conn.send_to(&bytes, req.remote_addr()).await?;
                return Ok(());
            }
        },
        None => {
            info!("hotspot Access-Request without User-Password; rejecting");
            let bytes = response::encode(req_packet, Code::AccessReject);
            conn.send_to(&bytes, req.remote_addr()).await?;
            return Ok(());
        }
    };

    let code =
        match sqlx::query_as::<_, (String,)>("SELECT password_hash FROM users WHERE username = ?")
            .bind(&user_name)
            .fetch_optional(db)
            .await
        {
            Ok(Some((hash,))) => match PasswordHash::new(&hash) {
                Ok(h) => {
                    if Argon2::default()
                        .verify_password(user_password.as_bytes(), &h)
                        .is_ok()
                    {
                        Code::AccessAccept
                    } else {
                        Code::AccessReject
                    }
                }
                Err(_) => Code::AccessReject,
            },
            _ => Code::AccessReject,
        };

    info!(
        "RADIUS => {:?} for user '{}' to {}",
        code,
        user_name,
        req.remote_addr()
    );

    let mut resp = response::make(req_packet, code);
    if code == Code::AccessAccept {
        mikrotik::add_mikrotik_rate_limit(&mut resp, "10M/10M");
    }
    let bytes = response::finalize(resp, req_packet.authenticator());
    conn.send_to(&bytes, req.remote_addr()).await?;
    Ok(())
}
