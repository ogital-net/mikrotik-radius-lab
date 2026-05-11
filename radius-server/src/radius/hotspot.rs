use super::{first_text, mikrotik_attrs};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use log::info;
use radius_tokio::auth::pap;
use radius_tokio::dict::generated::rfc::attrs;
use radius_tokio::server::{HandlerResult, Request};
use radius_tokio::Code;
use sqlx::SqlitePool;

pub async fn handle(request: &Request<'_>, db: &SqlitePool) -> HandlerResult {
    let user_name = match first_text(request, attrs::USER_NAME) {
        Some(s) => s,
        None => {
            info!(
                "hotspot Access-Request without User-Name from {}; rejecting",
                request.src()
            );
            return HandlerResult::Reply(request.reply(Code::ACCESS_REJECT));
        }
    };

    let user_password = match pap::decrypt_user_password(request) {
        Ok(Some(bytes)) => match std::str::from_utf8(bytes.as_bytes()) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                info!("hotspot Access-Request with non-UTF8 User-Password; rejecting");
                return HandlerResult::Reply(request.reply(Code::ACCESS_REJECT));
            }
        },
        Ok(None) => {
            info!("hotspot Access-Request without User-Password; rejecting");
            return HandlerResult::Reply(request.reply(Code::ACCESS_REJECT));
        }
        Err(_) => {
            info!("hotspot Access-Request with malformed User-Password; rejecting");
            return HandlerResult::Reply(request.reply(Code::ACCESS_REJECT));
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
                        Code::ACCESS_ACCEPT
                    } else {
                        Code::ACCESS_REJECT
                    }
                }
                Err(_) => Code::ACCESS_REJECT,
            },
            _ => Code::ACCESS_REJECT,
        };

    info!(
        "RADIUS => {:?} for user '{}' to {}",
        code,
        user_name,
        request.src()
    );

    let mut reply = request.reply(code);
    if code == Code::ACCESS_ACCEPT {
        let _ = reply.add_vsa(mikrotik_attrs::MIKROTIK_RATE_LIMIT, "10M/10M");
    }
    HandlerResult::Reply(reply)
}
