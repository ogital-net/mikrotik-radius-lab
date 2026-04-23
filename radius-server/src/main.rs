#[macro_use]
extern crate log;

use std::net::SocketAddr;
use std::{io, process};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use hmac::{Hmac, Mac};
use md5::Md5;
use serde::Deserialize;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use tokio::net::UdpSocket;
use tokio::signal;

use radius::core::code::Code;
use radius::core::request::Request;
use radius::dict::{mikrotik, rfc2865, rfc2869};
use radius::server::{RequestHandler, SecretProvider, SecretProviderError, Server};

const RADIUS_SECRET: &[u8] = b"secret";
const WEB_PORT: u16 = 8080;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    link_login: String,
    link_orig: String,
    mac: String,
    ip: String,
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    error: Option<String>,
    link_login: String,
    link_orig: String,
    mac: String,
    ip: String,
}

#[derive(Template)]
#[template(path = "welcome.html")]
struct WelcomeTemplate {
    username: String,
    mac: String,
    ip: String,
    link_orig: String,
}

#[derive(Template)]
#[template(path = "status.html")]
struct StatusTemplate {
    username: String,
    mac: String,
    ip: String,
    connected_since: String,
}

#[derive(Template)]
#[template(path = "logout.html")]
struct LogoutTemplate {
    username: String,
    mac: String,
}

#[derive(Deserialize)]
struct PortalParams {
    #[serde(default)]
    link_login: String,
    #[serde(default)]
    link_orig: String,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    #[serde(default)]
    link_login: String,
    #[serde(default)]
    link_orig: String,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    ip: String,
}

#[derive(Deserialize)]
struct RegisterForm {
    username: String,
    email: String,
    password: String,
    password_confirm: String,
    #[serde(default)]
    link_login: String,
    #[serde(default)]
    link_orig: String,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    ip: String,
}

fn render(tmpl: impl Template) -> Response {
    match tmpl.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("template render error: {}", e);
            Html(format!("<h1>Internal Error</h1><p>{}</p>", e)).into_response()
        }
    }
}

async fn get_login(Query(params): Query<PortalParams>) -> Response {
    render(LoginTemplate {
        error: params.error,
        link_login: params.link_login,
        link_orig: params.link_orig,
        mac: params.mac,
        ip: params.ip,
    })
}

async fn post_login(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let row = sqlx::query_as::<_, (String,)>("SELECT password_hash FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(&state.db)
        .await;

    let authenticated = match row {
        Ok(Some((hash,))) => {
            let parsed = PasswordHash::new(&hash);
            match parsed {
                Ok(h) => Argon2::default()
                    .verify_password(form.password.as_bytes(), &h)
                    .is_ok(),
                Err(_) => false,
            }
        }
        _ => false,
    };

    if !authenticated {
        let params = format!(
            "/login?error={}&link_login={}&link_orig={}&mac={}&ip={}",
            urlencoding::encode("Invalid username or password"),
            urlencoding::encode(&form.link_login),
            urlencoding::encode(&form.link_orig),
            urlencoding::encode(&form.mac),
            urlencoding::encode(&form.ip),
        );
        return Redirect::to(&params).into_response();
    }

    info!("web login OK for user '{}' from {}", form.username, form.ip);

    // If we have a MikroTik link-login, redirect back to complete hotspot auth
    if !form.link_login.is_empty() {
        let mikrotik_url = format!(
            "{}?username={}&password={}&dst={}",
            form.link_login,
            urlencoding::encode(&form.username),
            urlencoding::encode(&form.password),
            urlencoding::encode(&form.link_orig),
        );
        return Redirect::to(&mikrotik_url).into_response();
    }

    // No MikroTik context — just show welcome
    let params = format!(
        "/welcome?username={}&mac={}&ip={}&link_orig={}",
        urlencoding::encode(&form.username),
        urlencoding::encode(&form.mac),
        urlencoding::encode(&form.ip),
        urlencoding::encode(&form.link_orig),
    );
    Redirect::to(&params).into_response()
}

async fn get_register(Query(params): Query<PortalParams>) -> Response {
    render(RegisterTemplate {
        error: params.error,
        link_login: params.link_login,
        link_orig: params.link_orig,
        mac: params.mac,
        ip: params.ip,
    })
}

async fn post_register(State(state): State<AppState>, Form(form): Form<RegisterForm>) -> Response {
    // Validation
    if form.username.is_empty() || form.password.is_empty() {
        return redirect_register_error(
            "Username and password are required",
            &form.link_login,
            &form.link_orig,
            &form.mac,
            &form.ip,
        );
    }
    if form.password != form.password_confirm {
        return redirect_register_error(
            "Passwords do not match",
            &form.link_login,
            &form.link_orig,
            &form.mac,
            &form.ip,
        );
    }
    if form.password.len() < 4 {
        return redirect_register_error(
            "Password must be at least 4 characters",
            &form.link_login,
            &form.link_orig,
            &form.mac,
            &form.ip,
        );
    }

    // Check if user exists
    let exists = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    if exists > 0 {
        return redirect_register_error(
            "Username already taken",
            &form.link_login,
            &form.link_orig,
            &form.mac,
            &form.ip,
        );
    }

    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match Argon2::default().hash_password(form.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            error!("password hash error: {}", e);
            return redirect_register_error(
                "Internal error",
                &form.link_login,
                &form.link_orig,
                &form.mac,
                &form.ip,
            );
        }
    };

    // Insert user
    let result = sqlx::query("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)")
        .bind(&form.username)
        .bind(&form.email)
        .bind(&password_hash)
        .execute(&state.db)
        .await;

    if let Err(e) = result {
        error!("db insert error: {}", e);
        return redirect_register_error(
            "Could not create account",
            &form.link_login,
            &form.link_orig,
            &form.mac,
            &form.ip,
        );
    }

    info!("registered new user '{}'", form.username);

    // Redirect to login with their context preserved
    let params = format!(
        "/login?link_login={}&link_orig={}&mac={}&ip={}",
        urlencoding::encode(&form.link_login),
        urlencoding::encode(&form.link_orig),
        urlencoding::encode(&form.mac),
        urlencoding::encode(&form.ip),
    );
    Redirect::to(&params).into_response()
}

fn redirect_register_error(
    msg: &str,
    link_login: &str,
    link_orig: &str,
    mac: &str,
    ip: &str,
) -> Response {
    let params = format!(
        "/register?error={}&link_login={}&link_orig={}&mac={}&ip={}",
        urlencoding::encode(msg),
        urlencoding::encode(link_login),
        urlencoding::encode(link_orig),
        urlencoding::encode(mac),
        urlencoding::encode(ip),
    );
    Redirect::to(&params).into_response()
}

async fn get_welcome(Query(params): Query<PortalParams>) -> Response {
    render(WelcomeTemplate {
        username: params.username.unwrap_or_default(),
        mac: params.mac,
        ip: params.ip,
        link_orig: params.link_orig,
    })
}

async fn get_status(Query(params): Query<PortalParams>) -> Response {
    render(StatusTemplate {
        username: params.username.unwrap_or_default(),
        mac: params.mac,
        ip: params.ip,
        connected_since: "just now".to_string(),
    })
}

async fn get_logout(Query(params): Query<PortalParams>) -> Response {
    render(LogoutTemplate {
        username: params.username.unwrap_or_default(),
        mac: params.mac,
    })
}

async fn init_db(db: &SqlitePool) {
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

    info!("database initialized");
}

/// Build a RADIUS response with a correct Message-Authenticator (HMAC-MD5).
fn build_response(req_packet: &radius::core::packet::Packet, code: Code) -> Vec<u8> {
    let req_auth = req_packet.authenticator();

    let mut resp = req_packet.make_response_packet(code);

    if code == Code::AccessAccept {
        mikrotik::add_mikrotik_rate_limit(&mut resp, "10M/10M");
    }

    // Add zeroed Message-Authenticator placeholder for HMAC computation
    rfc2869::add_message_authenticator(&mut resp, &[0u8; 16]);

    // First encode: serialize with zeroed MA to compute HMAC-MD5
    let mut tmp = resp.encode().unwrap();
    tmp[4..20].copy_from_slice(req_auth); // HMAC uses Request Authenticator
    let mut mac = Hmac::<Md5>::new_from_slice(RADIUS_SECRET).unwrap();
    mac.update(&tmp);
    let hmac_result = mac.finalize().into_bytes();

    // Replace zeroed MA with computed HMAC, then re-encode for correct Response Authenticator
    rfc2869::delete_message_authenticator(&mut resp);
    rfc2869::add_message_authenticator(&mut resp, &hmac_result);
    resp.encode().unwrap()
}

struct MyRequestHandler {
    db: SqlitePool,
}

impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();
        info!("RADIUS request from {}", req.remote_addr());

        let maybe_user_name = rfc2865::lookup_user_name(req_packet);
        let maybe_user_password = rfc2865::lookup_user_password(req_packet);

        let user_name = maybe_user_name.unwrap().unwrap();
        let user_password = String::from_utf8(maybe_user_password.unwrap().unwrap()).unwrap();

        // Authenticate against SQLite database
        let code = match sqlx::query_as::<_, (String,)>(
            "SELECT password_hash FROM users WHERE username = ?",
        )
        .bind(&user_name)
        .fetch_optional(&self.db)
        .await
        {
            Ok(Some((hash,))) => {
                let parsed = PasswordHash::new(&hash);
                match parsed {
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
                }
            }
            _ => Code::AccessReject,
        };

        info!(
            "RADIUS => {:?} for user '{}' to {}",
            code,
            user_name,
            req.remote_addr()
        );

        let response_bytes = build_response(req_packet, code);
        conn.send_to(&response_bytes, req.remote_addr()).await?;
        Ok(())
    }
}

struct MySecretProvider {}

impl SecretProvider for MySecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        Ok(RADIUS_SECRET.to_vec())
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite:latigo.db?mode=rwc")
        .await
        .expect("failed to connect to database");

    init_db(&db).await;

    let app_state = AppState { db: db.clone() };

    let app = Router::new()
        .route("/login", get(get_login).post(post_login))
        .route("/register", get(get_register).post(post_register))
        .route("/welcome", get(get_welcome))
        .route("/status", get(get_status))
        .route("/logout", get(get_logout))
        .with_state(app_state);

    let web_addr = format!("0.0.0.0:{}", WEB_PORT);
    let listener = tokio::net::TcpListener::bind(&web_addr).await.unwrap();
    info!("web server listening on {}", web_addr);

    let web_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut server = Server::listen(
        "0.0.0.0",
        1812,
        MyRequestHandler { db: db.clone() },
        MySecretProvider {},
    )
    .await
    .unwrap();
    server.set_buffer_size(1500);
    server.set_skip_authenticity_validation(false);

    info!("RADIUS server listening on 0.0.0.0:1812");

    let result = server.run(signal::ctrl_c()).await;
    info!("RADIUS shutdown: {:?}", result);

    web_handle.abort();

    if result.is_err() {
        process::exit(1);
    }
}
