#[macro_use]
extern crate log;

mod audit;

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
use clickhouse::Client;
use hmac::{Hmac, Mac};
use md5::Md5;
use serde::Deserialize;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use time::OffsetDateTime;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::mpsc;

use radius::core::code::Code;
use radius::core::request::Request;
use radius::dict::{mikrotik, rfc2865, rfc2866, rfc2869};
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
    uptime: String,
    bytes_in: String,
    bytes_out: String,
    session_id: String,
}

#[derive(Template)]
#[template(path = "logout.html")]
struct LogoutTemplate {
    username: String,
    mac: String,
}

struct SessionRow {
    username: String,
    mac_address: String,
    ip_address: String,
    session_time: i64,
    bytes_in: i64,
    bytes_out: i64,
    terminate_cause: String,
}

struct SessionView {
    username: String,
    mac_address: String,
    ip_address: String,
    duration: String,
    bytes_in_fmt: String,
    bytes_out_fmt: String,
    terminate_cause: String,
}

fn format_duration(seconds: i64) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    if h > 0 {
        format!("{}h {:02}m", h, m)
    } else if m > 0 {
        format!("{}m {:02}s", m, s)
    } else {
        format!("{}s", s)
    }
}

fn format_bytes(bytes: i64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

impl SessionRow {
    fn into_view(self) -> SessionView {
        SessionView {
            username: self.username,
            mac_address: self.mac_address,
            ip_address: self.ip_address,
            duration: format_duration(self.session_time),
            bytes_in_fmt: format_bytes(self.bytes_in),
            bytes_out_fmt: format_bytes(self.bytes_out),
            terminate_cause: self.terminate_cause,
        }
    }
}

#[derive(Template)]
#[template(path = "sessions.html")]
struct SessionsTemplate {
    active_sessions: Vec<SessionView>,
    closed_sessions: Vec<SessionView>,
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
    #[serde(default)]
    uptime: Option<String>,
    #[serde(default)]
    bytes_in: Option<String>,
    #[serde(default)]
    bytes_out: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
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
        uptime: params.uptime.unwrap_or_default(),
        bytes_in: params.bytes_in.unwrap_or_default(),
        bytes_out: params.bytes_out.unwrap_or_default(),
        session_id: params.session_id.unwrap_or_default(),
    })
}

async fn get_logout(Query(params): Query<PortalParams>) -> Response {
    render(LogoutTemplate {
        username: params.username.unwrap_or_default(),
        mac: params.mac,
    })
}

async fn get_sessions(State(state): State<AppState>) -> Response {
    let active = sqlx::query_as::<_, (String, String, String, i64, i64, i64, String)>(
        "SELECT username, mac_address, ip_address, session_time, bytes_in, bytes_out, terminate_cause
         FROM sessions WHERE status = 'active' ORDER BY started_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(username, mac_address, ip_address, session_time, bytes_in, bytes_out, terminate_cause)| {
        SessionRow { username, mac_address, ip_address, session_time, bytes_in, bytes_out, terminate_cause }.into_view()
    })
    .collect();

    let closed = sqlx::query_as::<_, (String, String, String, i64, i64, i64, String)>(
        "SELECT username, mac_address, ip_address, session_time, bytes_in, bytes_out, terminate_cause
         FROM sessions WHERE status = 'closed' ORDER BY stopped_at DESC LIMIT 50",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(username, mac_address, ip_address, session_time, bytes_in, bytes_out, terminate_cause)| {
        SessionRow { username, mac_address, ip_address, session_time, bytes_in, bytes_out, terminate_cause }.into_view()
    })
    .collect();

    render(SessionsTemplate {
        active_sessions: active,
        closed_sessions: closed,
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
    audit_tx: mpsc::Sender<audit::SessionEvent>,
}

impl MyRequestHandler {
    async fn handle_access_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();

        let maybe_user_name = rfc2865::lookup_user_name(req_packet);
        let maybe_user_password = rfc2865::lookup_user_password(req_packet);

        let user_name = maybe_user_name.unwrap().unwrap();
        let user_password = String::from_utf8(maybe_user_password.unwrap().unwrap()).unwrap();

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
            code, user_name, req.remote_addr()
        );

        let response_bytes = build_response(req_packet, code);
        conn.send_to(&response_bytes, req.remote_addr()).await?;
        Ok(())
    }

    async fn handle_accounting_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();

        let status_type = rfc2866::lookup_acct_status_type(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or(0);
        let session_id = rfc2866::lookup_acct_session_id(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or_default();
        let username = rfc2865::lookup_user_name(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or_default();
        let mac = rfc2865::lookup_calling_station_id(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or_default();
        let ip = rfc2865::lookup_framed_ip_address(req_packet)
            .map(|r| r.ok().map(|addr| addr.to_string()).unwrap_or_default())
            .unwrap_or_default();
        let nas_ip = rfc2865::lookup_nas_ip_address(req_packet)
            .map(|r| r.ok().map(|addr| addr.to_string()).unwrap_or_default())
            .unwrap_or_default();
        let session_time = rfc2866::lookup_acct_session_time(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or(0);
        let bytes_in = rfc2866::lookup_acct_input_octets(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or(0);
        let bytes_out = rfc2866::lookup_acct_output_octets(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or(0);
        let cause_str: &str = match rfc2866::lookup_acct_terminate_cause(req_packet)
            .and_then(|r| r.ok())
        {
            None => "",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_USER_REQUEST) => "User-Request",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT) => "Idle-Timeout",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT) => "Session-Timeout",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_ADMIN_RESET) => "Admin-Reset",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_ADMIN_REBOOT) => "Admin-Reboot",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_NAS_REBOOT) => "NAS-Reboot",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_LOST_CARRIER) => "Lost-Carrier",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_NAS_REQUEST) => "NAS-Request",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_NAS_ERROR) => "NAS-Error",
            Some(rfc2866::ACCT_TERMINATE_CAUSE_PORT_ERROR) => "Port-Error",
            Some(_) => "Unknown",
        };

        match status_type {
            rfc2866::ACCT_STATUS_TYPE_START => {
                info!(
                    "Accounting START session='{}' user='{}' mac='{}' ip='{}'",
                    session_id, username, mac, ip
                );
                let _ = sqlx::query(
                    "INSERT INTO sessions (acct_session_id, username, mac_address, ip_address, nas_ip, started_at, status)
                     VALUES (?, ?, ?, ?, ?, datetime('now'), 'active')",
                )
                .bind(&session_id)
                .bind(&username)
                .bind(&mac)
                .bind(&ip)
                .bind(&nas_ip)
                .execute(&self.db)
                .await
                .map_err(|e| error!("accounting start db error: {}", e));
            }
            rfc2866::ACCT_STATUS_TYPE_INTERIM_UPDATE => {
                info!(
                    "Accounting INTERIM session='{}' user='{}' time={}s in={} out={}",
                    session_id, username, session_time, bytes_in, bytes_out
                );
                let _ = sqlx::query(
                    "UPDATE sessions SET session_time = ?, bytes_in = ?, bytes_out = ?
                     WHERE acct_session_id = ? AND nas_ip = ? AND status = 'active'",
                )
                .bind(session_time)
                .bind(bytes_in)
                .bind(bytes_out)
                .bind(&session_id)
                .bind(&nas_ip)
                .execute(&self.db)
                .await
                .map_err(|e| error!("accounting interim db error: {}", e));
            }
            rfc2866::ACCT_STATUS_TYPE_STOP => {
                info!(
                    "Accounting STOP session='{}' user='{}' time={}s in={} out={} cause='{}'",
                    session_id, username, session_time, bytes_in, bytes_out, cause_str
                );
                let _ = sqlx::query(
                    "UPDATE sessions SET session_time = ?, bytes_in = ?, bytes_out = ?,
                     stopped_at = datetime('now'), terminate_cause = ?, status = 'closed'
                     WHERE acct_session_id = ? AND nas_ip = ? AND status = 'active'",
                )
                .bind(session_time)
                .bind(bytes_in)
                .bind(bytes_out)
                .bind(cause_str)
                .bind(&session_id)
                .bind(&nas_ip)
                .execute(&self.db)
                .await
                .map_err(|e| error!("accounting stop db error: {}", e));
            }
            rfc2866::ACCT_STATUS_TYPE_ACCOUNTING_ON => {
                info!("Accounting ON from NAS '{}' — closing stale sessions", nas_ip);
                let _ = sqlx::query(
                    "UPDATE sessions SET stopped_at = datetime('now'), terminate_cause = 'NAS-Reboot', status = 'closed'
                     WHERE nas_ip = ? AND status = 'active'",
                )
                .bind(&nas_ip)
                .execute(&self.db)
                .await
                .map_err(|e| error!("accounting-on db error: {}", e));
            }
            rfc2866::ACCT_STATUS_TYPE_ACCOUNTING_OFF => {
                info!("Accounting OFF from NAS '{}'", nas_ip);
            }
            _ => {
                info!("Accounting unknown status_type={} session='{}'", status_type, session_id);
            }
        }

        let kind: Option<&str> = match status_type {
            rfc2866::ACCT_STATUS_TYPE_START => Some("start"),
            rfc2866::ACCT_STATUS_TYPE_INTERIM_UPDATE => Some("interim"),
            rfc2866::ACCT_STATUS_TYPE_STOP => Some("stop"),
            rfc2866::ACCT_STATUS_TYPE_ACCOUNTING_ON => Some("on"),
            rfc2866::ACCT_STATUS_TYPE_ACCOUNTING_OFF => Some("off"),
            _ => None,
        };
        if let Some(kind) = kind {
            let event = audit::SessionEvent {
                ts: OffsetDateTime::now_utc(),
                event: kind.to_string(),
                acct_session_id: session_id.clone(),
                nas_ip: audit::parse_v6(&nas_ip),
                username: username.clone(),
                mac: audit::normalize_mac(&mac),
                framed_ip: audit::parse_v6(&ip),
                session_time: session_time as u32,
                bytes_in: bytes_in as u64,
                bytes_out: bytes_out as u64,
                terminate_cause: cause_str.to_string(),
            };
            if let Err(e) = self.audit_tx.try_send(event) {
                warn!("audit channel send dropped: {}", e);
            }
        }

        // Send Accounting-Response (with Message-Authenticator for Mikrotik compatibility)
        let response_bytes = build_response(req_packet, Code::AccountingResponse);
        conn.send_to(&response_bytes, req.remote_addr()).await?;
        Ok(())
    }
}

impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();
        info!("RADIUS {:?} from {}", req_packet.code(), req.remote_addr());

        match req_packet.code() {
            Code::AccessRequest => self.handle_access_request(conn, req).await,
            Code::AccountingRequest => self.handle_accounting_request(conn, req).await,
            _ => {
                info!("ignoring unsupported RADIUS code {:?}", req_packet.code());
                Ok(())
            }
        }
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

    let app_state = AppState { db: db.clone() };

    let app = Router::new()
        .route("/login", get(get_login).post(post_login))
        .route("/register", get(get_register).post(post_register))
        .route("/welcome", get(get_welcome))
        .route("/status", get(get_status))
        .route("/logout", get(get_logout))
        .route("/sessions", get(get_sessions))
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
        MyRequestHandler {
            db: db.clone(),
            audit_tx,
        },
        MySecretProvider {},
    )
    .await
    .unwrap();
    server.set_buffer_size(1500);
    server.set_skip_authenticity_validation(false);

    info!("RADIUS server listening on 0.0.0.0:1812");

    let result = server.run(signal::ctrl_c()).await;
    info!("RADIUS shutdown: {:?}", result);

    drop(server);
    web_handle.abort();

    match tokio::time::timeout(std::time::Duration::from_secs(15), audit_handle).await {
        Ok(_) => info!("audit drain complete"),
        Err(_) => warn!("audit drain timed out; some events may be lost"),
    }

    if result.is_err() {
        process::exit(1);
    }
}
