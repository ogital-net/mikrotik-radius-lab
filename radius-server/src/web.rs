use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use log::{error, info};
use serde::Deserialize;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/login", get(get_login).post(post_login))
        .route("/register", get(get_register).post(post_register))
        .route("/welcome", get(get_welcome))
        .route("/status", get(get_status))
        .route("/logout", get(get_logout))
        .route("/sessions", get(get_sessions))
        .with_state(state)
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
#[allow(dead_code)]
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

#[derive(Template)]
#[template(path = "sessions.html")]
struct SessionsTemplate {
    active_sessions: Vec<SessionView>,
    closed_sessions: Vec<SessionView>,
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
        Ok(Some((hash,))) => match PasswordHash::new(&hash) {
            Ok(h) => Argon2::default()
                .verify_password(form.password.as_bytes(), &h)
                .is_ok(),
            Err(_) => false,
        },
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
