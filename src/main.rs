mod db;
mod middleware;
mod models;
mod routes;
mod socket;
mod utils;

use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use socketioxide::{extract::SocketRef, SocketIo};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::db::Database;
use crate::models::AppState;
use crate::socket::handler::on_connect;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "randerx=debug,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("[SERVER] Randerx Rust backend starting...");

    // ── Database ────────────────────────────────────────────────────────────
    let db = Database::new().await?;
    // Migration is non-fatal — DB calls fail gracefully at runtime with HTTP errors
    if let Err(e) = db.migrate().await {
        tracing::warn!("[DB] Migration warning (DB may be unreachable): {}", e);
    }
    let db = Arc::new(db);

    // ── App State ────────────────────────────────────────────────────────────
    let state = AppState::new(db.clone());

    // ── Socket.io ────────────────────────────────────────────────────────────
    let (socket_layer, io) = SocketIo::builder()
        .ping_interval(Duration::from_secs(5))
        .ping_timeout(Duration::from_secs(2))
        .max_payload(5 * 1024 * 1024)
        .build_layer();

    let io = Arc::new(io);

    {
        let state_c = state.clone();
        let io_c    = io.clone();
        // socketioxide 0.14: ns handler takes (SocketRef, Data<T>) or just (SocketRef,)
        // We use socketioxide::extract::State to pass our AppState
        io.ns("/", {
            let sc = state_c.clone();
            let ic = io_c.clone();
            move |socket: SocketRef| {
                let s2 = sc.clone();
                let i2 = ic.clone();
                on_connect(socket, s2, i2)
            }
        });
    }

    state.set_io(io.clone());

    // ── CORS ────────────────────────────────────────────────────────────────
    let allowed_origin = std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "*".to_string());
    let cors = if allowed_origin == "*" {
        CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any)
    } else {
        CorsLayer::new()
            .allow_origin(allowed_origin.parse::<axum::http::HeaderValue>()?)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    // ── Router ────────────────────────────────────────────────────────────────
    let app = Router::new()
        .route("/api/health",                    get(routes::health::health))
        .route("/api/db-test",                   get(routes::health::db_test))
        .route("/api/db-schema",                 get(routes::health::db_schema))
        .route("/google27d380bdf3dc690b.html",   get(routes::health::google_verify))
        .route("/api/captcha/init",              get(routes::captcha::init))
        .route("/api/captcha/render/:id",        get(routes::captcha::render))
        .route("/api/turn-credentials",          get(routes::turn::credentials))
        .route("/api/auth/register",             axum::routing::post(routes::auth::register))
        .route("/api/auth/verify-otp",           axum::routing::post(routes::auth::verify_otp))
        .route("/api/auth/login",                axum::routing::post(routes::auth::login))
        .route("/api/auth/forgot-password",      axum::routing::post(routes::auth::forgot_password))
        .route("/api/auth/verify-reset-otp",     axum::routing::post(routes::auth::verify_reset_otp))
        .route("/api/auth/reset-password",       axum::routing::post(routes::auth::reset_password))
        .route("/api/auth/me",                   get(routes::auth::me))
        .route("/api/auth/domain-rules",         get(routes::auth::domain_rules))
        .route("/api/users",                     get(routes::users::list))
        .route("/api/users/profile",             axum::routing::post(routes::users::update_profile))
        .route("/api/users/profile-photo",       axum::routing::post(routes::users::update_photo))
        .route("/api/users/verify",              axum::routing::post(routes::users::admin_verify))
        .route("/api/users/:uid",                get(routes::users::get_user))
        .route("/api/messages",                  axum::routing::post(routes::messages::send))
        .route("/api/messages/:uid",             get(routes::messages::history))
        .route("/api/calls/initiate",            axum::routing::post(routes::calls::initiate))
        .route("/",                              get(routes::health::root))
        .with_state(state)
        .layer(cors)
        .layer(socket_layer);

    let port     = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr     = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("[SERVER] Listening on {}", addr);

    // ── Keep-alive self-ping ──────────────────────────────────────────────────
    if let Ok(url) = std::env::var("RENDER_EXTERNAL_URL") {
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut interval = tokio::time::interval(Duration::from_secs(13 * 60));
            interval.tick().await;
            loop {
                interval.tick().await;
                match client.get(format!("{}/api/health", url)).send().await {
                    Ok(r)  => info!("[KEEP-ALIVE] OK status={}", r.status()),
                    Err(e) => tracing::warn!("[KEEP-ALIVE] failed: {}", e),
                }
            }
        });
    }

    axum::serve(listener, app).await?;
    Ok(())
}
