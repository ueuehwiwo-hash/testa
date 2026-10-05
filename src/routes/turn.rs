use axum::{extract::State, response::Json};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use serde_json::json;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::AppState;

type HmacSha1 = Hmac<Sha1>;

pub async fn credentials(State(_state): State<AppState>) -> Json<serde_json::Value> {
    let turn_secret = match std::env::var("TURN_SECRET") {
        Ok(s) => s,
        Err(_) => return Json(json!({ "error": "TURN service unavailable" })),
    };
    let turn_host = match std::env::var("TURN_HOST") {
        Ok(h) => h,
        Err(_) => return Json(json!({ "error": "TURN service unavailable" })),
    };

    let ttl: u64 = std::env::var("TURN_TTL").ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expiry = now + ttl;
    let username = format!("{}:guest", expiry);

    let mut mac = HmacSha1::new_from_slice(turn_secret.as_bytes()).expect("HMAC init");
    mac.update(username.as_bytes());
    let credential = B64.encode(mac.finalize().into_bytes());

    Json(json!({
        "ttl": ttl,
        "current_server_time": now,
        "expiry_timestamp": expiry,
        "username": username,
        "credential": credential,
        "urls": [
            format!("turn:{}:3478?transport=udp", turn_host),
            format!("turn:{}:3478?transport=tcp", turn_host),
            format!("turns:{}:5349?transport=tcp", turn_host)
        ]
    }))
}
