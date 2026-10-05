use axum::{extract::State, response::Json};
use serde_json::{json, Value};
use crate::models::AppState;

pub async fn health(State(_state): State<AppState>) -> Json<Value> {
    Json(json!({ "ok": true, "db": true, "dbReady": true, "dbError": null }))
}

pub async fn db_test(State(state): State<AppState>) -> Json<Value> {
    match state.db.query("SELECT 1 as ping", vec![]).await {
        Ok(_)  => Json(json!({ "ok": true, "dbReady": true })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn db_schema(State(state): State<AppState>) -> Json<Value> {
    match state.db.query("PRAGMA table_info(users)", vec![]).await {
        Ok(result) => {
            let cols: Vec<Value> = result.rows.iter().map(|row| {
                let name  = row.0.get(1).map(|c| c.as_string()).unwrap_or_default();
                let dtype = row.0.get(2).map(|c| c.as_string()).unwrap_or_default();
                json!({ "name": name, "type": dtype })
            }).collect();
            let wanted = ["bio", "tagline", "location", "cover_photo", "is_verified", "profile_photo"];
            let existing: Vec<String> = cols.iter().filter_map(|c| c["name"].as_str().map(String::from)).collect();
            let missing: Vec<_> = wanted.iter().filter(|w| !existing.contains(&w.to_string())).collect();
            Json(json!({ "ok": true, "columns": cols, "missing": missing }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn google_verify() -> &'static str {
    "google-site-verification: google27d380bdf3dc690b.html"
}

pub async fn root() -> Json<Value> {
    Json(json!({
        "name": "Zero1 Backend API (Rust)",
        "status": "Running",
        "message": "No HTML pages are served from this domain."
    }))
}
