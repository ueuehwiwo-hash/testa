use axum::{extract::{Path, State}, http::StatusCode, response::Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{args, middleware::AuthUser, models::AppState};

#[derive(Deserialize)]
pub struct SendBody { to_uid: String, text: String }

pub async fn send(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<SendBody>,
) -> (StatusCode, Json<Value>) {
    if body.to_uid.is_empty() || body.text.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Target and text required" })));
    }
    let encrypted = state.db.encrypt_message(&body.text);
    let from_uid  = auth.0.uid.clone();

    match state.db.query(
        "INSERT INTO messages (from_uid, to_uid, encrypted_text) VALUES (?, ?, ?) RETURNING id, created_at",
        args![from_uid.clone(), body.to_uid.clone(), encrypted],
    ).await {
        Ok(result) => {
            let id: i64 = result.rows.get(0)
                .and_then(|r| r.0.get(0)).map(|c| c.as_i64())
                .unwrap_or(result.last_insert_rowid);
            let created_at = result.rows.get(0)
                .and_then(|r| r.0.get(1)).map(|c| c.as_string())
                .unwrap_or_default();
            let msg = json!({
                "id": id, "from_uid": from_uid, "to_uid": body.to_uid,
                "text": body.text, "created_at": created_at, "reactions": null
            });
            if let Some(sids) = state.user_sockets.get(&body.to_uid) {
                if let Some(io) = state.io() {
                    for sid in sids.value() {
                        let _ = io.to(sid.clone()).emit("new_message", msg.clone());
                    }
                }
            }
            (StatusCode::OK, Json(msg))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))),
    }
}

pub async fn history(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(other_uid): Path<String>,
) -> (StatusCode, Json<Value>) {
    let my_uid = auth.0.uid;
    match state.db.query(
        "SELECT id, from_uid, to_uid, encrypted_text, created_at, read_at, reactions FROM (SELECT * FROM messages WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?) ORDER BY created_at DESC LIMIT 100) ORDER BY created_at ASC",
        args![my_uid.clone(), other_uid.clone(), other_uid.clone(), my_uid.clone()],
    ).await {
        Ok(result) => {
            let messages: Vec<Value> = result.rows.iter().map(|row| {
                let id         = row.0.get(0).map(|c| c.as_i64()).unwrap_or(0);
                let from_uid   = row.0.get(1).map(|c| c.as_string()).unwrap_or_default();
                let to_uid_v   = row.0.get(2).map(|c| c.as_string()).unwrap_or_default();
                let enc        = row.0.get(3).map(|c| c.as_string()).unwrap_or_default();
                let created_at = row.0.get(4).map(|c| c.as_string()).unwrap_or_default();
                let read_at    = row.0.get(5).and_then(|c| c.as_opt_string());
                let reactions_str = row.0.get(6).and_then(|c| c.as_opt_string());
                let text       = state.db.decrypt_message(&enc);
                let reactions  = reactions_str.and_then(|s| serde_json::from_str::<Value>(&s).ok());
                json!({
                    "id": id, "from_uid": from_uid, "to_uid": to_uid_v,
                    "text": text, "created_at": created_at, "read_at": read_at,
                    "reactions": reactions
                })
            }).collect();
            (StatusCode::OK, Json(Value::Array(messages)))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))),
    }
}
