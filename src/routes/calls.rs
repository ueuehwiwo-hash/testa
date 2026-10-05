use axum::{extract::State, http::StatusCode, response::Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{middleware::AuthUser, models::AppState};

#[derive(Deserialize)]
pub struct InitiateBody { target_uid: String }

pub async fn initiate(
    State(_state): State<AppState>,
    _auth: AuthUser,
    Json(body): Json<InitiateBody>,
) -> (StatusCode, Json<Value>) {
    if body.target_uid.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "target_uid required" })));
    }
    let call_id    = hex::encode(rand::random::<[u8; 16]>());
    let session_id = hex::encode(rand::random::<[u8; 12]>());
    (StatusCode::OK, Json(json!({ "callId": call_id, "sessionId": session_id })))
}
