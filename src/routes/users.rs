use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{args, db::DbArg, middleware::AuthUser, models::AppState};

fn row_to_json(row: &crate::db::Row, is_online: bool) -> Value {
    let uid           = row.0.get(0).map(|c| c.as_string()).unwrap_or_default();
    let username      = row.0.get(1).map(|c| c.as_string()).unwrap_or_default();
    let first_name    = row.0.get(2).map(|c| c.as_string()).unwrap_or_default();
    let last_name     = row.0.get(3).map(|c| c.as_string()).unwrap_or_default();
    let profile_photo = row.0.get(4).and_then(|c| c.as_opt_string());
    let is_verified   = row.0.get(5).map(|c| c.as_i64()).unwrap_or(0);
    let bio           = row.0.get(6).and_then(|c| c.as_opt_string());
    let tagline       = row.0.get(7).and_then(|c| c.as_opt_string());
    let location      = row.0.get(8).and_then(|c| c.as_opt_string());
    let cover_photo   = row.0.get(9).and_then(|c| c.as_opt_string());
    let last_active   = row.0.get(10).and_then(|c| c.as_opt_string());
    json!({
        "uid": uid, "username": username, "first_name": first_name,
        "last_name": last_name, "profile_photo": profile_photo,
        "is_verified": is_verified == 1, "bio": bio, "tagline": tagline,
        "location": location, "cover_photo": cover_photo,
        "last_active": last_active, "is_online": is_online
    })
}

pub async fn get_user(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(uid): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.db.query(
        "SELECT uid, username, first_name, last_name, profile_photo, is_verified, bio, tagline, location, cover_photo, last_active FROM users WHERE uid = ? LIMIT 1",
        args![uid.clone()],
    ).await {
        Ok(r) if !r.rows.is_empty() => {
            let is_online = state.user_sockets.contains_key(&uid);
            (StatusCode::OK, Json(row_to_json(&r.rows[0], is_online)))
        }
        Ok(_)  => (StatusCode::NOT_FOUND, Json(json!({ "error": "User not found" }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))),
    }
}

#[derive(Deserialize)]
pub struct SearchQuery { q: Option<String> }

pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<SearchQuery>,
) -> (StatusCode, Json<Value>) {
    let q   = params.q.unwrap_or_default().trim().to_string();
    let uid = auth.0.uid;

    let result = if q.is_empty() {
        state.db.query(
            "SELECT uid, username, first_name, last_name, profile_photo, is_verified, bio, tagline, location, cover_photo, last_active FROM users WHERE uid != ? ORDER BY created_at DESC LIMIT 40",
            args![uid.clone()],
        ).await
    } else {
        let p = format!("%{}%", q);
        state.db.query(
            "SELECT uid, username, first_name, last_name, profile_photo, is_verified, bio, tagline, location, cover_photo, last_active FROM users WHERE (username LIKE ? OR first_name LIKE ? OR last_name LIKE ? OR uid LIKE ?) AND uid != ? LIMIT 40",
            args![p.clone(), p.clone(), p.clone(), p.clone(), uid.clone()],
        ).await
    };

    match result {
        Ok(r) => {
            let users: Vec<Value> = r.rows.iter().map(|row| {
                let row_uid = row.0.get(0).map(|c| c.as_string()).unwrap_or_default();
                let is_online = state.user_sockets.contains_key(&row_uid);
                row_to_json(row, is_online)
            }).collect();
            (StatusCode::OK, Json(Value::Array(users)))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))),
    }
}

#[derive(Deserialize)]
pub struct UpdateProfileBody {
    first_name: Option<String>, last_name: Option<String>,
    bio: Option<String>, tagline: Option<String>, location: Option<String>,
    profile_photo: Option<String>, cover_photo: Option<String>,
}

pub async fn update_profile(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateProfileBody>,
) -> (StatusCode, Json<Value>) {
    if body.profile_photo.as_ref().map(|p| p.len() > 5 * 1024 * 1024).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Profile image too large" })));
    }
    if body.cover_photo.as_ref().map(|p| p.len() > 7 * 1024 * 1024).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Cover image too large" })));
    }
    let uid = auth.0.uid.clone();
    if let Err(e) = state.db.query(
        "UPDATE users SET first_name = COALESCE(?, first_name), last_name = COALESCE(?, last_name), bio = ?, tagline = ?, location = ?, profile_photo = COALESCE(?, profile_photo), cover_photo = COALESCE(?, cover_photo) WHERE uid = ?",
        vec![
            DbArg::from(body.first_name.as_deref().map(str::trim)),
            DbArg::from(body.last_name.as_deref().map(str::trim)),
            DbArg::from(body.bio.as_deref()),
            DbArg::from(body.tagline.as_deref()),
            DbArg::from(body.location.as_deref()),
            DbArg::from(body.profile_photo.as_deref()),
            DbArg::from(body.cover_photo.as_deref()),
            DbArg::from(uid.as_str()),
        ],
    ).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })));
    }
    if let Some(io) = state.io() {
        let _ = io.emit("profile_updated", json!({ "uid": uid }));
    }
    (StatusCode::OK, Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct UpdatePhotoBody { profile_photo: Option<String> }

pub async fn update_photo(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdatePhotoBody>,
) -> (StatusCode, Json<Value>) {
    if body.profile_photo.as_ref().map(|p| p.len() > 5 * 1024 * 1024).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Image too large" })));
    }
    if let Err(e) = state.db.query(
        "UPDATE users SET profile_photo = ? WHERE uid = ?",
        args![body.profile_photo.as_deref().map(String::from).unwrap_or_default(), auth.0.uid.clone()],
    ).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })));
    }
    (StatusCode::OK, Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct AdminVerifyBody { uid: String, is_verified: bool }

pub async fn admin_verify(
    State(state): State<AppState>,
    _auth: AuthUser,
    headers: HeaderMap,
    Json(body): Json<AdminVerifyBody>,
) -> (StatusCode, Json<Value>) {
    let expected = std::env::var("ADMIN_SECRET").unwrap_or_default();
    let provided = headers.get("x-admin-secret").and_then(|v| v.to_str().ok()).unwrap_or("");
    if provided != expected {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" })));
    }
    let val = if body.is_verified { 1i64 } else { 0i64 };
    if let Err(e) = state.db.query(
        "UPDATE users SET is_verified = ? WHERE uid = ?",
        args![val, body.uid.clone()],
    ).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })));
    }
    if let Some(io) = state.io() {
        let _ = io.emit("user_verified", json!({ "uid": body.uid, "is_verified": body.is_verified }));
    }
    (StatusCode::OK, Json(json!({ "success": true })))
}
