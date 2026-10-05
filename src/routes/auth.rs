use axum::{extract::State, http::StatusCode, response::Json};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tracing::{error, info};

use crate::{
    args,
    middleware::{sign_reset_token, sign_token, AuthUser},
    models::{AppState, OtpEntry, OtpType, RegistrationData},
    utils::{send_otp_email, verify_captcha},
};

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);

fn gen_otp() -> String { format!("{:06}", rand::random::<u32>() % 900000 + 100000) }
fn gen_uid() -> String { format!("UID{}", rand::random::<u32>() % 9000000 + 1000000) }

// ─── REGISTER ────────────────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct RegisterBody {
    username: String, first_name: String, last_name: String,
    email: String, password: String,
    captcha_id: Option<String>, captcha_answer: Option<String>,
}

pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterBody>,
) -> (StatusCode, Json<Value>) {
    if body.password.len() < 6 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Password must be at least 6 characters" })));
    }
    if !regex::Regex::new(r"^[a-zA-Z0-9_]{3,20}$").unwrap().is_match(&body.username) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Username: 3-20 chars, letters/numbers/underscore only" })));
    }
    if !verify_captcha(&HTTP_CLIENT, body.captcha_id.as_deref().unwrap_or(""), body.captcha_answer.as_deref().unwrap_or("")).await {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid CAPTCHA" })));
    }

    let email    = body.email.to_lowercase().trim().to_string();
    let username = body.username.to_lowercase();

    if let Some(at) = email.find('@') {
        let domain = email[at + 1..].to_lowercase();
        match check_domain_rules(&state, &domain).await {
            Ok(false) => return (StatusCode::FORBIDDEN, Json(json!({ "error": format!("Email domain @{} is not permitted.", domain) }))),
            Err(_)    => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Internal error" }))),
            _ => {}
        }
    }

    match state.db.query(
        "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1",
        args![username.clone(), email.clone()],
    ).await {
        Ok(r) if !r.rows.is_empty() => return (StatusCode::CONFLICT, Json(json!({ "error": "Username or email is already taken" }))),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))),
        _ => {}
    }

    let pw = body.password.clone();
    let password_hash = match tokio::task::spawn_blocking(move || bcrypt::hash(&pw, 10)).await {
        Ok(Ok(h)) => h,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Hashing failed" }))),
    };

    let otp = gen_otp();
    state.otp_store.insert(email.clone(), OtpEntry {
        otp: otp.clone(), entry_type: OtpType::Register,
        expires_at: Instant::now() + Duration::from_secs(600),
        registration_data: Some(RegistrationData {
            username, first_name: body.first_name.trim().to_string(),
            last_name: body.last_name.trim().to_string(), email: email.clone(), password_hash,
        }),
    });

    let e2 = email.clone(); let o2 = otp.clone();
    tokio::spawn(async move {
        if let Err(e) = send_otp_email(&e2, &o2, "register").await {
            error!("[AUTH] Email FAILED: {}", e);
        } else { info!("[AUTH] Email sent OK"); }
    });

    (StatusCode::OK, Json(json!({ "success": true, "requireOtp": true, "message": "OTP sent to your email." })))
}

// ─── VERIFY OTP ──────────────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct VerifyOtpBody { email: String, otp: String }

pub async fn verify_otp(
    State(state): State<AppState>,
    Json(body): Json<VerifyOtpBody>,
) -> (StatusCode, Json<Value>) {
    let email = body.email.to_lowercase().trim().to_string();
    let entry = match state.otp_store.get(&email) {
        Some(e) => e.clone(),
        None    => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid or expired OTP" }))),
    };
    if entry.otp != body.otp || entry.expires_at < Instant::now() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid or expired OTP" })));
    }
    let data = match entry.registration_data {
        Some(d) => d,
        None    => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid OTP type" }))),
    };

    let uid = gen_uid();
    if let Err(e) = state.db.query(
        "INSERT INTO users (uid, username, first_name, last_name, email, password_hash) VALUES (?, ?, ?, ?, ?, ?)",
        args![uid.clone(), data.username.clone(), data.first_name.clone(), data.last_name.clone(), email.clone(), data.password_hash.clone()],
    ).await {
        let msg = e.to_string();
        return if msg.contains("UNIQUE") || msg.contains("SQLITE_CONSTRAINT") {
            (StatusCode::CONFLICT, Json(json!({ "error": "Username or email is already taken" })))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": msg })))
        };
    }

    state.otp_store.remove(&email);
    let token = sign_token(&uid, &data.username, 30);
    (StatusCode::OK, Json(json!({
        "token": token, "uid": uid, "username": data.username,
        "first_name": data.first_name, "last_name": data.last_name, "is_verified": false
    })))
}

// ─── LOGIN ────────────────────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct LoginBody { identifier: String, password: String, captcha_id: Option<String>, captcha_answer: Option<String> }

pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> (StatusCode, Json<Value>) {
    if body.identifier.is_empty() || body.password.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "All fields are required" })));
    }
    if !verify_captcha(&HTTP_CLIENT, body.captcha_id.as_deref().unwrap_or(""), body.captcha_answer.as_deref().unwrap_or("")).await {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid CAPTCHA" })));
    }

    let id = body.identifier.to_lowercase().trim().to_string();
    let result = match state.db.query(
        "SELECT uid, username, first_name, last_name, password_hash, profile_photo, is_verified FROM users WHERE email = ? OR username = ? LIMIT 1",
        args![id.clone(), id.clone()],
    ).await {
        Ok(r)  => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))),
    };

    if result.rows.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid email/username or password" })));
    }
    let row = &result.rows[0];
    let uid:     String = row.0.get(0).map(|c| c.as_string()).unwrap_or_default();
    let uname:   String = row.0.get(1).map(|c| c.as_string()).unwrap_or_default();
    let fname:   String = row.0.get(2).map(|c| c.as_string()).unwrap_or_default();
    let lname:   String = row.0.get(3).map(|c| c.as_string()).unwrap_or_default();
    let hash:    String = row.0.get(4).map(|c| c.as_string()).unwrap_or_default();
    let photo:   Option<String> = row.0.get(5).and_then(|c| c.as_opt_string());
    let is_ver:  i64    = row.0.get(6).map(|c| c.as_i64()).unwrap_or(0);

    let pw = body.password.clone();
    let valid = match tokio::task::spawn_blocking(move || bcrypt::verify(&pw, &hash)).await {
        Ok(Ok(v)) => v,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Verification error" }))),
    };
    if !valid {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid email/username or password" })));
    }

    let token = sign_token(&uid, &uname, 30);
    (StatusCode::OK, Json(json!({
        "token": token, "uid": uid, "username": uname,
        "first_name": fname, "last_name": lname,
        "profile_photo": photo, "is_verified": is_ver == 1
    })))
}

// ─── FORGOT PASSWORD ──────────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct ForgotBody { email: String }

pub async fn forgot_password(
    State(state): State<AppState>,
    Json(body): Json<ForgotBody>,
) -> (StatusCode, Json<Value>) {
    let email = body.email.to_lowercase().trim().to_string();
    let exists = state.db.query("SELECT id FROM users WHERE email = ? LIMIT 1", args![email.clone()]).await
        .map(|r| !r.rows.is_empty()).unwrap_or(false);

    if exists {
        let otp = gen_otp();
        state.otp_store.insert(email.clone(), OtpEntry {
            otp: otp.clone(), entry_type: OtpType::Reset,
            expires_at: Instant::now() + Duration::from_secs(600),
            registration_data: None,
        });
        let e2 = email.clone();
        tokio::spawn(async move {
            if let Err(e) = send_otp_email(&e2, &otp, "reset").await {
                error!("[AUTH] Reset email FAILED: {}", e);
            }
        });
    }
    (StatusCode::OK, Json(json!({ "success": true, "message": "If an account exists, an OTP will be sent." })))
}

// ─── VERIFY RESET OTP ─────────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct VerifyResetBody { email: String, otp: String }

pub async fn verify_reset_otp(
    State(state): State<AppState>,
    Json(body): Json<VerifyResetBody>,
) -> (StatusCode, Json<Value>) {
    let email = body.email.to_lowercase().trim().to_string();
    let entry = match state.otp_store.get(&email) {
        Some(e) => e.clone(),
        None    => return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid or expired OTP" }))),
    };
    if entry.otp != body.otp || entry.expires_at < Instant::now() {
        state.otp_store.remove(&email);
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "OTP expired" })));
    }
    match entry.entry_type { OtpType::Reset => {} _ => return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid or expired OTP" }))), }
    state.otp_store.remove(&email);
    (StatusCode::OK, Json(json!({ "success": true, "resetToken": sign_reset_token(&email) })))
}

// ─── RESET PASSWORD ───────────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct ResetPasswordBody { reset_token: String, #[serde(rename = "newPassword")] new_password: String }

pub async fn reset_password(
    State(state): State<AppState>,
    Json(body): Json<ResetPasswordBody>,
) -> (StatusCode, Json<Value>) {
    if body.new_password.len() < 6 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Password must be at least 6 characters" })));
    }
    let claims = match crate::middleware::verify_token(&body.reset_token) {
        Ok(c)  => c,
        Err(_) => return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Token expired or invalid." }))),
    };
    if claims.r#type.as_deref() != Some("reset") {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid token type" })));
    }
    let email = match claims.email { Some(e) => e, None => return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid token" }))) };

    let pw = body.new_password.clone();
    let hash = match tokio::task::spawn_blocking(move || bcrypt::hash(&pw, 10)).await {
        Ok(Ok(h)) => h,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Hash failed" }))),
    };

    if let Err(e) = state.db.query("UPDATE users SET password_hash = ? WHERE email = ?", args![hash, email.clone()]).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })));
    }
    (StatusCode::OK, Json(json!({ "success": true, "message": "Password updated successfully" })))
}

// ─── ME ───────────────────────────────────────────────────────────────────────
pub async fn me(State(state): State<AppState>, auth: AuthUser) -> (StatusCode, Json<Value>) {
    let result = match state.db.query(
        "SELECT uid, username, first_name, last_name, email, created_at, last_active, profile_photo, is_verified, bio, tagline, location, cover_photo FROM users WHERE uid = ? LIMIT 1",
        args![auth.0.uid.clone()],
    ).await {
        Ok(r)  => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))),
    };
    if result.rows.is_empty() {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "User not found" })));
    }
    let row = &result.rows[0];
    let uid       = row.0.get(0).map(|c| c.as_string()).unwrap_or_default();
    let is_online = state.user_sockets.contains_key(&uid);
    let is_ver    = row.0.get(8).map(|c| c.as_i64()).unwrap_or(0);
    (StatusCode::OK, Json(json!({
        "uid": uid,
        "username":      row.0.get(1).map(|c| c.as_string()).unwrap_or_default(),
        "first_name":    row.0.get(2).map(|c| c.as_string()).unwrap_or_default(),
        "last_name":     row.0.get(3).map(|c| c.as_string()).unwrap_or_default(),
        "email":         row.0.get(4).map(|c| c.as_string()).unwrap_or_default(),
        "created_at":    row.0.get(5).map(|c| c.as_string()).unwrap_or_default(),
        "last_active":   row.0.get(6).and_then(|c| c.as_opt_string()),
        "profile_photo": row.0.get(7).and_then(|c| c.as_opt_string()),
        "is_verified":   is_ver == 1,
        "bio":           row.0.get(9).and_then(|c| c.as_opt_string()),
        "tagline":       row.0.get(10).and_then(|c| c.as_opt_string()),
        "location":      row.0.get(11).and_then(|c| c.as_opt_string()),
        "cover_photo":   row.0.get(12).and_then(|c| c.as_opt_string()),
        "is_online":     is_online
    })))
}

// ─── DOMAIN RULES ─────────────────────────────────────────────────────────────
pub async fn domain_rules(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    match state.db.query("SELECT domain, rule_type FROM email_domain_rules", vec![]).await {
        Ok(r) => {
            let mut allowed = vec![]; let mut blocked = vec![];
            for row in &r.rows {
                let domain = row.0.get(0).map(|c| c.as_string()).unwrap_or_default();
                let rule   = row.0.get(1).map(|c| c.as_string()).unwrap_or_default();
                if rule == "allow" { allowed.push(domain); } else { blocked.push(domain); }
            }
            (StatusCode::OK, Json(json!({ "hasAllowRules": !allowed.is_empty(), "allowedDomains": allowed, "blockedDomains": blocked })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))),
    }
}

// ─── HELPER ───────────────────────────────────────────────────────────────────
async fn check_domain_rules(state: &AppState, domain: &str) -> anyhow::Result<bool> {
    let r = state.db.query("SELECT 1 FROM email_domain_rules WHERE rule_type = 'allow' LIMIT 1", vec![]).await?;
    if !r.rows.is_empty() {
        let r2 = state.db.query("SELECT 1 FROM email_domain_rules WHERE domain = ? AND rule_type = 'allow'", args![domain.to_string()]).await?;
        if r2.rows.is_empty() { return Ok(false); }
    }
    let r3 = state.db.query("SELECT 1 FROM email_domain_rules WHERE domain = ? AND rule_type = 'block'", args![domain.to_string()]).await?;
    if !r3.rows.is_empty() { return Ok(false); }
    Ok(true)
}
