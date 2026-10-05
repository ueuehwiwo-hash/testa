use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response, Json},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub uid: String,
    pub username: String,
    pub exp: usize,
    /// Only present in reset tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

pub fn jwt_secret() -> String {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        format!("chet_secret_change_in_prod_{}", hex::encode(rand::random::<[u8; 8]>()))
    })
}

pub fn verify_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = jwt_secret();
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let data = decode::<Claims>(token, &key, &validation)?;
    Ok(data.claims)
}

pub fn sign_token(uid: &str, username: &str, days: u64) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + days * 86400;
    let claims = Claims {
        uid: uid.to_string(),
        username: username.to_string(),
        exp: exp as usize,
        email: None,
        r#type: None,
    };
    let secret = jwt_secret();
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .expect("JWT sign failed")
}

pub fn sign_reset_token(email: &str) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + 15 * 60; // 15 minutes
    let claims = Claims {
        uid: String::new(),
        username: String::new(),
        exp: exp as usize,
        email: Some(email.to_string()),
        r#type: Some("reset".to_string()),
    };
    let secret = jwt_secret();
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .expect("JWT reset sign failed")
}

/// Axum extractor — pulls JWT from Authorization: Bearer <token>
#[derive(Clone, Debug)]
pub struct AuthUser(pub Claims);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !auth_header.starts_with("Bearer ") {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Authentication required" })),
            ).into_response());
        }

        let token = &auth_header[7..];
        match verify_token(token) {
            Ok(claims) => Ok(AuthUser(claims)),
            Err(_) => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid or expired token" })),
            ).into_response()),
        }
    }
}
