use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde_json::json;


static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| Client::new());

const CAPTCHA_BASE: &str = "https://captcha-generator-v1.onrender.com";

pub async fn init() -> impl IntoResponse {
    match HTTP_CLIENT.get(format!("{}/api/captcha/init", CAPTCHA_BASE)).send().await {
        Ok(r) => match r.json::<serde_json::Value>().await {
            Ok(data) => {
                let id = data["id"].as_str().unwrap_or("").to_string();
                Json(json!({
                    "id": id,
                    "image_url": format!("/api/captcha/render/{}", id)
                })).into_response()
            }
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

pub async fn render(Path(id): Path<String>) -> impl IntoResponse {
    match HTTP_CLIENT.get(format!("{}/api/captcha/render/{}", CAPTCHA_BASE, id)).send().await {
        Ok(r) if r.status().is_success() => {
            let bytes = r.bytes().await.unwrap_or_default();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "image/png")
                .header(header::CACHE_CONTROL, "no-store")
                .body(axum::body::Body::from(bytes))
                .unwrap()
        }
        Ok(r) => Response::builder()
            .status(r.status().as_u16())
            .body(axum::body::Body::from("Not Found"))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::from("Error loading image"))
            .unwrap(),
    }
}
