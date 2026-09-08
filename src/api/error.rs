//! Uniform API error envelope.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    Unauthorized(String),
    Locked(String),
    TooManyRequests(String),
    Forbidden(String),
    Conflict(String),
    DeviceAlreadyPaired(String),
    PayloadTooLarge(String),
    Gone(String),
    ServiceUnavailable { code: &'static str, message: String },
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::NotFound(m) => {
                let body = Json(json!({ "error": { "code": "NOT_FOUND", "message": m } }));
                (StatusCode::NOT_FOUND, body).into_response()
            }
            ApiError::BadRequest(m) => {
                let body = Json(json!({ "error": { "code": "BAD_REQUEST", "message": m } }));
                (StatusCode::BAD_REQUEST, body).into_response()
            }
            ApiError::Unauthorized(m) => {
                let body = Json(json!({ "error": { "code": "UNAUTHORIZED", "message": m } }));
                (StatusCode::UNAUTHORIZED, body).into_response()
            }
            ApiError::Locked(m) => {
                let body = Json(json!({ "error": { "code": "LOCKED", "message": m } }));
                (StatusCode::LOCKED, body).into_response()
            }
            ApiError::TooManyRequests(m) => {
                let body = Json(json!({ "error": { "code": "TOO_MANY_REQUESTS", "message": m } }));
                (StatusCode::TOO_MANY_REQUESTS, body).into_response()
            }
            ApiError::Forbidden(m) => {
                let body = Json(json!({ "error": { "code": "FORBIDDEN", "message": m } }));
                (StatusCode::FORBIDDEN, body).into_response()
            }
            ApiError::Conflict(m) => {
                let body = Json(json!({ "error": { "code": "CONFLICT", "message": m } }));
                (StatusCode::CONFLICT, body).into_response()
            }
            ApiError::DeviceAlreadyPaired(m) => {
                let body =
                    Json(json!({ "error": { "code": "DEVICE_ALREADY_PAIRED", "message": m } }));
                (StatusCode::CONFLICT, body).into_response()
            }
            ApiError::PayloadTooLarge(m) => {
                let body = Json(json!({ "error": { "code": "PAYLOAD_TOO_LARGE", "message": m } }));
                (StatusCode::PAYLOAD_TOO_LARGE, body).into_response()
            }
            ApiError::Gone(m) => {
                let body = Json(json!({ "error": { "code": "GONE", "message": m } }));
                (StatusCode::GONE, body).into_response()
            }
            ApiError::ServiceUnavailable { code, message } => {
                let body = Json(json!({ "error": { "code": code, "message": message } }));
                (StatusCode::SERVICE_UNAVAILABLE, body).into_response()
            }
            ApiError::Internal(msg) => {
                eprintln!("API Internal Error: {}", msg);
                let body = Json(json!({
                    "error": {
                        "code": "INTERNAL",
                        "message": msg
                    }
                }));
                (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
            }
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::Internal(format!("io: {}", e))
    }
}
impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::Internal(format!("json: {}", e))
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}
impl From<crate::dusage::errors::DusageError> for ApiError {
    fn from(e: crate::dusage::errors::DusageError) -> Self {
        match e {
            crate::dusage::errors::DusageError::InvalidPeriod(message) => {
                ApiError::BadRequest(message)
            }
            other => ApiError::Internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn internal_error_response_includes_the_actual_message() {
        let response =
            ApiError::Internal("parse devices.json: expected a sequence".into()).into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("parse response body");
        assert_eq!(body["error"]["code"], "INTERNAL");
        assert_eq!(
            body["error"]["message"],
            "parse devices.json: expected a sequence"
        );
    }

    #[tokio::test]
    async fn device_already_paired_response_has_dedicated_conflict_code() {
        let response =
            ApiError::DeviceAlreadyPaired("device DID is already paired".into()).into_response();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("parse response body");
        assert_eq!(body["error"]["code"], "DEVICE_ALREADY_PAIRED");
    }
}
