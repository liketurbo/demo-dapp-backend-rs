pub use anyhow::anyhow;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub enum AppError {
    BadRequest(anyhow::Error),
    ServerError(anyhow::Error),
    Unauthorized(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::BadRequest(e) => (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)),
            Self::ServerError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Something went wrong: {}", e),
            ),
            Self::Unauthorized(e) => (
                StatusCode::UNAUTHORIZED,
                format!("Authorization error: {}", e),
            ),
        };

        let body = Json(json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self::ServerError(err.into())
    }
}
