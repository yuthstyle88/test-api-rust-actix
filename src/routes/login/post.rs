use actix_web::{http::StatusCode, web, HttpResponse, ResponseError};
use anyhow::Context;
use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    authentication::{generate_token, validate_credentials, AuthError, Credentials},
    utils::is_valid_email,
};

#[derive(serde::Deserialize, Debug)]
pub struct LoginData {
    email: String,
    password: String,
}

#[derive(thiserror::Error, Debug)]
pub enum LoginError {
    #[error("Authentication failed")]
    AuthError,

    #[error("Invalid email format")]
    InvalidEmailFormatError,

    #[error("Something went wrong")]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
    timestamp: String,
}

impl ResponseError for LoginError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::AuthError | Self::InvalidEmailFormatError => StatusCode::BAD_REQUEST,
            Self::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let response = ErrorResponse {
            message: self.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };
        HttpResponse::build(self.status_code()).json(response)
    }
}

#[derive(Serialize)]
struct Token {
    access_token: String,
    refresh_token: String,
}

#[tracing::instrument(
    skip(login_data, pool),
    fields(email=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn login(
    login_data: web::Json<LoginData>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, LoginError> {
    if !is_valid_email(&login_data.email) {
        return Err(LoginError::InvalidEmailFormatError);
    }

    let credentials = Credentials {
        email: login_data.email.clone(),
        password: login_data.password.clone(),
    };

    let user_id = validate_credentials(credentials, &pool)
        .await
        .map_err(|e| match e {
            AuthError::InvalidCredentials(_) => LoginError::AuthError,
            _ => LoginError::UnexpectedError(anyhow::anyhow!("Failed to validate credentials")),
        })?;

    let access_token = generate_token(user_id, 1).context("Failed to create access token")?;

    let token_response = Token {
        access_token,
        refresh_token: Uuid::new_v4().to_string(),
    };

    Ok(HttpResponse::Ok().json(token_response))
}
