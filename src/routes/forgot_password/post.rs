use actix_web::{http::StatusCode, web, HttpResponse, ResponseError};
use anyhow::Context;
use chrono::{Duration, Utc};
use log::error;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use rand::{distributions::Alphanumeric, Rng};
use lettre::{Message, SmtpTransport, Transport};

use crate::{authentication::compute_password_hash, utils::is_valid_email};


#[derive(serde::Deserialize)]
pub struct ForgotPasswordRequest {
    email: String,
}

#[derive(serde::Deserialize)]
pub struct ForgotPasswordData {
    email: String,
    new_password: String,
    tokens: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ForgotPasswordError {
    #[error("Email does not exist")]
    EmailNotFoundError,

    #[error("Invalid email format")]
    InvalidEmailFormatError,

    #[error("Invalid verification code")]
    InvalidVerificationCodeError,

    #[error("Something went wrong")]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
    timestamp: String,
}

impl ResponseError for ForgotPasswordError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::EmailNotFoundError | Self::InvalidEmailFormatError | Self::InvalidVerificationCodeError => StatusCode::BAD_REQUEST,
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

pub async fn request_password_reset(
    forgot_password_request: web::Json<ForgotPasswordRequest>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, ForgotPasswordError> {
    if !is_valid_email(&forgot_password_request.email) {
        return Err(ForgotPasswordError::InvalidEmailFormatError);
    }

    let user_id = get_user_id_by_email(&pool, &forgot_password_request.email).await?;

    // Generate a 6-digit random token
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    let expired_at = Utc::now() + chrono::Duration::minutes(10);

    store_reset_token(&pool, user_id, &token, expired_at).await?;
    send_email(&forgot_password_request.email, &token).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Verification code sent to your email"
    })))
}

pub async fn forgot_password(
    forgot_password_data: web::Json<ForgotPasswordData>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, ForgotPasswordError> {
    if !is_valid_email(&forgot_password_data.email) {
        return Err(ForgotPasswordError::InvalidEmailFormatError);
    }

    if !check_email_existence(&pool, &forgot_password_data.email)
        .await
        .context("Unexpected error occurs when checking email existence.")?
    {
        return Err(ForgotPasswordError::EmailNotFoundError);
    }

    let new_password_hash = compute_password_hash(forgot_password_data.new_password.clone())
        .map_err(ForgotPasswordError::UnexpectedError)?;

    update_user_password(&pool, forgot_password_data.email.clone(), new_password_hash)
        .await
        .context("Failed to update user password.")?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Password updated successfully"})))
}

async fn update_user_password(
    pool: &PgPool,
    email: String,
    new_password_hash: String,
) -> Result<(), sqlx::Error> {
    let _ = sqlx::query!(
        r#"
        UPDATE users SET password = $1 
        WHERE email = $2
        "#,
        new_password_hash,
        email
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn get_user_id_by_email(pool: &PgPool, email: &str) -> Result<uuid::Uuid, ForgotPasswordError> {
    let user_id: Option<uuid::Uuid> = sqlx::query_scalar!(
        "SELECT id FROM users WHERE email = $1",
        email
    )
    .fetch_optional(pool)
    .await
    .context("Failed to fetch user by email.")?;

    user_id.ok_or(ForgotPasswordError::EmailNotFoundError)
}

async fn store_reset_token(
    pool: &PgPool,
    user_id: uuid::Uuid,
    token: &str,
    expired_at: chrono::DateTime<Utc>,
) -> Result<(), ForgotPasswordError> {
    sqlx::query!(
        "INSERT INTO forgot_password_tokens (user_id, token, expired_at)
         VALUES ($1, $2, $3) ON CONFLICT (user_id) DO UPDATE SET token = $2, expired_at = $3",
        user_id,
        token,
        expired_at
    )
    .execute(pool)
    .await
    .context("Failed to store reset token")?;

    Ok(())
}

async fn check_email_existence(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", email)
            .fetch_one(pool)
            .await?
            .unwrap_or(false),
    )
}
