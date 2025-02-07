use actix_web::{http::StatusCode, web, HttpResponse, ResponseError};
use anyhow::Context;
use chrono::{Duration, NaiveDateTime, Utc};
use lettre::{Message, SmtpTransport, Transport};
use log::error;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{authentication::compute_password_hash, utils::is_valid_email};

#[derive(Debug, serde::Deserialize)]
pub struct ForgotPasswordRequest {
    email: String,
}

#[derive(serde::Deserialize)]
pub struct ForgotPasswordData {
    email: String,
    new_password: String,
    token: String,
}

#[derive(Debug)]
pub enum StoreResetTokenResponse {
    TokenStillValid,
    TokenCreated,
}

#[derive(Debug, thiserror::Error)]
pub enum ForgotPasswordError {
    #[error("Email does not exist")]
    EmailNotFoundError,

    #[error("Invalid email format")]
    InvalidEmailFormatError,

    #[error("Invalid verification code")]
    InvalidVerificationCodeError,

    #[error("Database error, {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Token error, {0}")]
    TokenStillValid(String),

    #[error("Token storage failed, {0}")]
    StoreTokenFailed(String),

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
            Self::EmailNotFoundError
            | Self::InvalidEmailFormatError
            | Self::InvalidVerificationCodeError => StatusCode::BAD_REQUEST,

            Self::DatabaseError(_) | Self::StoreTokenFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,

            Self::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TokenStillValid(_) => StatusCode::TOO_MANY_REQUESTS,
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
    if (!is_valid_email(&forgot_password_request.email)) {
        return Err(ForgotPasswordError::InvalidEmailFormatError);
    }
    println!("Email is valid");
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    let expired_at = Utc::now() + chrono::Duration::minutes(1);

    store_reset_token(&pool, &forgot_password_request.email, &token, expired_at).await?;
    println!("Token stored");
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Verification code sent to your email",
        "reset-token": token
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
        .context("Email is not found.")?
    {
        return Err(ForgotPasswordError::EmailNotFoundError);
    }

    verify_reset_token(
        &pool,
        &forgot_password_data.email,
        &forgot_password_data.token,
    )
    .await?;

    let new_password_hash = compute_password_hash(forgot_password_data.new_password.clone())
        .map_err(ForgotPasswordError::UnexpectedError)?;

    update_user_password(&pool, forgot_password_data.email.clone(), new_password_hash)
        .await
        .context("Failed while updating your password.")?;

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

async fn store_reset_token(
    pool: &PgPool,
    email: &str,
    token: &str,
    expired_at: chrono::DateTime<Utc>,
) -> Result<StoreResetTokenResponse, ForgotPasswordError> {
    let expired_at_naive = expired_at.naive_utc();

    let existing_token = sqlx::query!(
        "SELECT expired_at FROM forgot_password_tokens WHERE email = $1 ORDER BY expired_at DESC LIMIT 1",
        email
    )
    .fetch_optional(pool)
    .await
    .context("Failed to check for existing reset token")?;

    if let Some(record) = existing_token {
        if let Some(existing_expired_at) = record.expired_at {
            let current_time = Utc::now().naive_utc();
            let current_time_epoch = current_time.timestamp();
            let existing_expired_at_epoch = existing_expired_at.timestamp();

            println!(
                "Current time: {:?}, Existing expired at: {:?}",
                current_time_epoch, existing_expired_at_epoch
            );

            if existing_expired_at_epoch > current_time_epoch {
                println!("Token exists and has not expired. No new token will be created.");
                return Err(ForgotPasswordError::TokenStillValid(
                    "We have sent your token, please wait for 60 seconds.".to_string(),
                ));
            }
        }
        println!("Token exists but has expired, a new one will be created.");
    } else {
        println!("No existing token found, creating a new one.");
    }

    println!("Inserting new token now...");
    sqlx::query!(
        "INSERT INTO forgot_password_tokens (email, token, expired_at)
         VALUES ($1, $2, $3)",
        email,
        token,
        expired_at_naive
    )
    .execute(pool)
    .await
    .context("Failed to insert reset token")?;

    println!("New token created");
    Ok(StoreResetTokenResponse::TokenCreated)
}

async fn check_email_existence(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", email)
            .fetch_one(pool)
            .await?
            .unwrap_or(false),
    )
}

async fn verify_reset_token(
    pool: &PgPool,
    email: &str,
    token: &str,
) -> Result<(), ForgotPasswordError> {
    let record = sqlx::query!(
        "SELECT expired_at FROM forgot_password_tokens WHERE email = $1 AND token = $2",
        email,
        token
    )
    .fetch_optional(pool)
    .await
    .context("Failed to verify reset token")?;

    match record {
        Some(record) => {
            if let Some(expired_at) = record.expired_at {
                if expired_at < Utc::now().naive_utc() {
                    return Err(ForgotPasswordError::InvalidVerificationCodeError);
                }
                Ok(())
            } else {
                Err(ForgotPasswordError::InvalidVerificationCodeError)
            }
        }
        None => Err(ForgotPasswordError::InvalidVerificationCodeError),
    }
}
