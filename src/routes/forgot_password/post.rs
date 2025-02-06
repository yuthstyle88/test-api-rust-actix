use actix_web::{http::StatusCode, web, HttpResponse, ResponseError};
use anyhow::Context;
use chrono::Utc;
use log::error;
use serde::Serialize;
use sqlx::PgPool;

use crate::{authentication::compute_password_hash, utils::is_valid_email};

#[derive(serde::Deserialize)]
pub struct ForgotPasswordData {
    email: String,
    new_password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ForgotPasswordError {
    #[error("Email does not exist")]
    EmailNotFoundError,

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

impl ResponseError for ForgotPasswordError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::EmailNotFoundError | Self::InvalidEmailFormatError => StatusCode::BAD_REQUEST,
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

    Ok(
        HttpResponse::Ok()
            .json(serde_json::json!({"message": "Password updated successfully"})),
    )
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

async fn check_email_existence(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", email)
            .fetch_one(pool)
            .await?
            .unwrap_or(false),
    )
}