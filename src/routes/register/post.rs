use actix_web::{http::StatusCode, web, HttpResponse, ResponseError};
use anyhow::Context;
use chrono::Utc;
use log::error;
use serde::Serialize;
use sqlx::PgPool;

use crate::{authentication::compute_password_hash, utils::is_valid_email};

#[derive(serde::Deserialize)]
pub struct RegisterData {
    email: String,
    password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("Email already exists")]
    DuplicateEmailError,

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

impl ResponseError for RegisterError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::DuplicateEmailError | Self::InvalidEmailFormatError => StatusCode::BAD_REQUEST,
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

pub async fn register(
    register_data: web::Json<RegisterData>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, RegisterError> {
    let password_hash = compute_password_hash(register_data.password.clone())
        .map_err(RegisterError::UnexpectedError)?;

    if !is_valid_email(&register_data.email) {
        return Err(RegisterError::InvalidEmailFormatError);
    }

    if check_email_existence(&pool, &register_data.email)
        .await
        .context("Unexpected error occurs when check email existence.")?
    {
        return Err(RegisterError::DuplicateEmailError);
    }

    create_new_user(&pool, register_data.email.clone(), password_hash)
        .await
        .context("Failed to create new user.")?;

    Ok(
        HttpResponse::Created()
            .json(serde_json::json!({"message": "User registered successfully"})),
    )
}

async fn create_new_user(
    pool: &PgPool,
    email: String,
    password_hash: String,
) -> Result<(), sqlx::Error> {
    let _ = sqlx::query!(
        r#"
        INSERT INTO users (email, password) 
        VALUES ($1, $2)
        "#,
        email,
        password_hash
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
