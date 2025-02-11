use actix_web::{http::StatusCode, web, HttpResponse, ResponseError};
use anyhow::Context;
use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    authentication::{generate_token, validate_credentials, AuthError, Credentials},
    routes::UserDto,
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

    let found_user = get_user_by_id(&pool, user_id)
        .await
        .context("Unexpected error")?;

    let role_name = get_role_name_by_id(&pool, found_user.unwrap().role_id)
        .await
        .context("Unexpected error")?
        .ok_or_else(|| anyhow::anyhow!("Role not found"))?;

    let access_token =
        generate_token(user_id, role_name, 1).context("Failed to create access token")?;

    let token_response = Token {
        access_token,
        refresh_token: Uuid::new_v4().to_string(),
    };

    Ok(HttpResponse::Ok().json(token_response))
}

async fn get_role_name_by_id(pool: &PgPool, id: Uuid) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query!("SELECT name FROM roles WHERE id = $1", id)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|r| r.name))
}

async fn get_user_by_id(pool: &PgPool, user_id: Uuid) -> Result<Option<UserDto>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT id, email, password, created_at, updated_at, role_id
        FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(pool)
    .await?;

    let user = row.map(|row| UserDto {
        id: row.id,
        email: row.email,
        password: row.password,
        created_at: row.created_at.naive_utc(),
        updated_at: row.updated_at.naive_utc(),
        role_id: row.role_id,
    });

    Ok(user)
}
