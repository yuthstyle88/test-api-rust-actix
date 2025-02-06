use actix_web::{
    web::{self, Json},
    HttpResponse, ResponseError,
};
use anyhow::Ok;
use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    authentication::{generate_token, validate_credentials, Credentials},
    utils::is_valid_email,
};

#[derive(serde::Deserialize)]
pub struct LoginData {
    email: String,
    password: String,
}

#[derive(thiserror::Error, Debug)]
pub enum LoginError {
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),

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
    fn error_response(&self) -> HttpResponse {
        let response = ErrorResponse {
            message: self.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };
        match self {
            LoginError::InvalidEmailFormatError | LoginError::AuthError(_) => {
                HttpResponse::BadRequest().json(response)
            }
            LoginError::UnexpectedError(_) => HttpResponse::InternalServerError().json(response),
        }
    }
}

#[derive(Serialize)]
struct Token {
    access_token: String,
    refresh_token: String,
}

pub async fn login(
    login_data: Json<LoginData>,
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
        .map_err(LoginError::AuthError)?;

    let access_token = generate_token(user_id, 1).map_err(LoginError::UnexpectedError)?;

    let token_response = Token {
        access_token,
        refresh_token: Uuid::new_v4().to_string(),
    };

    Ok(HttpResponse::Ok().json(token_response))
}
