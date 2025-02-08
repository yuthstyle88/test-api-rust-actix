use anyhow::{Context, Error};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use sqlx::PgPool;

use crate::telemetry::spawn_blocking_with_tracing;

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials.")]
    InvalidCredentials(#[source] anyhow::Error),

    #[error("Something went wrong")]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(serde::Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

#[tracing::instrument(name = "Get stored credentials", skip(email, pool))]
async fn get_stored_credentials(
    email: &str,
    pool: &PgPool,
) -> Result<Option<(uuid::Uuid, String)>, anyhow::Error> {
    let row = sqlx::query!(
        r#"
        SELECT id, password
        FROM users
        WHERE email = $1
        "#,
        email,
    )
    .fetch_optional(pool)
    .await
    .context("Failed to performed a query to retrieve stored credentials.")?
    .map(|row| (row.id, row.password));
    Ok(row)
}

#[tracing::instrument(name = "Validate credentials", skip(credentials, pool))]
pub async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, AuthError> {
    let mut user_id = None;

    if let Some((stored_user_id, stored_password_hash)) =
        get_stored_credentials(&credentials.email, pool).await?
    {
        user_id = Some(stored_user_id);
        let is_valid = spawn_blocking_with_tracing(move || {
            verify_password_hash(stored_password_hash, credentials.password)
        })
        .await
        .map_err(|e| AuthError::UnexpectedError(anyhow::anyhow!(e)))?
        .map_err(|_| AuthError::InvalidCredentials(anyhow::anyhow!("Invalid password.")))?;

        if !is_valid {
            return Err(AuthError::InvalidCredentials(anyhow::anyhow!(
                "Invalid password."
            )));
        }
    }

    user_id.ok_or_else(|| AuthError::InvalidCredentials(anyhow::anyhow!("Unknown user.")))
}

#[tracing::instrument(
    name = "Validate credentials",
    skip(expected_password_hash, password_candidate)
)]
fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<bool, AuthError> {
    let expected_password_hash = PasswordHash::new(&expected_password_hash)
        .map_err(|e| AuthError::InvalidCredentials(anyhow::anyhow!("Failed to parse hash: {e}")))?;

    Argon2::default()
        .verify_password(password_candidate.as_bytes(), &expected_password_hash)
        .map_err(|e| AuthError::InvalidCredentials(anyhow::anyhow!("Invalid password: {e}")))?;

    Ok(true)
}

pub fn compute_password_hash(password: String) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(Error::msg)?
        .to_string();

    Ok(password_hash)
}
