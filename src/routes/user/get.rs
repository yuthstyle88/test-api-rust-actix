use actix_web::{web, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(thiserror::Error, Debug)]
pub enum UserError {
    #[error("Something went wrong")]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(Serialize, Deserialize)]
pub struct UserDto {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
    pub role_id: Uuid,
}

pub async fn get_user_by_id(
    id: web::Path<Uuid>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let user = sqlx::query!(
        r#"
        SELECT id, email, password, created_at, updated_at, role_id
        FROM users
        WHERE id = $1
        "#,
        id.into_inner()
    )
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?
    .map(|row| UserDto {
        id: row.id,
        email: row.email,
        password: row.password,
        created_at: row.created_at.naive_utc(),
        updated_at: row.updated_at.naive_utc(),
        role_id: row.role_id,
    });

    match user {
        Some(user) => Ok(HttpResponse::Ok().json(user)),
        None => Ok(HttpResponse::NotFound().body("User not found")),
    }
}

pub async fn get_users(pool: web::Data<PgPool>) -> Result<HttpResponse, actix_web::Error> {
    match get_all_users(pool.get_ref()).await {
        Ok(users) => Ok(HttpResponse::Ok().json(users)),
        Err(_) => Ok(HttpResponse::InternalServerError().finish()),
    }
}

async fn get_all_users(pool: &PgPool) -> Result<Vec<UserDto>, sqlx::Error> {
    let users = sqlx::query(
        r#"
        SELECT id, email, password, created_at, updated_at, role_id FROM users
        "#,
    )
    .map(|row: sqlx::postgres::PgRow| UserDto {
        id: row.get("id"),
        email: row.get("email"),
        password: row.get("password"),
        created_at: row
            .get::<chrono::DateTime<Utc>, _>("created_at")
            .naive_utc(),
        updated_at: row
            .get::<chrono::DateTime<Utc>, _>("updated_at")
            .naive_utc(),
        role_id: row.get("role_id"),
    })
    .fetch_all(pool)
    .await?;

    Ok(users)
}
