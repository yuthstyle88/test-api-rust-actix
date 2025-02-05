use actix_web::{error::InternalError, web, HttpResponse};

#[derive(serde::Deserialize)]
pub struct RegisterData {
    email: String,
    password: String,
}

pub async fn register(
    register_data: web::Json<RegisterData>,
) -> Result<HttpResponse, InternalError<RegisterError>> {
    // business logic code here
    println!("{} and {}", register_data.email, register_data.password);
    Ok(HttpResponse::Created().json(serde_json::json!({"message": "User registered successfully"})))
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("Register failed")]
    RegisterError(#[source] anyhow::Error),

    #[error("Something went wrong")]
    UnexpectedError(#[from] anyhow::Error),
}
