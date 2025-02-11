use std::net::TcpListener;

use actix_web::{
    dev::Server,
    web::{self, Data},
    App, HttpServer,
};
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::{
    authentication::JwtMiddleware,
    configuration::{DatabaseSettings, Settings},
    routes::{get_user_by_id, get_users, login, register},
};

pub struct Application {
    port: u16,
    server: Server,
}

impl Application {
    pub async fn build(configuration: Settings) -> Result<Self, anyhow::Error> {
        let connection_pool =
            get_connection_pool(&configuration.database).expect("Failed to connect to Postgres.");

        let address = format!(
            "{}:{}",
            configuration.application.host, configuration.application.port
        );
        let listener = TcpListener::bind(address)?;
        let port = listener.local_addr().unwrap().port();
        let server = run(
            listener,
            connection_pool,
            configuration.application.base_url,
        )
        .await?;

        Ok(Self { port, server })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        self.server.await
    }
}

pub fn get_connection_pool(configuration: &DatabaseSettings) -> Result<PgPool, anyhow::Error> {
    Ok(PgPoolOptions::new().connect_lazy_with(configuration.connect_options()))
}

pub struct ApplicationBaseUrl(pub String);

pub async fn run(
    listener: TcpListener,
    db_pool: PgPool,
    base_url: String,
) -> Result<Server, anyhow::Error> {
    let db_pool = Data::new(db_pool);
    let base_url = Data::new(ApplicationBaseUrl(base_url));
    let server = HttpServer::new(move || {
        App::new()
            .service(
                web::scope("/api/v1")
                    .route("/register", web::post().to(register))
                    .route("/login", web::post().to(login))
                    .service(
                        web::scope("/users")
                            .wrap(JwtMiddleware::new(Some("Customer".to_string())))
                            .route("/{id}", web::get().to(get_user_by_id)),
                    )
                    .service(
                        web::scope("/admin")
                            .wrap(JwtMiddleware::new(Some("Admin".to_string())))
                            .route("/users", web::get().to(get_users)),
                    ),
            )
            .app_data(db_pool.clone())
            .app_data(base_url.clone())
    })
    .listen(listener)?
    .run();
    Ok(server)
}
