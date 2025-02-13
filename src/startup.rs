use std::{net::TcpListener, sync::Arc};

use actix_web::{
    dev::Server,
    middleware::Logger,
    web::{self, Data},
    App, HttpServer,
};
use casbin::{CoreApi, DefaultModel, Enforcer, FileAdapter};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::RwLock;

use crate::{
    authentication::{JwtCasbinMiddleware, JwtMiddleware},
    configuration::{DatabaseSettings, Settings},
    routes::{get_user_by_id, get_users, login, register},
};

pub struct Application {
    port: u16,
    server: Server,
}

impl Application {
    pub async fn build(configuration: Settings) -> Result<Self, anyhow::Error> {
        let connection_pool = get_connection_pool(&configuration.database)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to database: {}", e))?;

        // ✅ Initialize Casbin Enforcer
        let model = DefaultModel::from_file("rbac_model.conf").await?;
        let adapter = FileAdapter::new("policy.csv");
        let enforcer = Arc::new(RwLock::new(Enforcer::new(model, adapter).await?));

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
            enforcer,
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

async fn get_connection_pool(configuration: &DatabaseSettings) -> Result<PgPool, anyhow::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(configuration.connect_options())
        .await?;

    if let Err(err) = pool.acquire().await {
        return Err(anyhow::anyhow!("Database connection failed: {}", err));
    }

    Ok(pool)
}

pub struct ApplicationBaseUrl(pub String);

pub async fn run(
    listener: TcpListener,
    db_pool: PgPool,
    base_url: String,
    enforcer: Arc<RwLock<Enforcer>>,
) -> Result<Server, anyhow::Error> {
    let db_pool = Data::new(db_pool);
    let base_url = Data::new(ApplicationBaseUrl(base_url));
    let enforcer = Data::new(enforcer);

    let server = HttpServer::new(move || {
        App::new()
            .service(
                web::scope("/api/v1")
                    .route("/register", web::post().to(register))
                    .route("/login", web::post().to(login))
                    .service(
                        web::scope("/users")
                            .wrap(JwtCasbinMiddleware::new(enforcer.as_ref().clone()))
                            .route("/{id}", web::get().to(get_user_by_id)),
                    )
                    .service(
                        web::scope("/admin")
                            .wrap(JwtCasbinMiddleware::new(enforcer.as_ref().clone()))
                            .route("/users", web::get().to(get_users)),
                    ),
            )
            .app_data(db_pool.clone())
            .app_data(base_url.clone())
            .app_data(enforcer.clone())
    })
    .listen(listener)?
    .run();

    Ok(server)
}
