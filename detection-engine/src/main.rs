use actix_web::{App, HttpServer, middleware, web};
use actix_cors::Cors;
use std::env;
use dotenv::dotenv;
use log::{info, error};

mod api;
mod detection;
mod models;
mod utils;
mod config;
mod db;
mod error;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a number");
    
    let db_pool = match db::create_pool().await {
        Ok(pool) => {
            info!("Connected to database successfully");
            pool
        },
        Err(e) => {
            error!("Failed to connect to database: {}", e);
            panic!("Database connection failed");
        }
    };
    
    info!("Starting detection engine on {}:{}", host, port);
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);
        
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .app_data(web::Data::new(db_pool.clone()))
            .configure(api::routes::configure)
            .service(api::routes::detection_routes())
    })
    .bind((host, port))?
    .run()
    .await
}