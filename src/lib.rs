pub mod config;
pub mod detection;
pub mod input;
pub mod models;
pub mod output;
pub mod geolocation;
pub mod persistence;
pub mod alerting;

// Re-export commonly used types
pub use models::{LogEvent, AnomalyReport};
pub use detection::{IdentityContext, GeoVelocityTracker, LoginRateLimiter, GeoLocation};
pub use geolocation::GeoIpService;
pub use persistence::{StateStore, SqliteStateStore};
pub use alerting::{AlertDispatcher, AlertQueue, AlertConfig};

