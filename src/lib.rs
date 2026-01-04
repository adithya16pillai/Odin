pub mod config;
pub mod detection;
pub mod input;
pub mod models;
pub mod output;

// Re-export commonly used types
pub use models::{LogEvent, AnomalyReport};
pub use detection::{IdentityContext, GeoVelocityTracker, LoginRateLimiter, GeoLocation};

