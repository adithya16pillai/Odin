use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Configuration for the ISDS daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Input source configuration
    pub input: InputConfig,
    /// Detection rules configuration
    pub detection: DetectionConfig,
    /// Output configuration
    pub output: OutputConfig,
    /// Persistence configuration
    #[serde(default)]
    pub persistence: PersistenceConfig,
    /// Alerting configuration
    #[serde(default)]
    pub alerting: AlertConfig,
}

/// Input source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputConfig {
    /// Type of input source: "file" or "syslog"
    pub source_type: String,
    /// Path to log file (if source_type is "file")
    pub file_path: Option<PathBuf>,
    /// Syslog bind address (if source_type is "syslog")
    pub syslog_address: Option<String>,
}

/// Detection rules configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Enable IP switching detection
    pub enable_ip_switch: bool,
    /// Enable geo velocity/impossible travel detection
    pub enable_geo_velocity: bool,
    /// Enable rate limiting detection
    pub enable_rate_limiting: bool,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Geo velocity configuration
    pub geo_velocity: GeoVelocityConfig,
    /// Geolocation configuration
    #[serde(default)]
    pub geo_location: GeoLocationConfig,
}

/// Geolocation configuration for IP-to-location lookups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocationConfig {
    /// Enable geolocation lookups
    pub enabled: bool,
    /// Path to MaxMind GeoLite2-City.mmdb database file
    pub database_path: Option<PathBuf>,
}

impl Default for GeoLocationConfig {
    fn default() -> Self {
        GeoLocationConfig {
            enabled: true,
            database_path: Some(PathBuf::from("GeoLite2-City.mmdb")),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Time window in seconds
    pub window_seconds: i64,
    /// Maximum login attempts per user within window
    pub max_user_attempts: usize,
    /// Maximum login attempts per IP within window
    pub max_ip_attempts: usize,
}

/// Geo velocity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoVelocityConfig {
    /// Maximum plausible travel speed in km/h
    pub max_velocity_kmh: f64,
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format: "json", "jsonl", or "console"
    pub format: String,
    /// Output file path (if format is not "console")
    pub file_path: Option<PathBuf>,
}

/// Persistence configuration for state storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    /// Enable persistent state storage
    pub enabled: bool,
    /// Path to SQLite database file
    pub database_path: Option<PathBuf>,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        PersistenceConfig {
            enabled: true,
            database_path: Some(PathBuf::from("odin_state.db")),
        }
    }
}

/// Alerting configuration for webhooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alerting
    pub enabled: bool,
    /// Minimum severity to trigger alerts (1-10)
    pub min_severity: u8,
    /// Slack webhook configuration
    pub slack: Option<SlackConfig>,
    /// Discord webhook configuration
    pub discord: Option<DiscordConfig>,
    /// Generic webhook configurations
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        AlertConfig {
            enabled: false,
            min_severity: 7,
            slack: None,
            discord: None,
            webhooks: Vec::new(),
        }
    }
}

/// Slack webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    /// Slack webhook URL
    pub webhook_url: String,
    /// Channel to post to (optional)
    pub channel: Option<String>,
    /// Username for the bot (optional)
    pub username: Option<String>,
}

/// Discord webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    /// Discord webhook URL
    pub webhook_url: String,
    /// Username for the bot (optional)
    pub username: Option<String>,
}

/// Generic webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Name identifier for this webhook
    pub name: String,
    /// Webhook URL
    pub url: String,
    /// HTTP method (POST or PUT, defaults to POST)
    pub method: Option<String>,
    /// Custom headers to include
    pub headers: Option<HashMap<String, String>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            input: InputConfig {
                source_type: "file".to_string(),
                file_path: Some(PathBuf::from("/var/log/auth.log")),
                syslog_address: None,
            },
            detection: DetectionConfig {
                enable_ip_switch: true,
                enable_geo_velocity: true,
                enable_rate_limiting: true,
                rate_limit: RateLimitConfig {
                    window_seconds: 300,
                    max_user_attempts: 10,
                    max_ip_attempts: 20,
                },
                geo_velocity: GeoVelocityConfig {
                    max_velocity_kmh: 900.0,
                },
                geo_location: GeoLocationConfig::default(),
            },
            output: OutputConfig {
                format: "json".to_string(),
                file_path: Some(PathBuf::from("anomalies.jsonl")),
            },
            persistence: PersistenceConfig::default(),
            alerting: AlertConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a file
    pub fn from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save configuration to a file
    pub fn to_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

