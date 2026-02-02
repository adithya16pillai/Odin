//! ISDS Daemon - Intrusion Detection System Daemon
//!
//! This is the main daemon process that monitors log sources, runs
//! detection rules, and dispatches alerts.

use std::path::PathBuf;
use std::sync::Arc;
use std::env;

use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

use odin::config::Config;
use odin::detection::{IdentityContext, GeoVelocityTracker, LoginRateLimiter};
use odin::models::{LogEvent, AnomalyReport};
use odin::input::{AsyncFileTailer, AsyncSyslogListener};
use odin::output::{OutputHandler, OutputFormat};
use odin::geolocation::GeoIpService;
use odin::persistence::SqliteStateStore;
use odin::alerting::{AlertDispatcher, AlertQueue};

/// Main daemon entry point
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("Starting ISDS Daemon (async)...");

    // Load configuration
    let config_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    let config = if config_path.exists() {
        log::info!("Loading configuration from {:?}", config_path);
        Config::from_file(&config_path)?
    } else {
        log::warn!("Config file not found at {:?}, using defaults", config_path);
        Config::default()
    };

    // Initialize persistence
    let state_store = if config.persistence.enabled {
        let db_path = config
            .persistence
            .database_path
            .as_deref()
            .unwrap_or(std::path::Path::new("odin_state.db"));

        match SqliteStateStore::new(db_path) {
            Ok(store) => {
                log::info!("Persistence initialized at {:?}", db_path);
                Some(Arc::new(store))
            }
            Err(e) => {
                log::error!("Failed to initialize persistence: {}", e);
                log::warn!("Continuing without persistence");
                None
            }
        }
    } else {
        log::info!("Persistence disabled");
        None
    };

    // Initialize geolocation service
    let geo_service = if config.detection.geo_location.enabled {
        config
            .detection
            .geo_location
            .database_path
            .as_ref()
            .and_then(|path| {
                match GeoIpService::new(path) {
                    Ok(service) => {
                        log::info!("GeoIP service initialized from {:?}", path);
                        Some(service)
                    }
                    Err(e) => {
                        log::warn!("Failed to initialize GeoIP service: {}", e);
                        log::warn!("Geo-velocity detection will be disabled");
                        None
                    }
                }
            })
    } else {
        None
    };

    // Initialize alerting
    let (alert_tx, alert_rx) = AlertDispatcher::create_channel();
    let alert_queue = AlertQueue::new(alert_tx);
    let alert_dispatcher = AlertDispatcher::new(config.alerting.clone()).0;

    // Spawn alert dispatcher task
    tokio::spawn(async move {
        alert_dispatcher.run(alert_rx).await;
    });

    if config.alerting.enabled {
        log::info!(
            "Alerting enabled (min severity: {})",
            config.alerting.min_severity
        );
    }

    // Initialize output handler
    let output_format = OutputFormat::from_str(&config.output.format);
    let output_handler = Arc::new(tokio::sync::Mutex::new(
        OutputHandler::new(output_format, config.output.file_path.clone())?
    ));
    log::info!("Output handler initialized (format: {})", config.output.format);

    // Initialize detection components
    let identity_context = Arc::new(tokio::sync::Mutex::new(
        if let Some(ref store) = state_store {
            IdentityContext::with_persistence(store.clone())
        } else {
            IdentityContext::new()
        }
    ));

    let geo_velocity_tracker = Arc::new(tokio::sync::Mutex::new(
        if let Some(ref store) = state_store {
            GeoVelocityTracker::with_persistence(
                config.detection.geo_velocity.max_velocity_kmh,
                store.clone(),
            )
        } else {
            GeoVelocityTracker::with_max_velocity(config.detection.geo_velocity.max_velocity_kmh)
        }
    ));

    let rate_limiter = Arc::new(tokio::sync::Mutex::new(
        if let Some(ref store) = state_store {
            LoginRateLimiter::with_persistence(
                config.detection.rate_limit.window_seconds,
                config.detection.rate_limit.max_user_attempts,
                config.detection.rate_limit.max_ip_attempts,
                store.clone(),
            )
        } else {
            LoginRateLimiter::with_config(
                config.detection.rate_limit.window_seconds,
                config.detection.rate_limit.max_user_attempts,
                config.detection.rate_limit.max_ip_attempts,
            )
        }
    ));

    log::info!("Detection rules initialized:");
    log::info!("  - IP switch detection: {}", config.detection.enable_ip_switch);
    log::info!("  - Geo velocity detection: {} (GeoIP: {})",
        config.detection.enable_geo_velocity,
        geo_service.is_some()
    );
    log::info!("  - Rate limiting: {} (window: {}s, max user: {}, max IP: {})",
        config.detection.enable_rate_limiting,
        config.detection.rate_limit.window_seconds,
        config.detection.rate_limit.max_user_attempts,
        config.detection.rate_limit.max_ip_attempts
    );

    // Create event channel
    let (event_tx, mut event_rx) = mpsc::channel::<LogEvent>(1000);

    // Spawn input source task
    match config.input.source_type.as_str() {
        "file" => {
            if let Some(ref path) = config.input.file_path {
                let path = path.clone();
                let tx = event_tx.clone();
                tokio::spawn(async move {
                    let mut tailer = AsyncFileTailer::new(path.clone());
                    if let Err(e) = tailer.run(tx).await {
                        log::error!("File tailer error: {}", e);
                    }
                });
                log::info!("Monitoring log file: {:?}", config.input.file_path);
            } else {
                log::warn!("File source type selected but no file path configured");
            }
        }
        "syslog" => {
            if let Some(ref address) = config.input.syslog_address {
                let addr = address.clone();
                let tx = event_tx.clone();
                tokio::spawn(async move {
                    match AsyncSyslogListener::new(&addr).await {
                        Ok(mut listener) => {
                            if let Err(e) = listener.run(tx).await {
                                log::error!("Syslog listener error: {}", e);
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to create syslog listener: {}", e);
                        }
                    }
                });
                log::info!("Listening on syslog: {}", address);
            } else {
                log::warn!("Syslog source type selected but no address configured");
            }
        }
        _ => {
            log::warn!("Unknown input source type: {}", config.input.source_type);
        }
    }

    // Drop the original sender so the channel closes when tasks complete
    drop(event_tx);

    // Setup graceful shutdown
    log::info!("Daemon running. Press Ctrl+C to stop.");

    // Periodic maintenance interval (every 60 seconds)
    let mut maintenance_interval = interval(Duration::from_secs(60));

    // Main event loop
    loop {
        tokio::select! {
            // Process incoming events
            Some(event) = event_rx.recv() => {
                process_event(
                    &event,
                    &config,
                    &identity_context,
                    &geo_velocity_tracker,
                    &rate_limiter,
                    &output_handler,
                    geo_service.as_ref(),
                    &alert_queue,
                    state_store.as_ref(),
                ).await;
            }

            // Periodic maintenance
            _ = maintenance_interval.tick() => {
                // Prune old data from persistence
                if let Some(ref store) = state_store {
                    let cutoff = chrono::Utc::now().timestamp() - 86400; // 24 hours
                    match store.prune_old_data(cutoff) {
                        Ok(count) => {
                            if count > 0 {
                                log::debug!("Pruned {} old records from database", count);
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to prune old data: {}", e);
                        }
                    }
                }

                // Prune in-memory caches
                let now = chrono::Utc::now().timestamp();
                rate_limiter.lock().await.prune_stale(now);
            }

            // Shutdown signal
            _ = tokio::signal::ctrl_c() => {
                log::info!("Received shutdown signal, gracefully stopping...");
                break;
            }
        }
    }

    // Flush output before exit
    if let Err(e) = output_handler.lock().await.flush() {
        log::error!("Failed to flush output: {}", e);
    }

    log::info!("ISDS Daemon stopped");
    Ok(())
}

/// Process a single log event through all detection rules
async fn process_event(
    event: &LogEvent,
    config: &Config,
    identity_context: &Arc<tokio::sync::Mutex<IdentityContext>>,
    geo_velocity_tracker: &Arc<tokio::sync::Mutex<GeoVelocityTracker>>,
    rate_limiter: &Arc<tokio::sync::Mutex<LoginRateLimiter>>,
    output_handler: &Arc<tokio::sync::Mutex<OutputHandler>>,
    geo_service: Option<&GeoIpService>,
    alert_queue: &AlertQueue,
    state_store: Option<&Arc<SqliteStateStore>>,
) {
    log::debug!(
        "Processing event: user={}, ip={}, type={}",
        event.user,
        event.ip_address,
        event.event_type
    );

    // Helper to handle anomaly reports
    let handle_report = |report: AnomalyReport| async {
        // Write to output
        {
            let mut out = output_handler.lock().await;
            if let Err(e) = out.write_report(&report) {
                log::error!("Failed to write report: {}", e);
            }
        }

        // Store in persistence
        if let Some(store) = state_store {
            if let Err(e) = store.store_anomaly_report(&report) {
                log::warn!("Failed to store anomaly report: {}", e);
            }
        }

        // Queue alert
        alert_queue.queue_alert(report.clone());

        // Log warning
        log::warn!(
            "ANOMALY DETECTED: [{}] Severity: {} - User: {} - {}",
            report.rule_name,
            report.severity,
            report.user,
            report.description
        );
    };

    // Check for IP switching
    if config.detection.enable_ip_switch {
        let mut ctx = identity_context.lock().await;
        if let Some(report) = ctx.check_for_ip_switch(event) {
            handle_report(report).await;
        }
    }

    // Check for impossible travel (requires geo location lookup)
    if config.detection.enable_geo_velocity {
        if let Some(geo) = geo_service {
            if let Some(location) = geo.lookup_optional(&event.ip_address) {
                let mut tracker = geo_velocity_tracker.lock().await;
                if let Some(report) = tracker.check_impossible_travel(event, location) {
                    handle_report(report).await;
                }
            }
        }
    }

    // Check for rate limiting violations
    if config.detection.enable_rate_limiting {
        let mut limiter = rate_limiter.lock().await;
        for report in limiter.check_rate_limit(event) {
            handle_report(report).await;
        }
    }
}
