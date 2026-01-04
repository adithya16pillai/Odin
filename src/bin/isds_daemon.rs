use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::net::IpAddr;
use std::path::PathBuf;
use std::env;

use crate::config::Config;
use crate::detection::{IdentityContext, GeoVelocityTracker, LoginRateLimiter};
use crate::models::LogEvent;
use crate::input::{FileTailer, SyslogListener};
use crate::output::{OutputHandler, OutputFormat};

/// Main daemon entry point for the Intrusion Detection System
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("Starting ISDS Daemon...");

    // Load configuration
    let config_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    
    let config = if config_path.exists() {
        Config::from_file(&config_path)?
    } else {
        log::warn!("Config file not found, using defaults");
        Config::default()
    };

    // Setup graceful shutdown signal handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal, gracefully stopping...");
        r.store(false, Ordering::SeqCst);
    })?;

    // Initialize output handler
    let output_format = OutputFormat::from_str(&config.output.format);
    let mut output_handler = OutputHandler::new(
        output_format,
        config.output.file_path.clone()
    )?;

    // Initialize detection components
    let mut identity_context = IdentityContext::new();
    let mut geo_velocity_tracker = GeoVelocityTracker::with_max_velocity(
        config.detection.geo_velocity.max_velocity_kmh
    );
    let mut rate_limiter = LoginRateLimiter::with_config(
        config.detection.rate_limit.window_seconds,
        config.detection.rate_limit.max_user_attempts,
        config.detection.rate_limit.max_ip_attempts,
    );

    log::info!("Detection rules initialized");
    log::info!("Daemon running. Press Ctrl+C to stop.");

    // Initialize input source
    let mut file_tailer: Option<FileTailer> = None;
    let mut syslog_listener: Option<SyslogListener> = None;

    match config.input.source_type.as_str() {
        "file" => {
            if let Some(ref path) = config.input.file_path {
                let mut tailer = FileTailer::new(path.clone());
                tailer.initialize()?;
                file_tailer = Some(tailer);
                log::info!("Monitoring log file: {:?}", path);
            }
        }
        "syslog" => {
            if let Some(ref address) = config.input.syslog_address {
                let listener = SyslogListener::new(address)?;
                syslog_listener = Some(listener);
                log::info!("Listening on syslog: {}", address);
            }
        }
        _ => {
            log::warn!("Unknown input source type: {}", config.input.source_type);
        }
    }

    // Main event processing loop
    while running.load(Ordering::SeqCst) {
        let mut events = Vec::new();

        // Read events from configured input source
        if let Some(ref mut tailer) = file_tailer {
            if tailer.is_valid() {
                match tailer.read_events() {
                    Ok(new_events) => events.extend(new_events),
                    Err(e) => log::error!("Error reading from file: {}", e),
                }
            }
        } else if let Some(ref mut listener) = syslog_listener {
            loop {
                match listener.read_message() {
                    Ok(Some(msg)) => {
                        match SyslogListener::parse_syslog_message(&msg) {
                            Ok(event) => events.push(event),
                            Err(e) => log::debug!("Failed to parse syslog message: {}", e),
                        }
                    }
                    Ok(None) => break, // No more messages
                    Err(e) => {
                        log::error!("Error reading syslog: {}", e);
                        break;
                    }
                }
            }
        }

        // Process each event through detection rules
        for event in events {
            process_event(
                &event,
                &config,
                &mut identity_context,
                &mut geo_velocity_tracker,
                &mut rate_limiter,
                &mut output_handler,
            )?;
        }

        // Sleep to avoid busy-waiting
        std::thread::sleep(Duration::from_millis(100));
    }

    output_handler.flush()?;
    log::info!("ISDS Daemon stopped");
    Ok(())
}

/// Process a single log event through all detection rules
fn process_event(
    event: &LogEvent,
    config: &Config,
    identity_context: &mut IdentityContext,
    geo_velocity_tracker: &mut GeoVelocityTracker,
    rate_limiter: &mut LoginRateLimiter,
    output_handler: &mut OutputHandler,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check for IP switching
    if config.detection.enable_ip_switch {
        if let Some(report) = identity_context.check_for_ip_switch(event) {
            output_handler.write_report(&report)?;
            log::warn!(
                "ANOMALY DETECTED: [{}] {} - User: {}, IP: {} -> {}",
                report.rule_name, report.description, report.user,
                report.trusted_ip, report.detected_ip
            );
        }
    }

    // Check for impossible travel (requires geo location lookup)
    if config.detection.enable_geo_velocity {
        // In a real implementation, you'd look up the IP's geo location
        // For now, this is disabled as it requires external geo IP service
        // if let Some(location) = lookup_ip_location(&event.ip_address)? {
        //     if let Some(report) = geo_velocity_tracker.check_impossible_travel(event, location) {
        //         output_handler.write_report(&report)?;
        //     }
        // }
    }

    // Check for rate limiting violations
    if config.detection.enable_rate_limiting {
        for report in rate_limiter.check_rate_limit(event) {
            output_handler.write_report(&report)?;
            log::warn!(
                "ANOMALY DETECTED: [{}] {} - User: {}, Severity: {}",
                report.rule_name, report.description, report.user, report.severity
            );
        }
    }

    Ok(())
}

// Placeholder for IP geolocation lookup
// In a real implementation, this would query a geo IP service
// fn lookup_ip_location(_ip: &IpAddr) -> Result<Option<crate::detection::GeoLocation>, Box<dyn std::error::Error>> {
//     // TODO: Implement actual geo IP lookup
//     Ok(None)
// }

