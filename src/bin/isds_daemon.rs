use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::net::IpAddr;
use std::str::FromStr;

use crate::detection::{IdentityContext, GeoVelocityTracker, LoginRateLimiter};
use crate::models::{LogEvent, AnomalyReport};

/// Main daemon entry point for the Intrusion Detection System
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("Starting ISDS Daemon...");

    // Setup graceful shutdown signal handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal, gracefully stopping...");
        r.store(false, Ordering::SeqCst);
    })?;

    // Initialize detection components
    let mut identity_context = IdentityContext::new();
    let mut geo_velocity_tracker = GeoVelocityTracker::new();
    let mut rate_limiter = LoginRateLimiter::new();

    log::info!("Detection rules initialized");
    log::info!("Daemon running. Press Ctrl+C to stop.");

    // Main event processing loop
    while running.load(Ordering::SeqCst) {
        // In a real implementation, this would read from actual log sources
        // For now, this is a placeholder that demonstrates the structure
        
        // TODO: Replace with actual log input (file tailer, syslog listener, etc.)
        // Example: Read events from input source
        // let events = read_log_events()?;
        
        // Process each event through detection rules
        // for event in events {
        //     process_event(&event, &mut identity_context, &mut geo_velocity_tracker, &mut rate_limiter)?;
        // }

        // Sleep to avoid busy-waiting
        std::thread::sleep(Duration::from_millis(100));
    }

    log::info!("ISDS Daemon stopped");
    Ok(())
}

/// Process a single log event through all detection rules
fn process_event(
    event: &LogEvent,
    identity_context: &mut IdentityContext,
    geo_velocity_tracker: &mut GeoVelocityTracker,
    rate_limiter: &mut LoginRateLimiter,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check for IP switching
    if let Some(report) = identity_context.check_for_ip_switch(event) {
        handle_anomaly(&report)?;
    }

    // Check for impossible travel (requires geo location lookup)
    // In a real implementation, you'd look up the IP's geo location
    // For now, this is a placeholder
    // if let Some(location) = lookup_ip_location(&event.ip_address)? {
    //     if let Some(report) = geo_velocity_tracker.check_impossible_travel(event, location) {
    //         handle_anomaly(&report)?;
    //     }
    // }

    // Check for rate limiting violations
    for report in rate_limiter.check_rate_limit(event) {
        handle_anomaly(&report)?;
    }

    Ok(())
}

/// Handle an anomaly report (output, alert, etc.)
fn handle_anomaly(report: &AnomalyReport) -> Result<(), Box<dyn std::error::Error>> {
    // Log the anomaly
    log::warn!(
        "ANOMALY DETECTED: [{}] {} - User: {}, IP: {} -> {}, Severity: {}",
        report.rule_name,
        report.description,
        report.user,
        report.trusted_ip,
        report.detected_ip,
        report.severity
    );

    // In a real implementation, you would:
    // - Write to output file/database
    // - Send alerts (email, webhook, etc.)
    // - Update metrics/dashboards
    
    // Example: Serialize and output JSON
    let json = serde_json::to_string_pretty(report)?;
    println!("{}", json);

    Ok(())
}

/// Placeholder for IP geolocation lookup
/// In a real implementation, this would query a geo IP service
fn lookup_ip_location(_ip: &IpAddr) -> Result<Option<crate::detection::GeoLocation>, Box<dyn std::error::Error>> {
    // TODO: Implement actual geo IP lookup
    // For now, return None to skip geo velocity checks
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_process_event_ip_switch() {
        let mut identity_context = IdentityContext::new();
        let mut geo_velocity_tracker = GeoVelocityTracker::new();
        let mut rate_limiter = LoginRateLimiter::new();

        let event = LogEvent {
            timestamp: 1700000000,
            user: "test_user".to_string(),
            ip_address: IpAddr::from_str("192.168.1.1").unwrap(),
            event_type: "SSH_LOGIN".to_string(),
        };

        // First event should not trigger IP switch
        let result = process_event(&event, &mut identity_context, &mut geo_velocity_tracker, &mut rate_limiter);
        assert!(result.is_ok());

        // Second event with different IP should trigger IP switch
        let event2 = LogEvent {
            timestamp: 1700000005,
            user: "test_user".to_string(),
            ip_address: IpAddr::from_str("192.168.1.2").unwrap(),
            event_type: "SSH_LOGIN".to_string(),
        };

        let result = process_event(&event2, &mut identity_context, &mut geo_velocity_tracker, &mut rate_limiter);
        assert!(result.is_ok());
    }
}

