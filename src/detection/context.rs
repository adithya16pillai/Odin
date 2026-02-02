//! IP switch detection context
//!
//! Tracks user IP addresses and detects when a user logs in from
//! a different IP than previously seen.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use crate::models::{LogEvent, AnomalyReport};
use crate::persistence::StateStore;

/// Context for tracking user identities and detecting IP switches
pub struct IdentityContext {
    /// In-memory cache of user -> last known IP
    last_known_ip: HashMap<String, IpAddr>,
    /// Optional persistence backend
    store: Option<Arc<dyn StateStore>>,
}

impl IdentityContext {
    /// Create a new identity context (in-memory only)
    pub fn new() -> Self {
        IdentityContext {
            last_known_ip: HashMap::new(),
            store: None,
        }
    }

    /// Create an identity context with persistence support
    ///
    /// When a persistence backend is provided, the context will:
    /// - Check the database for previously stored IP addresses
    /// - Store new IP addresses to the database
    /// - Use the in-memory cache for fast lookups
    pub fn with_persistence(store: Arc<dyn StateStore>) -> Self {
        IdentityContext {
            last_known_ip: HashMap::new(),
            store: Some(store),
        }
    }

    /// Check if the user has switched IP addresses
    ///
    /// Returns an anomaly report if the user is logging in from a different
    /// IP than their last known IP address.
    pub fn check_for_ip_switch(&mut self, event: &LogEvent) -> Option<AnomalyReport> {
        // First check in-memory cache
        let cached_ip = self.last_known_ip.get(&event.user).copied();

        // If not in cache, try persistence backend
        let trusted_ip = match cached_ip {
            Some(ip) => Some(ip),
            None => {
                if let Some(ref store) = self.store {
                    match store.get_user_last_ip(&event.user) {
                        Ok(Some((ip, _timestamp))) => {
                            // Populate cache from persistence
                            self.last_known_ip.insert(event.user.clone(), ip);
                            Some(ip)
                        }
                        Ok(None) => None,
                        Err(e) => {
                            log::warn!("Failed to get user IP from persistence: {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            }
        };

        // Generate report if IP changed
        let report = match trusted_ip {
            None => None,
            Some(ip) if ip == event.ip_address => None,
            Some(trusted_ip) => Some(AnomalyReport {
                severity: 8,
                rule_name: "Sudden IP Switch".to_string(),
                user: event.user.clone(),
                detected_ip: event.ip_address.to_string(),
                trusted_ip: trusted_ip.to_string(),
                timestamp: event.timestamp,
                description: format!(
                    "User '{}' switched from trusted IP {} to new IP {}.",
                    event.user, trusted_ip, event.ip_address
                ),
            }),
        };

        // Update both cache and persistence
        self.last_known_ip.insert(event.user.clone(), event.ip_address);
        if let Some(ref store) = self.store {
            if let Err(e) = store.set_user_last_ip(&event.user, &event.ip_address, event.timestamp) {
                log::warn!("Failed to persist user IP: {}", e);
            }
        }

        report
    }

    /// Clear tracking data for a specific user
    pub fn clear_user(&mut self, user: &str) {
        self.last_known_ip.remove(user);
    }

    /// Clear all tracking data (in-memory only)
    pub fn clear_all(&mut self) {
        self.last_known_ip.clear();
    }

    /// Get the last known IP for a user
    pub fn get_last_ip(&self, user: &str) -> Option<IpAddr> {
        self.last_known_ip.get(user).copied()
    }
}

impl Default for IdentityContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn create_event(user: &str, ip: &str, timestamp: i64) -> LogEvent {
        LogEvent {
            timestamp,
            user: user.to_string(),
            ip_address: IpAddr::from_str(ip).unwrap(),
            event_type: "SSH_LOGIN".to_string(),
        }
    }

    #[test]
    fn test_first_login_no_anomaly() {
        let mut context = IdentityContext::new();
        let event = create_event("alice", "1.1.1.1", 1700000000);

        assert!(context.check_for_ip_switch(&event).is_none());
        assert_eq!(context.get_last_ip("alice"), Some(IpAddr::from_str("1.1.1.1").unwrap()));
    }

    #[test]
    fn test_same_ip_no_anomaly() {
        let mut context = IdentityContext::new();

        let event1 = create_event("alice", "1.1.1.1", 1700000000);
        context.check_for_ip_switch(&event1);

        let event2 = create_event("alice", "1.1.1.1", 1700000005);
        assert!(context.check_for_ip_switch(&event2).is_none());
    }

    #[test]
    fn test_ip_switch_anomaly() {
        let mut context = IdentityContext::new();

        let event1 = create_event("alice", "1.1.1.1", 1700000000);
        assert!(context.check_for_ip_switch(&event1).is_none());

        let event2 = create_event("alice", "2.2.2.2", 1700000005);
        let report = context.check_for_ip_switch(&event2);

        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.severity, 8);
        assert_eq!(report.trusted_ip, "1.1.1.1");
        assert_eq!(report.detected_ip, "2.2.2.2");
        assert!(report.description.contains("alice"));
    }

    #[test]
    fn test_different_users_independent() {
        let mut context = IdentityContext::new();

        context.check_for_ip_switch(&create_event("alice", "1.1.1.1", 1700000000));
        context.check_for_ip_switch(&create_event("bob", "2.2.2.2", 1700000001));

        // Alice switching IP should trigger anomaly
        let report = context.check_for_ip_switch(&create_event("alice", "3.3.3.3", 1700000002));
        assert!(report.is_some());

        // Bob from same IP should be fine
        let report = context.check_for_ip_switch(&create_event("bob", "2.2.2.2", 1700000003));
        assert!(report.is_none());
    }

    #[test]
    fn test_clear_user() {
        let mut context = IdentityContext::new();

        context.check_for_ip_switch(&create_event("alice", "1.1.1.1", 1700000000));
        assert!(context.get_last_ip("alice").is_some());

        context.clear_user("alice");
        assert!(context.get_last_ip("alice").is_none());

        // After clearing, new IP shouldn't trigger anomaly
        let report = context.check_for_ip_switch(&create_event("alice", "2.2.2.2", 1700000005));
        assert!(report.is_none());
    }

    #[test]
    fn test_clear_all() {
        let mut context = IdentityContext::new();

        context.check_for_ip_switch(&create_event("alice", "1.1.1.1", 1700000000));
        context.check_for_ip_switch(&create_event("bob", "2.2.2.2", 1700000001));

        context.clear_all();

        assert!(context.get_last_ip("alice").is_none());
        assert!(context.get_last_ip("bob").is_none());
    }

    #[test]
    fn test_ipv6_support() {
        let mut context = IdentityContext::new();

        let event1 = create_event("alice", "2001:db8::1", 1700000000);
        context.check_for_ip_switch(&event1);

        let event2 = create_event("alice", "2001:db8::2", 1700000005);
        let report = context.check_for_ip_switch(&event2);

        assert!(report.is_some());
        assert!(report.unwrap().trusted_ip.contains("2001:db8::1"));
    }
}
