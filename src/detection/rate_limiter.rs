use std::collections::HashMap;
use crate::models::{LogEvent, AnomalyReport};

/// Sliding window entry for tracking login attempts
#[derive(Debug, Clone)]
struct WindowEntry {
    timestamps: Vec<i64>,
}

impl WindowEntry {
    fn new() -> Self {
        WindowEntry { timestamps: Vec::new() }
    }

    /// Add a timestamp and prune old entries outside the window
    fn add_and_prune(&mut self, timestamp: i64, window_seconds: i64) {
        let cutoff = timestamp - window_seconds;
        self.timestamps.retain(|&t| t > cutoff);
        self.timestamps.push(timestamp);
    }

    fn count(&self) -> usize {
        self.timestamps.len()
    }
}

/// Tracks login attempt rates to detect brute force attacks
pub struct LoginRateLimiter {
    /// Maps (user OR ip) -> window entry
    per_user_attempts: HashMap<String, WindowEntry>,
    per_ip_attempts: HashMap<String, WindowEntry>,
    /// Time window in seconds (default: 300 = 5 minutes)
    window_seconds: i64,
    /// Max attempts per user within window
    max_user_attempts: usize,
    /// Max attempts per IP within window
    max_ip_attempts: usize,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        LoginRateLimiter {
            per_user_attempts: HashMap::new(),
            per_ip_attempts: HashMap::new(),
            window_seconds: 300,
            max_user_attempts: 10,
            max_ip_attempts: 20,
        }
    }

    /// Create with custom thresholds
    pub fn with_config(
        window_seconds: i64,
        max_user_attempts: usize,
        max_ip_attempts: usize,
    ) -> Self {
        LoginRateLimiter {
            per_user_attempts: HashMap::new(),
            per_ip_attempts: HashMap::new(),
            window_seconds,
            max_user_attempts,
            max_ip_attempts,
        }
    }

    /// Check for rate limit violations (returns up to 2 reports if both limits exceeded)
    pub fn check_rate_limit(&mut self, event: &LogEvent) -> Vec<AnomalyReport> {
        let mut reports = Vec::new();

        // Track per-user attempts
        let user_entry = self
            .per_user_attempts
            .entry(event.user.clone())
            .or_insert_with(WindowEntry::new);
        user_entry.add_and_prune(event.timestamp, self.window_seconds);

        if user_entry.count() > self.max_user_attempts {
            reports.push(AnomalyReport {
                severity: Self::calculate_severity(user_entry.count(), self.max_user_attempts),
                rule_name: "User Rate Limit Exceeded".to_string(),
                user: event.user.clone(),
                detected_ip: event.ip_address.to_string(),
                trusted_ip: String::new(),
                timestamp: event.timestamp,
                description: format!(
                    "User '{}' has {} login attempts in the last {} seconds (threshold: {}). \
                     Possible credential stuffing or brute force attack.",
                    event.user,
                    user_entry.count(),
                    self.window_seconds,
                    self.max_user_attempts
                ),
            });
        }

        // Track per-IP attempts
        let ip_str = event.ip_address.to_string();
        let ip_entry = self
            .per_ip_attempts
            .entry(ip_str.clone())
            .or_insert_with(WindowEntry::new);
        ip_entry.add_and_prune(event.timestamp, self.window_seconds);

        if ip_entry.count() > self.max_ip_attempts {
            reports.push(AnomalyReport {
                severity: Self::calculate_severity(ip_entry.count(), self.max_ip_attempts),
                rule_name: "IP Rate Limit Exceeded".to_string(),
                user: event.user.clone(),
                detected_ip: ip_str,
                trusted_ip: String::new(),
                timestamp: event.timestamp,
                description: format!(
                    "IP {} has {} login attempts in the last {} seconds (threshold: {}). \
                     Possible distributed attack or compromised host.",
                    event.ip_address,
                    ip_entry.count(),
                    self.window_seconds,
                    self.max_ip_attempts
                ),
            });
        }

        reports
    }

    /// Get current attempt count for a user
    pub fn get_user_attempt_count(&self, user: &str) -> usize {
        self.per_user_attempts
            .get(user)
            .map(|e| e.count())
            .unwrap_or(0)
    }

    /// Get current attempt count for an IP
    pub fn get_ip_attempt_count(&self, ip: &str) -> usize {
        self.per_ip_attempts
            .get(ip)
            .map(|e| e.count())
            .unwrap_or(0)
    }

    fn calculate_severity(actual: usize, threshold: usize) -> u8 {
        let ratio = actual as f64 / threshold as f64;
        if ratio > 5.0 {
            10
        } else if ratio > 3.0 {
            9
        } else if ratio > 2.0 {
            8
        } else {
            7
        }
    }

    /// Clear all tracking data
    pub fn clear_all(&mut self) {
        self.per_user_attempts.clear();
        self.per_ip_attempts.clear();
    }

    /// Prune stale entries older than the window
    pub fn prune_stale(&mut self, current_timestamp: i64) {
        let cutoff = current_timestamp - self.window_seconds;

        self.per_user_attempts.retain(|_, entry| {
            entry.timestamps.retain(|&t| t > cutoff);
            !entry.timestamps.is_empty()
        });

        self.per_ip_attempts.retain(|_, entry| {
            entry.timestamps.retain(|&t| t > cutoff);
            !entry.timestamps.is_empty()
        });
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn create_event(user: &str, timestamp: i64, ip: &str) -> LogEvent {
        LogEvent {
            timestamp,
            user: user.to_string(),
            ip_address: IpAddr::from_str(ip).unwrap(),
            event_type: "LOGIN".to_string(),
        }
    }

    #[test]
    fn test_normal_login_rate() {
        let mut limiter = LoginRateLimiter::with_config(300, 5, 10);

        // 3 logins within threshold
        for i in 0..3 {
            let event = create_event("user1", 1700000000 + i * 60, "1.1.1.1");
            let reports = limiter.check_rate_limit(&event);
            assert!(reports.is_empty(), "Should not trigger for normal rate");
        }
    }

    #[test]
    fn test_user_rate_exceeded() {
        let mut limiter = LoginRateLimiter::with_config(300, 3, 100);

        // 5 rapid logins from same user
        for i in 0..5 {
            let event = create_event("attacker", 1700000000 + i, "1.1.1.1");
            let reports = limiter.check_rate_limit(&event);

            if i >= 3 {
                assert!(!reports.is_empty(), "Should trigger after threshold");
                assert!(reports[0].rule_name.contains("User Rate"));
            }
        }
    }

    #[test]
    fn test_ip_rate_exceeded() {
        let mut limiter = LoginRateLimiter::with_config(300, 100, 3);

        // 5 rapid logins from same IP targeting different users
        for i in 0..5 {
            let event = create_event(&format!("user{}", i), 1700000000 + i as i64, "10.0.0.1");
            let reports = limiter.check_rate_limit(&event);

            if i >= 3 {
                assert!(!reports.is_empty(), "Should trigger after IP threshold");
                assert!(reports.iter().any(|r| r.rule_name.contains("IP Rate")));
            }
        }
    }

    #[test]
    fn test_window_expiry() {
        let mut limiter = LoginRateLimiter::with_config(60, 3, 100);

        // 3 logins
        for i in 0..3 {
            let event = create_event("user1", 1700000000 + i, "1.1.1.1");
            limiter.check_rate_limit(&event);
        }

        assert_eq!(limiter.get_user_attempt_count("user1"), 3);

        // Login after window expires
        let event = create_event("user1", 1700000000 + 120, "1.1.1.1");
        limiter.check_rate_limit(&event);

        // Old attempts should be pruned, only 1 recent attempt
        assert_eq!(limiter.get_user_attempt_count("user1"), 1);
    }

    #[test]
    fn test_both_limits_exceeded() {
        let mut limiter = LoginRateLimiter::with_config(300, 2, 2);

        // First two logins from same user and IP
        for i in 0..2 {
            let event = create_event("target", 1700000000 + i, "5.5.5.5");
            limiter.check_rate_limit(&event);
        }

        // Third login triggers both limits
        let event = create_event("target", 1700000002, "5.5.5.5");
        let reports = limiter.check_rate_limit(&event);

        assert_eq!(reports.len(), 2, "Should trigger both user and IP limits");
    }
}
