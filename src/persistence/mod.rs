//! Persistence module for state storage
//!
//! This module provides persistent storage for detection state,
//! allowing the daemon to maintain context across restarts.

pub mod sqlite_store;

pub use sqlite_store::SqliteStateStore;

use crate::detection::GeoLocation;
use crate::models::AnomalyReport;
use std::net::IpAddr;
use thiserror::Error;

/// Errors that can occur during persistence operations
#[derive(Error, Debug)]
pub enum PersistenceError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid data in database: {0}")]
    InvalidData(String),

    #[error("Database not initialized")]
    NotInitialized,
}

/// Trait for state persistence backends
///
/// This trait defines the interface for storing and retrieving
/// detection state. Implementations can use different storage
/// backends (SQLite, Redis, etc.).
pub trait StateStore: Send + Sync {
    // =====================
    // User IP Tracking
    // =====================

    /// Get the last known IP address for a user
    ///
    /// Returns the IP address and timestamp of the last login
    fn get_user_last_ip(&self, user: &str) -> Result<Option<(IpAddr, i64)>, PersistenceError>;

    /// Set the last known IP address for a user
    fn set_user_last_ip(
        &self,
        user: &str,
        ip: &IpAddr,
        timestamp: i64,
    ) -> Result<(), PersistenceError>;

    // =====================
    // User Location Tracking
    // =====================

    /// Get the last known location for a user
    ///
    /// Returns the timestamp and geographic location of the last login
    fn get_user_last_location(
        &self,
        user: &str,
    ) -> Result<Option<(i64, GeoLocation)>, PersistenceError>;

    /// Add a location record for a user
    fn add_user_location(
        &self,
        user: &str,
        timestamp: i64,
        location: &GeoLocation,
        ip: &IpAddr,
    ) -> Result<(), PersistenceError>;

    // =====================
    // Login Attempt Tracking
    // =====================

    /// Record a login attempt
    fn add_login_attempt(
        &self,
        user: &str,
        ip: &IpAddr,
        timestamp: i64,
    ) -> Result<(), PersistenceError>;

    /// Get timestamps of login attempts for a user within a time window
    fn get_user_attempts_in_window(
        &self,
        user: &str,
        window_start: i64,
    ) -> Result<Vec<i64>, PersistenceError>;

    /// Get timestamps of login attempts from an IP within a time window
    fn get_ip_attempts_in_window(
        &self,
        ip: &str,
        window_start: i64,
    ) -> Result<Vec<i64>, PersistenceError>;

    /// Get count of login attempts for a user within a time window
    fn get_user_attempt_count(
        &self,
        user: &str,
        window_start: i64,
    ) -> Result<usize, PersistenceError> {
        Ok(self.get_user_attempts_in_window(user, window_start)?.len())
    }

    /// Get count of login attempts from an IP within a time window
    fn get_ip_attempt_count(
        &self,
        ip: &str,
        window_start: i64,
    ) -> Result<usize, PersistenceError> {
        Ok(self.get_ip_attempts_in_window(ip, window_start)?.len())
    }

    // =====================
    // Anomaly Report Storage
    // =====================

    /// Store an anomaly report
    fn store_anomaly_report(&self, report: &AnomalyReport) -> Result<(), PersistenceError>;

    /// Get recent anomaly reports
    fn get_recent_reports(&self, limit: usize) -> Result<Vec<AnomalyReport>, PersistenceError>;

    // =====================
    // Maintenance
    // =====================

    /// Remove old data before the specified timestamp
    ///
    /// This is used to prevent unbounded growth of the database
    fn prune_old_data(&self, before_timestamp: i64) -> Result<usize, PersistenceError>;

    /// Clear all data (useful for testing)
    fn clear_all(&self) -> Result<(), PersistenceError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests are in sqlite_store.rs since they need an implementation
}
