//! SQLite implementation of the StateStore trait

use super::{PersistenceError, StateStore};
use crate::detection::GeoLocation;
use crate::models::AnomalyReport;
use rusqlite::{params, Connection};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;

/// SQLite-based state storage
///
/// This implementation stores all detection state in a SQLite database,
/// providing persistence across daemon restarts.
pub struct SqliteStateStore {
    conn: Mutex<Connection>,
}

impl SqliteStateStore {
    /// Create a new SQLite state store at the specified path
    ///
    /// Creates the database file and initializes the schema if it doesn't exist.
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, PersistenceError> {
        let conn = Connection::open(db_path)?;
        let store = SqliteStateStore {
            conn: Mutex::new(conn),
        };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Create an in-memory SQLite database (useful for testing)
    pub fn in_memory() -> Result<Self, PersistenceError> {
        let conn = Connection::open_in_memory()?;
        let store = SqliteStateStore {
            conn: Mutex::new(conn),
        };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Initialize the database schema
    fn initialize_schema(&self) -> Result<(), PersistenceError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(include_str!("schema.sql"))?;
        Ok(())
    }

    /// Helper to parse IP address from database string
    fn parse_ip(ip_str: &str) -> Result<IpAddr, PersistenceError> {
        IpAddr::from_str(ip_str)
            .map_err(|_| PersistenceError::InvalidData(format!("Invalid IP address: {}", ip_str)))
    }
}

impl StateStore for SqliteStateStore {
    fn get_user_last_ip(&self, user: &str) -> Result<Option<(IpAddr, i64)>, PersistenceError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip, last_seen FROM user_last_ip WHERE user = ?"
        )?;

        let result = stmt.query_row(params![user], |row| {
            let ip_str: String = row.get(0)?;
            let timestamp: i64 = row.get(1)?;
            Ok((ip_str, timestamp))
        });

        match result {
            Ok((ip_str, timestamp)) => {
                let ip = Self::parse_ip(&ip_str)?;
                Ok(Some((ip, timestamp)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set_user_last_ip(
        &self,
        user: &str,
        ip: &IpAddr,
        timestamp: i64,
    ) -> Result<(), PersistenceError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO user_last_ip (user, ip, last_seen) VALUES (?, ?, ?)",
            params![user, ip.to_string(), timestamp],
        )?;
        Ok(())
    }

    fn get_user_last_location(
        &self,
        user: &str,
    ) -> Result<Option<(i64, GeoLocation)>, PersistenceError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT timestamp, latitude, longitude FROM user_locations
             WHERE user = ? ORDER BY timestamp DESC LIMIT 1"
        )?;

        let result = stmt.query_row(params![user], |row| {
            let timestamp: i64 = row.get(0)?;
            let latitude: f64 = row.get(1)?;
            let longitude: f64 = row.get(2)?;
            Ok((timestamp, GeoLocation { latitude, longitude }))
        });

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn add_user_location(
        &self,
        user: &str,
        timestamp: i64,
        location: &GeoLocation,
        ip: &IpAddr,
    ) -> Result<(), PersistenceError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO user_locations (user, timestamp, latitude, longitude, ip)
             VALUES (?, ?, ?, ?, ?)",
            params![
                user,
                timestamp,
                location.latitude,
                location.longitude,
                ip.to_string()
            ],
        )?;
        Ok(())
    }

    fn add_login_attempt(
        &self,
        user: &str,
        ip: &IpAddr,
        timestamp: i64,
    ) -> Result<(), PersistenceError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO login_attempts (user, ip, timestamp) VALUES (?, ?, ?)",
            params![user, ip.to_string(), timestamp],
        )?;
        Ok(())
    }

    fn get_user_attempts_in_window(
        &self,
        user: &str,
        window_start: i64,
    ) -> Result<Vec<i64>, PersistenceError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT timestamp FROM login_attempts
             WHERE user = ? AND timestamp >= ?
             ORDER BY timestamp DESC"
        )?;

        let timestamps = stmt
            .query_map(params![user, window_start], |row| row.get(0))?
            .collect::<Result<Vec<i64>, _>>()?;

        Ok(timestamps)
    }

    fn get_ip_attempts_in_window(
        &self,
        ip: &str,
        window_start: i64,
    ) -> Result<Vec<i64>, PersistenceError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT timestamp FROM login_attempts
             WHERE ip = ? AND timestamp >= ?
             ORDER BY timestamp DESC"
        )?;

        let timestamps = stmt
            .query_map(params![ip, window_start], |row| row.get(0))?
            .collect::<Result<Vec<i64>, _>>()?;

        Ok(timestamps)
    }

    fn store_anomaly_report(&self, report: &AnomalyReport) -> Result<(), PersistenceError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO anomaly_reports
             (severity, rule_name, user, detected_ip, trusted_ip, timestamp, description)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                report.severity,
                report.rule_name,
                report.user,
                report.detected_ip,
                report.trusted_ip,
                report.timestamp,
                report.description
            ],
        )?;
        Ok(())
    }

    fn get_recent_reports(&self, limit: usize) -> Result<Vec<AnomalyReport>, PersistenceError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT severity, rule_name, user, detected_ip, trusted_ip, timestamp, description
             FROM anomaly_reports
             ORDER BY created_at DESC
             LIMIT ?"
        )?;

        let reports = stmt
            .query_map(params![limit], |row| {
                Ok(AnomalyReport {
                    severity: row.get(0)?,
                    rule_name: row.get(1)?,
                    user: row.get(2)?,
                    detected_ip: row.get(3)?,
                    trusted_ip: row.get(4)?,
                    timestamp: row.get(5)?,
                    description: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(reports)
    }

    fn prune_old_data(&self, before_timestamp: i64) -> Result<usize, PersistenceError> {
        let conn = self.conn.lock().unwrap();

        let mut total_deleted = 0usize;

        // Prune user locations
        total_deleted += conn.execute(
            "DELETE FROM user_locations WHERE timestamp < ?",
            params![before_timestamp],
        )?;

        // Prune login attempts
        total_deleted += conn.execute(
            "DELETE FROM login_attempts WHERE timestamp < ?",
            params![before_timestamp],
        )?;

        // Keep anomaly reports longer (30 days instead of window)
        let report_cutoff = before_timestamp - (30 * 24 * 3600);
        total_deleted += conn.execute(
            "DELETE FROM anomaly_reports WHERE timestamp < ?",
            params![report_cutoff],
        )?;

        Ok(total_deleted)
    }

    fn clear_all(&self) -> Result<(), PersistenceError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "DELETE FROM user_last_ip;
             DELETE FROM user_locations;
             DELETE FROM login_attempts;
             DELETE FROM anomaly_reports;"
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_store() -> SqliteStateStore {
        SqliteStateStore::in_memory().expect("Failed to create in-memory store")
    }

    #[test]
    fn test_user_ip_roundtrip() {
        let store = create_test_store();
        let user = "testuser";
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let timestamp = 1700000000;

        // Initially no IP
        assert!(store.get_user_last_ip(user).unwrap().is_none());

        // Set IP
        store.set_user_last_ip(user, &ip, timestamp).unwrap();

        // Retrieve IP
        let (stored_ip, stored_timestamp) = store.get_user_last_ip(user).unwrap().unwrap();
        assert_eq!(stored_ip, ip);
        assert_eq!(stored_timestamp, timestamp);
    }

    #[test]
    fn test_user_ip_update() {
        let store = create_test_store();
        let user = "testuser";
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.1".parse().unwrap();

        store.set_user_last_ip(user, &ip1, 1000).unwrap();
        store.set_user_last_ip(user, &ip2, 2000).unwrap();

        let (stored_ip, stored_timestamp) = store.get_user_last_ip(user).unwrap().unwrap();
        assert_eq!(stored_ip, ip2);
        assert_eq!(stored_timestamp, 2000);
    }

    #[test]
    fn test_user_location() {
        let store = create_test_store();
        let user = "testuser";
        let location = GeoLocation {
            latitude: 40.7128,
            longitude: -74.0060,
        };
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let timestamp = 1700000000;

        // Initially no location
        assert!(store.get_user_last_location(user).unwrap().is_none());

        // Add location
        store.add_user_location(user, timestamp, &location, &ip).unwrap();

        // Retrieve location
        let (stored_ts, stored_loc) = store.get_user_last_location(user).unwrap().unwrap();
        assert_eq!(stored_ts, timestamp);
        assert!((stored_loc.latitude - location.latitude).abs() < 0.0001);
        assert!((stored_loc.longitude - location.longitude).abs() < 0.0001);
    }

    #[test]
    fn test_login_attempts() {
        let store = create_test_store();
        let user = "testuser";
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Add attempts at different timestamps
        store.add_login_attempt(user, &ip, 1000).unwrap();
        store.add_login_attempt(user, &ip, 2000).unwrap();
        store.add_login_attempt(user, &ip, 3000).unwrap();

        // Get attempts in window
        let attempts = store.get_user_attempts_in_window(user, 1500).unwrap();
        assert_eq!(attempts.len(), 2); // 2000 and 3000

        let ip_attempts = store.get_ip_attempts_in_window(&ip.to_string(), 1500).unwrap();
        assert_eq!(ip_attempts.len(), 2);
    }

    #[test]
    fn test_anomaly_report() {
        let store = create_test_store();
        let report = AnomalyReport {
            severity: 8,
            rule_name: "Test Rule".to_string(),
            user: "testuser".to_string(),
            detected_ip: "1.2.3.4".to_string(),
            trusted_ip: "5.6.7.8".to_string(),
            timestamp: 1700000000,
            description: "Test anomaly".to_string(),
        };

        store.store_anomaly_report(&report).unwrap();

        let reports = store.get_recent_reports(10).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].rule_name, "Test Rule");
        assert_eq!(reports[0].severity, 8);
    }

    #[test]
    fn test_prune_old_data() {
        let store = create_test_store();
        let user = "testuser";
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let location = GeoLocation {
            latitude: 40.0,
            longitude: -74.0,
        };

        // Add old data
        store.add_login_attempt(user, &ip, 1000).unwrap();
        store.add_user_location(user, 1000, &location, &ip).unwrap();

        // Add new data
        store.add_login_attempt(user, &ip, 5000).unwrap();
        store.add_user_location(user, 5000, &location, &ip).unwrap();

        // Prune data older than 3000
        let deleted = store.prune_old_data(3000).unwrap();
        assert!(deleted > 0);

        // Old data should be gone
        let attempts = store.get_user_attempts_in_window(user, 0).unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0], 5000);
    }

    #[test]
    fn test_clear_all() {
        let store = create_test_store();
        let user = "testuser";
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        store.set_user_last_ip(user, &ip, 1000).unwrap();
        store.add_login_attempt(user, &ip, 1000).unwrap();

        store.clear_all().unwrap();

        assert!(store.get_user_last_ip(user).unwrap().is_none());
        assert!(store.get_user_attempts_in_window(user, 0).unwrap().is_empty());
    }

    #[test]
    fn test_ipv6_support() {
        let store = create_test_store();
        let user = "testuser";
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();

        store.set_user_last_ip(user, &ipv6, 1000).unwrap();
        let (stored_ip, _) = store.get_user_last_ip(user).unwrap().unwrap();
        assert_eq!(stored_ip, ipv6);
    }

    #[test]
    fn test_multiple_users() {
        let store = create_test_store();
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();

        store.set_user_last_ip("user1", &ip1, 1000).unwrap();
        store.set_user_last_ip("user2", &ip2, 2000).unwrap();

        let (stored_ip1, _) = store.get_user_last_ip("user1").unwrap().unwrap();
        let (stored_ip2, _) = store.get_user_last_ip("user2").unwrap().unwrap();

        assert_eq!(stored_ip1, ip1);
        assert_eq!(stored_ip2, ip2);
    }
}
