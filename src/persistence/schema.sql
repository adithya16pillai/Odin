-- Odin IDS Database Schema
-- SQLite database for persistent state storage

-- User last known IP tracking for IP switch detection
CREATE TABLE IF NOT EXISTS user_last_ip (
    user TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    last_seen INTEGER NOT NULL
);

-- User geographic locations for velocity tracking
CREATE TABLE IF NOT EXISTS user_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    ip TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_locations_user ON user_locations(user);
CREATE INDEX IF NOT EXISTS idx_user_locations_timestamp ON user_locations(timestamp);

-- Login attempts for rate limiting
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    ip TEXT NOT NULL,
    timestamp INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(user);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip);
CREATE INDEX IF NOT EXISTS idx_login_attempts_timestamp ON login_attempts(timestamp);

-- Anomaly reports history for auditing
CREATE TABLE IF NOT EXISTS anomaly_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    user TEXT NOT NULL,
    detected_ip TEXT NOT NULL,
    trusted_ip TEXT,
    timestamp INTEGER NOT NULL,
    description TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_anomaly_reports_timestamp ON anomaly_reports(timestamp);
CREATE INDEX IF NOT EXISTS idx_anomaly_reports_user ON anomaly_reports(user);
CREATE INDEX IF NOT EXISTS idx_anomaly_reports_severity ON anomaly_reports(severity);
