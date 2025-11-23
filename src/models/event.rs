use std::net::IpAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct LogEvent {
    pub timestamp: i64,
    pub user: String,
    pub ip_address: IpAddr,
    pub event_type: String, 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub severity: u8,
    pub rule_name: String,
    pub user: String,
    pub detected_ip: String,
    pub trusted_ip: String,
    pub timestamp: i64,
    pub description: String,
}