use std::collections::HashMap;
use std::net::IpAddr;
use crate::models::{LogEvent, AnomalyReport}; 

pub struct IdentityContext {
    pub last_known_ip: HashMap<String, IpAddr>,
}

impl IdentityContext {
    pub fn new() -> Self {
        IdentityContext {
            last_known_ip: HashMap::new(),
        }
    }

    pub fn check_for_ip_switch(&mut self, event: &LogEvent) -> Option<AnomalyReport> {
        
        match self.last_known_ip.get(&event.user) {
            
            None => {
                self.last_known_ip.insert(event.user.clone(), event.ip_address);
                None
            }
            
            Some(trusted_ip) => {
                if event.ip_address == *trusted_ip {
                    None
                } else {
                    Some(AnomalyReport {
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
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ip_switch_anomaly() {
        let mut context = IdentityContext::new();

        let event1 = LogEvent {
            timestamp: 1700000000, user: "alice".to_string(),
            ip_address: IpAddr::from_str("1.1.1.1").unwrap(), event_type: "SSH_LOGIN".to_string()
        };
        assert!(context.check_for_ip_switch(&event1).is_none());

        let event2 = LogEvent {
            timestamp: 1700000005, user: "alice".to_string(),
            ip_address: IpAddr::from_str("2.2.2.2").unwrap(), event_type: "SSH_LOGIN".to_string()
        };
        let report = context.check_for_ip_switch(&event2);
        assert!(report.is_some());
        assert_eq!(report.unwrap().trusted_ip, "1.1.1.1");
    }
}