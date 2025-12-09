use std::collections::HashMap;
use crate::models::{LogEvent, AnomalyReport};

/// Geographic coordinates for IP location
#[derive(Debug, Clone, Copy)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
}

/// Tracks user login locations and timestamps for velocity analysis
pub struct GeoVelocityTracker {
    /// Maps user -> (last_timestamp, last_location)
    user_locations: HashMap<String, (i64, GeoLocation)>,
    /// Maximum plausible travel speed in km/h (default: 900 km/h for commercial flight)
    max_velocity_kmh: f64,
}

impl GeoVelocityTracker {
    pub fn new() -> Self {
        GeoVelocityTracker {
            user_locations: HashMap::new(),
            max_velocity_kmh: 900.0,
        }
    }

    pub fn with_max_velocity(max_velocity_kmh: f64) -> Self {
        GeoVelocityTracker {
            user_locations: HashMap::new(),
            max_velocity_kmh,
        }
    }

    /// Check if the user's travel between logins is physically impossible
    pub fn check_impossible_travel(
        &mut self,
        event: &LogEvent,
        current_location: GeoLocation,
    ) -> Option<AnomalyReport> {
        let result = match self.user_locations.get(&event.user) {
            None => None,
            Some((last_timestamp, last_location)) => {
                let time_diff_hours = (event.timestamp - last_timestamp) as f64 / 3600.0;

                // Avoid division by zero for near-simultaneous logins
                if time_diff_hours < 0.001 {
                    return Some(self.create_simultaneous_login_report(
                        event,
                        last_location,
                        &current_location,
                    ));
                }

                let distance_km = haversine_distance(*last_location, current_location);
                let velocity_kmh = distance_km / time_diff_hours;

                if velocity_kmh > self.max_velocity_kmh {
                    Some(AnomalyReport {
                        severity: Self::calculate_severity(velocity_kmh, self.max_velocity_kmh),
                        rule_name: "Impossible Travel Velocity".to_string(),
                        user: event.user.clone(),
                        detected_ip: event.ip_address.to_string(),
                        trusted_ip: String::new(), // N/A for geo-velocity
                        timestamp: event.timestamp,
                        description: format!(
                            "User '{}' traveled {:.1} km in {:.2} hours ({:.0} km/h). \
                             Max plausible speed: {:.0} km/h. Previous location: ({:.4}, {:.4}), \
                             Current location: ({:.4}, {:.4}).",
                            event.user,
                            distance_km,
                            time_diff_hours,
                            velocity_kmh,
                            self.max_velocity_kmh,
                            last_location.latitude,
                            last_location.longitude,
                            current_location.latitude,
                            current_location.longitude
                        ),
                    })
                } else {
                    None
                }
            }
        };

        // Update the user's last known location
        self.user_locations
            .insert(event.user.clone(), (event.timestamp, current_location));

        result
    }

    fn create_simultaneous_login_report(
        &self,
        event: &LogEvent,
        last_location: &GeoLocation,
        current_location: &GeoLocation,
    ) -> AnomalyReport {
        let distance_km = haversine_distance(*last_location, *current_location);
        AnomalyReport {
            severity: 10,
            rule_name: "Simultaneous Multi-Location Login".to_string(),
            user: event.user.clone(),
            detected_ip: event.ip_address.to_string(),
            trusted_ip: String::new(),
            timestamp: event.timestamp,
            description: format!(
                "User '{}' logged in from two locations {:.1} km apart within seconds. \
                 Locations: ({:.4}, {:.4}) and ({:.4}, {:.4}). Likely credential compromise.",
                event.user,
                distance_km,
                last_location.latitude,
                last_location.longitude,
                current_location.latitude,
                current_location.longitude
            ),
        }
    }

    fn calculate_severity(actual_velocity: f64, max_velocity: f64) -> u8 {
        let ratio = actual_velocity / max_velocity;
        if ratio > 10.0 {
            10 // Extreme anomaly
        } else if ratio > 5.0 {
            9
        } else if ratio > 2.0 {
            8
        } else {
            7 // Just over threshold
        }
    }

    /// Clear tracking data for a specific user
    pub fn clear_user(&mut self, user: &str) {
        self.user_locations.remove(user);
    }

    /// Clear all tracking data
    pub fn clear_all(&mut self) {
        self.user_locations.clear();
    }
}

impl Default for GeoVelocityTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate the great-circle distance between two points using the Haversine formula
/// Returns distance in kilometers
fn haversine_distance(loc1: GeoLocation, loc2: GeoLocation) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;

    let lat1_rad = loc1.latitude.to_radians();
    let lat2_rad = loc2.latitude.to_radians();
    let delta_lat = (loc2.latitude - loc1.latitude).to_radians();
    let delta_lon = (loc2.longitude - loc1.longitude).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_KM * c
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
    fn test_haversine_distance() {
        // New York to Los Angeles: ~3944 km
        let nyc = GeoLocation { latitude: 40.7128, longitude: -74.0060 };
        let la = GeoLocation { latitude: 34.0522, longitude: -118.2437 };
        let distance = haversine_distance(nyc, la);
        assert!((distance - 3944.0).abs() < 50.0, "NYC to LA should be ~3944 km, got {}", distance);
    }

    #[test]
    fn test_normal_travel() {
        let mut tracker = GeoVelocityTracker::new();

        // First login from NYC
        let event1 = create_event("bob", 1700000000, "1.1.1.1");
        let nyc = GeoLocation { latitude: 40.7128, longitude: -74.0060 };
        assert!(tracker.check_impossible_travel(&event1, nyc).is_none());

        // Second login from LA after 6 hours (plausible flight)
        let event2 = create_event("bob", 1700000000 + 6 * 3600, "2.2.2.2");
        let la = GeoLocation { latitude: 34.0522, longitude: -118.2437 };
        assert!(tracker.check_impossible_travel(&event2, la).is_none());
    }

    #[test]
    fn test_impossible_travel() {
        let mut tracker = GeoVelocityTracker::new();

        // First login from NYC
        let event1 = create_event("alice", 1700000000, "1.1.1.1");
        let nyc = GeoLocation { latitude: 40.7128, longitude: -74.0060 };
        assert!(tracker.check_impossible_travel(&event1, nyc).is_none());

        // Second login from Tokyo after only 1 hour (impossible)
        let event2 = create_event("alice", 1700000000 + 3600, "3.3.3.3");
        let tokyo = GeoLocation { latitude: 35.6762, longitude: 139.6503 };

        let report = tracker.check_impossible_travel(&event2, tokyo);
        assert!(report.is_some(), "Should detect impossible travel");
        let report = report.unwrap();
        assert!(report.severity >= 9, "High severity expected for extreme velocity");
        assert!(report.description.contains("alice"));
    }

    #[test]
    fn test_simultaneous_login() {
        let mut tracker = GeoVelocityTracker::new();

        let event1 = create_event("charlie", 1700000000, "1.1.1.1");
        let london = GeoLocation { latitude: 51.5074, longitude: -0.1278 };
        tracker.check_impossible_travel(&event1, london);

        // Login from Sydney 1 second later
        let event2 = create_event("charlie", 1700000001, "4.4.4.4");
        let sydney = GeoLocation { latitude: -33.8688, longitude: 151.2093 };

        let report = tracker.check_impossible_travel(&event2, sydney);
        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.severity, 10);
        assert!(report.rule_name.contains("Simultaneous"));
    }
}
