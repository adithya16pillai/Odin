use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::f64::consts::PI;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessMetadata {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub ip_address: String,
    pub user_agent: String, 
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub isp: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl AccessMetadata {
    pub fn new(
        ip_address: String,
        user_agent: String,
        country: Option<String>,
        city: Option<String>,
        latitude: f64,
        longitude: f64,
        isp: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            ip_address,
            user_agent,
            country,
            city,
            latitude,
            longitude,
            isp,
            timestamp: Utc::now(),
        }
    }
    
    // Calculate distance in kilometers between two geo coordinates
    pub fn distance_to(&self, other: &Self) -> f64 {
        const EARTH_RADIUS: f64 = 6371.0; // km
        
        let lat1_rad = self.latitude * PI / 180.0;
        let lat2_rad = other.latitude * PI / 180.0;
        let delta_lat = (other.latitude - self.latitude) * PI / 180.0;
        let delta_lon = (other.longitude - self.longitude) * PI / 180.0;
        
        let a = (delta_lat / 2.0).sin() * (delta_lat / 2.0).sin() + 
                lat1_rad.cos() * lat2_rad.cos() * 
                (delta_lon / 2.0).sin() * (delta_lon / 2.0).sin();
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        
        EARTH_RADIUS * c
    }
    
    // Calculate speed in km/h between this and previous access
    pub fn travel_speed(&self, previous: &Self) -> Option<f64> {
        let distance = self.distance_to(previous);
        let time_diff = self.timestamp.signed_duration_since(previous.timestamp);
        
        // Convert time difference to hours
        let hours = time_diff.num_seconds() as f64 / 3600.0;
        
        if hours > 0.0 {
            Some(distance / hours)
        } else {
            None
        }
    }
}