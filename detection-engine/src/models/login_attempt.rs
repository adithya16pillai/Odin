use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use super::{AccessMetadata, DeviceFingerprint};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub user_id: Uuid,
    pub successful: bool,
    pub device_fingerprint: DeviceFingerprint,
    pub access_metadata: AccessMetadata,
    pub created_at: DateTime<Utc>,
}

impl LoginAttempt {
    pub fn new(
        user_id: Uuid,
        device_fingerprint: DeviceFingerprint,
        access_metadata: AccessMetadata,
        successful: bool,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            successful,
            device_fingerprint,
            access_metadata,
            created_at: Utc::now(),
        }
    }
    
    pub fn is_same_device(&self, other: &Self) -> bool {
        self.device_fingerprint.fingerprint_hash == other.device_fingerprint.fingerprint_hash
    }
    
    pub fn is_same_location(&self, other: &Self, radius_km: f64) -> bool {
        let distance = self.access_metadata.distance_to(&other.access_metadata);
        distance <= radius_km
    }
    
    pub fn time_since(&self, other: &Self) -> chrono::Duration {
        self.access_metadata.timestamp - other.access_metadata.timestamp
    }
}