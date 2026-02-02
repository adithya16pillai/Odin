//! IP Geolocation module using MaxMind GeoLite2 database
//!
//! This module provides IP-to-geographic-location lookups using the MaxMind
//! GeoLite2-City database. Users must download the database file separately
//! from MaxMind (free with registration).

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

use crate::detection::GeoLocation;

/// Errors that can occur during geolocation lookups
#[derive(Error, Debug)]
pub enum GeoError {
    #[error("Failed to open database: {0}")]
    DatabaseOpen(#[from] maxminddb::MaxMindDBError),

    #[error("IP address not found in database")]
    NotFound,

    #[error("Location data missing for IP address")]
    NoLocation,

    #[error("Database file not found: {0}")]
    FileNotFound(String),
}

/// GeoIP lookup service using MaxMind GeoLite2-City database
///
/// This service wraps the MaxMind database reader and provides convenient
/// methods for looking up geographic coordinates from IP addresses.
///
/// # Example
///
/// ```ignore
/// use odin::geolocation::GeoIpService;
/// use std::net::IpAddr;
/// use std::str::FromStr;
///
/// let service = GeoIpService::new("GeoLite2-City.mmdb")?;
/// let ip = IpAddr::from_str("8.8.8.8").unwrap();
/// if let Some(location) = service.lookup_optional(&ip) {
///     println!("Location: {}, {}", location.latitude, location.longitude);
/// }
/// ```
pub struct GeoIpService {
    reader: Arc<Reader<Vec<u8>>>,
}

impl GeoIpService {
    /// Create a new GeoIP service from a MaxMind database file
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the GeoLite2-City.mmdb database file
    ///
    /// # Errors
    ///
    /// Returns an error if the database file cannot be opened or is invalid.
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, GeoError> {
        let path = db_path.as_ref();
        if !path.exists() {
            return Err(GeoError::FileNotFound(path.display().to_string()));
        }

        let reader = Reader::open_readfile(path)?;
        Ok(GeoIpService {
            reader: Arc::new(reader),
        })
    }

    /// Look up the geographic location of an IP address
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to look up (IPv4 or IPv6)
    ///
    /// # Returns
    ///
    /// Returns `Ok(GeoLocation)` with latitude and longitude if found,
    /// or an error if the IP is not in the database or has no location data.
    pub fn lookup(&self, ip: &IpAddr) -> Result<GeoLocation, GeoError> {
        let city: geoip2::City = self.reader.lookup(*ip).map_err(|e| {
            match e {
                maxminddb::MaxMindDBError::AddressNotFoundError(_) => GeoError::NotFound,
                other => GeoError::DatabaseOpen(other),
            }
        })?;

        let location = city.location.ok_or(GeoError::NoLocation)?;
        let latitude = location.latitude.ok_or(GeoError::NoLocation)?;
        let longitude = location.longitude.ok_or(GeoError::NoLocation)?;

        Ok(GeoLocation {
            latitude,
            longitude,
        })
    }

    /// Look up an IP address, returning None instead of an error
    ///
    /// This is a convenience method that converts errors to None,
    /// useful when you want to silently skip IPs that can't be located.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to look up
    ///
    /// # Returns
    ///
    /// Returns `Some(GeoLocation)` if found, `None` otherwise.
    pub fn lookup_optional(&self, ip: &IpAddr) -> Option<GeoLocation> {
        self.lookup(ip).ok()
    }

    /// Check if an IP address is in the database
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.lookup(ip).is_ok()
    }

    /// Get additional city information for an IP address
    ///
    /// Returns the full city record including country, city name, etc.
    pub fn lookup_city_info(&self, ip: &IpAddr) -> Result<CityInfo, GeoError> {
        let city: geoip2::City = self.reader.lookup(*ip).map_err(|e| {
            match e {
                maxminddb::MaxMindDBError::AddressNotFoundError(_) => GeoError::NotFound,
                other => GeoError::DatabaseOpen(other),
            }
        })?;

        let location = city.location.ok_or(GeoError::NoLocation)?;

        Ok(CityInfo {
            city_name: city.city
                .and_then(|c| c.names)
                .and_then(|n| n.get("en").copied())
                .map(String::from),
            country_name: city.country
                .and_then(|c| c.names)
                .and_then(|n| n.get("en").copied())
                .map(String::from),
            country_code: city.country
                .and_then(|c| c.iso_code)
                .map(String::from),
            latitude: location.latitude.unwrap_or(0.0),
            longitude: location.longitude.unwrap_or(0.0),
            timezone: location.time_zone.map(String::from),
            accuracy_radius: location.accuracy_radius,
        })
    }
}

impl Clone for GeoIpService {
    fn clone(&self) -> Self {
        GeoIpService {
            reader: Arc::clone(&self.reader),
        }
    }
}

/// Extended city information from the GeoIP database
#[derive(Debug, Clone)]
pub struct CityInfo {
    /// City name in English
    pub city_name: Option<String>,
    /// Country name in English
    pub country_name: Option<String>,
    /// ISO 3166-1 alpha-2 country code
    pub country_code: Option<String>,
    /// Latitude coordinate
    pub latitude: f64,
    /// Longitude coordinate
    pub longitude: f64,
    /// Timezone identifier (e.g., "America/New_York")
    pub timezone: Option<String>,
    /// Accuracy radius in kilometers
    pub accuracy_radius: Option<u16>,
}

impl CityInfo {
    /// Get a human-readable location string
    pub fn display_location(&self) -> String {
        match (&self.city_name, &self.country_name) {
            (Some(city), Some(country)) => format!("{}, {}", city, country),
            (None, Some(country)) => country.clone(),
            (Some(city), None) => city.clone(),
            (None, None) => format!("({:.4}, {:.4})", self.latitude, self.longitude),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Note: These tests require a GeoLite2-City.mmdb file to be present.
    // They will be skipped if the file is not available.

    fn get_test_service() -> Option<GeoIpService> {
        // Try common locations for the database file
        let paths = [
            "GeoLite2-City.mmdb",
            "../GeoLite2-City.mmdb",
            "../../GeoLite2-City.mmdb",
            "assets/GeoLite2-City.mmdb",
        ];

        for path in &paths {
            if let Ok(service) = GeoIpService::new(path) {
                return Some(service);
            }
        }
        None
    }

    #[test]
    fn test_file_not_found() {
        let result = GeoIpService::new("nonexistent.mmdb");
        assert!(matches!(result, Err(GeoError::FileNotFound(_))));
    }

    #[test]
    fn test_private_ip_not_found() {
        if let Some(service) = get_test_service() {
            // Private IPs are not in the GeoIP database
            let private_ip = IpAddr::from_str("192.168.1.1").unwrap();
            let result = service.lookup(&private_ip);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_localhost_not_found() {
        if let Some(service) = get_test_service() {
            let localhost = IpAddr::from_str("127.0.0.1").unwrap();
            let result = service.lookup(&localhost);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_public_ip_lookup() {
        if let Some(service) = get_test_service() {
            // Google's public DNS - should be in any GeoIP database
            let google_dns = IpAddr::from_str("8.8.8.8").unwrap();
            let result = service.lookup(&google_dns);

            // The lookup might succeed or fail depending on database version
            // but it should not panic
            match result {
                Ok(location) => {
                    // Verify coordinates are reasonable (not 0,0)
                    assert!(location.latitude != 0.0 || location.longitude != 0.0);
                    // Verify coordinates are within valid range
                    assert!(location.latitude >= -90.0 && location.latitude <= 90.0);
                    assert!(location.longitude >= -180.0 && location.longitude <= 180.0);
                }
                Err(_) => {
                    // This is also acceptable if the IP is not in the database
                }
            }
        }
    }

    #[test]
    fn test_lookup_optional() {
        if let Some(service) = get_test_service() {
            // Private IP should return None, not panic
            let private_ip = IpAddr::from_str("10.0.0.1").unwrap();
            assert!(service.lookup_optional(&private_ip).is_none());
        }
    }

    #[test]
    fn test_clone() {
        if let Some(service) = get_test_service() {
            let cloned = service.clone();
            // Both should work independently
            let ip = IpAddr::from_str("8.8.8.8").unwrap();
            let _r1 = service.lookup_optional(&ip);
            let _r2 = cloned.lookup_optional(&ip);
        }
    }
}
