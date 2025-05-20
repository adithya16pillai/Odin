use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub fingerprint_hash: String,
    pub os: Option<String>,
    pub browser: Option<String>,
    pub screen_resolution: Option<String>,
    pub timezone: Option<String>,
    pub language: Option<String>,
    pub installed_fonts: Option<Vec<String>>,
    pub canvas_fingerprint: Option<String>,
    pub webgl_fingerprint: Option<String>,
    pub audio_fingerprint: Option<String>,
    pub hardware_concurrency: Option<i32>,
    pub device_memory: Option<f64>,
}

impl DeviceFingerprint {
    pub fn new(
        os: Option<String>,
        browser: Option<String>,
        screen_resolution: Option<String>,
        timezone: Option<String>,
        language: Option<String>,
        installed_fonts: Option<Vec<String>>,
        canvas_fingerprint: Option<String>,
        webgl_fingerprint: Option<String>,
        audio_fingerprint: Option<String>,
        hardware_concurrency: Option<i32>,
        device_memory: Option<f64>,
    ) -> Self {
        let mut fingerprint = Self {
            id: Uuid::new_v4(),
            fingerprint_hash: String::new(),
            os,
            browser,
            screen_resolution,
            timezone,
            language,
            installed_fonts,
            canvas_fingerprint,
            webgl_fingerprint,
            audio_fingerprint,
            hardware_concurrency,
            device_memory,
        };
        
        // Generate fingerprint hash
        fingerprint.fingerprint_hash = fingerprint.generate_hash();
        fingerprint
    }
    
    // Generate a unique hash for this device fingerprint
    fn generate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        
        // Add device properties to hash
        if let Some(os) = &self.os {
            hasher.update(os.as_bytes());
        }
        if let Some(browser) = &self.browser {
            hasher.update(browser.as_bytes());
        }
        if let Some(resolution) = &self.screen_resolution {
            hasher.update(resolution.as_bytes());
        }
        if let Some(canvas) = &self.canvas_fingerprint {
            hasher.update(canvas.as_bytes());
        }
        if let Some(webgl) = &self.webgl_fingerprint {
            hasher.update(webgl.as_bytes());
        }
        if let Some(audio) = &self.audio_fingerprint {
            hasher.update(audio.as_bytes());
        }
        
        // Generate hash
        let result = hasher.finalize();
        format!("{:x}", result)
    }
    
    // Similarity score with another fingerprint (0.0 to 1.0)
    pub fn similarity(&self, other: &Self) -> f64 {
        let mut matches = 0;
        let mut total = 0;
        
        // Compare browser and OS
        if let (Some(os1), Some(os2)) = (&self.os, &other.os) {
            total += 1;
            if os1 == os2 {
                matches += 1;
            }
        }
        
        if let (Some(browser1), Some(browser2)) = (&self.browser, &other.browser) {
            total += 1;
            if browser1 == browser2 {
                matches += 1;
            }
        }
        
        // Compare other properties
        if let (Some(res1), Some(res2)) = (&self.screen_resolution, &other.screen_resolution) {
            total += 1;
            if res1 == res2 {
                matches += 1;
            }
        }
        
        if let (Some(tz1), Some(tz2)) = (&self.timezone, &other.timezone) {
            total += 1;
            if tz1 == tz2 {
                matches += 1;
            }
        }
        
        if let (Some(lang1), Some(lang2)) = (&self.language, &other.language) {
            total += 1;
            if lang1 == lang2 {
                matches += 1;
            }
        }
        
        // Advanced fingerprint comparison
        if let (Some(canvas1), Some(canvas2)) = (&self.canvas_fingerprint, &other.canvas_fingerprint) {
            total += 2; // Weighted higher
            if canvas1 == canvas2 {
                matches += 2;
            }
        }
        
        if let (Some(webgl1), Some(webgl2)) = (&self.webgl_fingerprint, &other.webgl_fingerprint) {
            total += 2; // Weighted higher
            if webgl1 == webgl2 {
                matches += 2;
            }
        }
        
        if total == 0 {
            return 0.0;
        }
        
        matches as f64 / total as f64
    }
}
