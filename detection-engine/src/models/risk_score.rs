use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskFactor {
    NewDevice,
    UnusualLocation,
    UnusualLoginTime,
    ImpossibleTravel,
    TooManyAttempts,
    UnknownProxy,
    AnomalousActivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub login_attempt_id: Uuid,
    pub risk_score: f64,
    pub risk_factors: Vec<RiskFactor>,
    pub confidence: f64,
    pub recommendation: String,
    pub created_at: DateTime<Utc>,
}

impl RiskAssessment {
    pub fn new(
        login_attempt_id: Uuid,
        risk_score: f64,
        risk_factors: Vec<RiskFactor>,
        confidence: f64,
    ) -> Self {
        let recommendation = if risk_score > 0.8 {
            "High risk - Request additional verification"
        } else if risk_score > 0.5 {
            "Medium risk - Monitor activity"
        } else {
            "Low risk - Allow access"
        };
        
        Self {
            id: Uuid::new_v4(),
            login_attempt_id,
            risk_score,
            risk_factors,
            confidence,
            recommendation: recommendation.to_string(),
            created_at: Utc::now(),
        }
    }
    
    pub fn is_high_risk(&self) -> bool {
        self.risk_score > 0.8
    }
    
    pub fn is_medium_risk(&self) -> bool {
        self.risk_score > 0.5 && self.risk_score <= 0.8
    }
    
    pub fn is_low_risk(&self) -> bool {
        self.risk_score <= 0.5
    }
}