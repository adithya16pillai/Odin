class RiskAssessmentService
  def initialize(login_attempt)
    @login_attempt = login_attempt
    @user = login_attempt.user
  end
  
  def assess_risk
    risk_factors = []
    anomalies = []
    risk_score = 0.0
    
    # Check for unusual IP address
    if unusual_ip?
      risk_factors << "Unusual IP address"
      risk_score += 0.3
    end
    
    # Check for unusual user agent
    if unusual_user_agent?
      risk_factors << "Unusual user agent"
      risk_score += 0.2
    end
    
    # Check for rapid login attempts
    if rapid_attempts?
      risk_factors << "Rapid login attempts"
      risk_score += 0.4
    end
    
    # Check for failed attempts from same IP
    if recent_failed_attempts?
      risk_factors << "Recent failed attempts from same IP"
      risk_score += 0.3
    end
    
    # Check for device fingerprint changes
    if device_fingerprint_changed?
      risk_factors << "Device fingerprint changed"
      risk_score += 0.2
    end
    
    # Check for time-based anomalies
    if unusual_time?
      risk_factors << "Unusual login time"
      risk_score += 0.1
    end
    
    # Cap risk score at 1.0
    risk_score = [risk_score, 1.0].min
    
    {
      risk_score: risk_score,
      risk_level: determine_risk_level(risk_score),
      factors: risk_factors,
      anomalies: anomalies,
      recommendations: generate_recommendations(risk_score, risk_factors)
    }
  end
  
  private
  
  def unusual_ip?
    # Check if IP is from a different country/region than usual
    # This would integrate with geo-ip services
    false # Placeholder
  end
  
  def unusual_user_agent?
    # Check if user agent is significantly different from previous ones
    previous_agents = @user.login_attempts.recent(30).pluck(:user_agent).uniq
    return false if previous_agents.empty?
    
    current_agent = @login_attempt.user_agent
    previous_agents.none? { |agent| similar_user_agents?(current_agent, agent) }
  end
  
  def rapid_attempts?
    # Check for multiple attempts in short time period
    @user.login_attempts.where('created_at > ?', 5.minutes.ago).count > 3
  end
  
  def recent_failed_attempts?
    # Check for recent failed attempts from same IP
    LoginAttempt.where(
      ip_address: @login_attempt.ip_address,
      success: false,
      created_at: 1.hour.ago..Time.current
    ).count > 2
  end
  
  def device_fingerprint_changed?
    # Check if device fingerprint is significantly different
    # This would integrate with device fingerprinting
    false # Placeholder
  end
  
  def unusual_time?
    # Check if login is at unusual time for user
    hour = @login_attempt.created_at.hour
    # Unusual if between 2 AM and 6 AM
    hour >= 2 && hour <= 6
  end
  
  def similar_user_agents?(agent1, agent2)
    # Simple similarity check - in production, use more sophisticated matching
    agent1.split(' ').first == agent2.split(' ').first
  end
  
  def determine_risk_level(score)
    case score
    when 0.0..0.3
      "low"
    when 0.3..0.6
      "medium"
    when 0.6..0.8
      "high"
    else
      "critical"
    end
  end
  
  def generate_recommendations(score, factors)
    recommendations = []
    
    if score > 0.6
      recommendations << "Consider requiring additional authentication"
    end
    
    if factors.include?("Rapid login attempts")
      recommendations << "Implement rate limiting"
    end
    
    if factors.include?("Unusual IP address")
      recommendations << "Verify user location"
    end
    
    if score > 0.8
      recommendations << "Block access and require manual review"
    end
    
    recommendations
  end
end
