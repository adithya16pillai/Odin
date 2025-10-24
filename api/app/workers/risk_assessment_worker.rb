class RiskAssessmentWorker
  include Sidekiq::Worker
  
  sidekiq_options queue: :analysis, retry: 2
  
  def perform(login_attempt_id)
    login_attempt = LoginAttempt.find_by(id: login_attempt_id)
    return unless login_attempt
    
    Rails.logger.info "Performing risk assessment for login attempt #{login_attempt_id}"
    
    # Perform risk assessment
    risk_service = RiskAssessmentService.new(login_attempt)
    assessment = risk_service.assess_risk
    
    # Store risk assessment results
    # This would typically be stored in a separate RiskAssessment model
    # For now, we'll log the results
    Rails.logger.info "Risk assessment completed: #{assessment}"
    
    # If risk is high, trigger additional security measures
    if assessment[:risk_level] == "high" || assessment[:risk_level] == "critical"
      trigger_security_alert(login_attempt, assessment)
    end
    
    # Perform additional security analysis
    analyzer = SecurityAnalyzerService.new(
      login_attempt.user,
      login_attempt.ip_address,
      login_attempt.user_agent
    )
    
    security_analysis = analyzer.analyze_session_security
    anomalies = analyzer.detect_anomalies
    
    Rails.logger.info "Security analysis completed: #{security_analysis}"
    Rails.logger.info "Detected anomalies: #{anomalies}" if anomalies.any?
    
    # Store analysis results
    # This would typically be stored in a SecurityAnalysis model
    store_security_analysis(login_attempt, security_analysis, anomalies)
  end
  
  private
  
  def trigger_security_alert(login_attempt, assessment)
    Rails.logger.warn "HIGH RISK LOGIN DETECTED"
    Rails.logger.warn "User: #{login_attempt.user.email}"
    Rails.logger.warn "IP: #{login_attempt.ip_address}"
    Rails.logger.warn "Risk Level: #{assessment[:risk_level]}"
    Rails.logger.warn "Risk Score: #{assessment[:risk_score]}"
    Rails.logger.warn "Factors: #{assessment[:factors].join(', ')}"
    
    # In a real application, this would:
    # - Send notifications to security team
    # - Log to security monitoring system
    # - Potentially block the session
    # - Send alerts to user
  end
  
  def store_security_analysis(login_attempt, analysis, anomalies)
    # This would store the analysis in a database table
    # For now, we'll just log it
    Rails.logger.info "Storing security analysis for login attempt #{login_attempt.id}"
    Rails.logger.info "Analysis: #{analysis}"
    Rails.logger.info "Anomalies: #{anomalies}"
  end
end
