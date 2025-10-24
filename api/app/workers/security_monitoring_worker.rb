class SecurityMonitoringWorker
  include Sidekiq::Worker
  
  sidekiq_options queue: :monitoring, retry: 1
  
  def perform
    Rails.logger.info "Starting security monitoring analysis..."
    
    # Analyze recent failed login attempts
    analyze_failed_attempts
    
    # Check for suspicious patterns
    detect_suspicious_patterns
    
    # Monitor for brute force attacks
    detect_brute_force_attempts
    
    # Check for account takeover attempts
    detect_account_takeover_attempts
    
    Rails.logger.info "Security monitoring analysis completed"
  end
  
  private
  
  def analyze_failed_attempts
    recent_failed = LoginAttempt.failed.recent(1)
    
    # Group by IP address to detect patterns
    ip_groups = recent_failed.group_by(&:ip_address)
    
    ip_groups.each do |ip, attempts|
      if attempts.count > 5
        Rails.logger.warn "Suspicious activity detected from IP: #{ip}"
        Rails.logger.warn "Failed attempts: #{attempts.count} in the last hour"
        
        # In a real application, this would trigger security alerts
        trigger_ip_security_alert(ip, attempts)
      end
    end
  end
  
  def detect_suspicious_patterns
    # Look for patterns in user agents
    recent_attempts = LoginAttempt.recent(1)
    user_agents = recent_attempts.pluck(:user_agent).uniq
    
    user_agents.each do |agent|
      attempts_with_agent = recent_attempts.select { |a| a.user_agent == agent }
      
      if attempts_with_agent.count > 10
        Rails.logger.warn "Suspicious user agent pattern detected: #{agent}"
        Rails.logger.warn "Attempts: #{attempts_with_agent.count}"
        
        trigger_user_agent_alert(agent, attempts_with_agent)
      end
    end
  end
  
  def detect_brute_force_attempts
    # Check for rapid successive attempts from same IP
    recent_attempts = LoginAttempt.recent(1).order(:created_at)
    
    # Group consecutive attempts by IP
    current_ip = nil
    consecutive_count = 0
    start_time = nil
    
    recent_attempts.each do |attempt|
      if attempt.ip_address == current_ip
        consecutive_count += 1
      else
        # Check if previous sequence was suspicious
        if consecutive_count > 10 && start_time && (attempt.created_at - start_time) < 10.minutes
          Rails.logger.warn "Potential brute force attack detected from IP: #{current_ip}"
          Rails.logger.warn "Attempts: #{consecutive_count} in #{attempt.created_at - start_time} seconds"
          
          trigger_brute_force_alert(current_ip, consecutive_count, start_time, attempt.created_at)
        end
        
        # Start new sequence
        current_ip = attempt.ip_address
        consecutive_count = 1
        start_time = attempt.created_at
      end
    end
    
    # Check final sequence
    if consecutive_count > 10 && start_time && (Time.current - start_time) < 10.minutes
      Rails.logger.warn "Potential brute force attack detected from IP: #{current_ip}"
      trigger_brute_force_alert(current_ip, consecutive_count, start_time, Time.current)
    end
  end
  
  def detect_account_takeover_attempts
    # Look for attempts to access multiple accounts from same IP
    recent_attempts = LoginAttempt.recent(1)
    ip_user_combinations = recent_attempts.group_by(&:ip_address)
    
    ip_user_combinations.each do |ip, attempts|
      unique_users = attempts.map(&:user).uniq
      
      if unique_users.count > 5
        Rails.logger.warn "Potential account takeover attempt detected from IP: #{ip}"
        Rails.logger.warn "Targeting #{unique_users.count} different users"
        
        trigger_account_takeover_alert(ip, unique_users)
      end
    end
  end
  
  def trigger_ip_security_alert(ip, attempts)
    Rails.logger.warn "SECURITY ALERT: Suspicious IP activity"
    Rails.logger.warn "IP: #{ip}"
    Rails.logger.warn "Failed attempts: #{attempts.count}"
    Rails.logger.warn "Time range: #{attempts.first.created_at} to #{attempts.last.created_at}"
    
    # In a real application, this would:
    # - Block the IP address
    # - Send notifications to security team
    # - Log to security monitoring system
  end
  
  def trigger_user_agent_alert(agent, attempts)
    Rails.logger.warn "SECURITY ALERT: Suspicious user agent pattern"
    Rails.logger.warn "User Agent: #{agent}"
    Rails.logger.warn "Attempts: #{attempts.count}"
    
    # In a real application, this would:
    # - Add user agent to blocklist
    # - Send notifications to security team
  end
  
  def trigger_brute_force_alert(ip, count, start_time, end_time)
    Rails.logger.warn "SECURITY ALERT: Potential brute force attack"
    Rails.logger.warn "IP: #{ip}"
    Rails.logger.warn "Attempts: #{count}"
    Rails.logger.warn "Duration: #{end_time - start_time} seconds"
    
    # In a real application, this would:
    # - Immediately block the IP
    # - Send urgent notifications
    # - Log to security monitoring system
  end
  
  def trigger_account_takeover_alert(ip, users)
    Rails.logger.warn "SECURITY ALERT: Potential account takeover attempt"
    Rails.logger.warn "IP: #{ip}"
    Rails.logger.warn "Targeted users: #{users.map(&:email).join(', ')}"
    
    # In a real application, this would:
    # - Block the IP immediately
    # - Notify affected users
    # - Send urgent security alerts
  end
end
