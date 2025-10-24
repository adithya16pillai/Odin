class SecurityAnalyzerService
  def initialize(user, ip_address, user_agent)
    @user = user
    @ip_address = ip_address
    @user_agent = user_agent
  end
  
  def analyze_session_security
    {
      ip_reputation: check_ip_reputation,
      user_agent_analysis: analyze_user_agent,
      behavioral_patterns: analyze_behavioral_patterns,
      device_consistency: check_device_consistency,
      location_analysis: analyze_location
    }
  end
  
  def detect_anomalies
    anomalies = []
    
    # Check for suspicious patterns
    anomalies << "Suspicious user agent pattern" if suspicious_user_agent?
    anomalies << "Unusual login frequency" if unusual_frequency?
    anomalies << "Geographic anomaly" if geographic_anomaly?
    anomalies << "Device fingerprint mismatch" if device_mismatch?
    
    anomalies
  end
  
  private
  
  def check_ip_reputation
    # This would integrate with IP reputation services
    # For now, return a basic analysis
    {
      is_known_malicious: false,
      is_tor_exit_node: false,
      is_vpn: false,
      country: "Unknown",
      isp: "Unknown"
    }
  end
  
  def analyze_user_agent
    {
      browser: extract_browser,
      os: extract_os,
      device_type: extract_device_type,
      is_mobile: mobile_device?,
      is_bot: bot_user_agent?
    }
  end
  
  def analyze_behavioral_patterns
    recent_attempts = @user.login_attempts.recent(7)
    
    {
      login_frequency: calculate_login_frequency(recent_attempts),
      time_patterns: analyze_time_patterns(recent_attempts),
      success_rate: calculate_success_rate(recent_attempts),
      ip_consistency: calculate_ip_consistency(recent_attempts)
    }
  end
  
  def check_device_consistency
    recent_fingerprints = @user.device_fingerprints.recent(30)
    
    {
      fingerprint_stability: calculate_fingerprint_stability(recent_fingerprints),
      device_changes: detect_device_changes(recent_fingerprints),
      consistency_score: calculate_consistency_score(recent_fingerprints)
    }
  end
  
  def analyze_location
    # This would integrate with geo-ip services
    {
      country: "Unknown",
      region: "Unknown",
      city: "Unknown",
      timezone: "Unknown",
      is_vpn: false,
      is_proxy: false
    }
  end
  
  def suspicious_user_agent?
    # Check for known bot patterns or suspicious strings
    suspicious_patterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /java/i
    ]
    
    suspicious_patterns.any? { |pattern| @user_agent.match?(pattern) }
  end
  
  def unusual_frequency?
    # Check if login frequency is unusual
    recent_attempts = @user.login_attempts.where('created_at > ?', 1.hour.ago)
    recent_attempts.count > 10
  end
  
  def geographic_anomaly?
    # Check for unusual geographic patterns
    # This would require geo-ip integration
    false
  end
  
  def device_mismatch?
    # Check if device fingerprint is significantly different
    recent_fingerprints = @user.device_fingerprints.recent(7)
    return false if recent_fingerprints.empty?
    
    # Simple check - in production, use more sophisticated fingerprinting
    recent_fingerprints.none? { |fp| fp.user_agent == @user_agent }
  end
  
  def extract_browser
    case @user_agent
    when /Chrome/
      "Chrome"
    when /Firefox/
      "Firefox"
    when /Safari/
      "Safari"
    when /Edge/
      "Edge"
    else
      "Unknown"
    end
  end
  
  def extract_os
    case @user_agent
    when /Windows/
      "Windows"
    when /Mac/
      "macOS"
    when /Linux/
      "Linux"
    when /Android/
      "Android"
    when /iPhone|iPad/
      "iOS"
    else
      "Unknown"
    end
  end
  
  def extract_device_type
    if mobile_device?
      "Mobile"
    elsif tablet_device?
      "Tablet"
    else
      "Desktop"
    end
  end
  
  def mobile_device?
    @user_agent.match?(/Mobile|Android|iPhone|iPad/)
  end
  
  def tablet_device?
    @user_agent.match?(/iPad|Tablet/)
  end
  
  def bot_user_agent?
    bot_patterns = [/bot/i, /crawler/i, /spider/i, /scraper/i]
    bot_patterns.any? { |pattern| @user_agent.match?(pattern) }
  end
  
  def calculate_login_frequency(attempts)
    return 0 if attempts.empty?
    
    hours = (Time.current - attempts.first.created_at) / 1.hour
    attempts.count / [hours, 1].max
  end
  
  def analyze_time_patterns(attempts)
    hours = attempts.pluck(:created_at).map(&:hour)
    
    {
      most_common_hour: hours.max_by { |h| hours.count(h) },
      spread: hours.max - hours.min,
      night_logins: hours.count { |h| h >= 22 || h <= 6 }
    }
  end
  
  def calculate_success_rate(attempts)
    return 0 if attempts.empty?
    
    successful = attempts.count(&:success)
    (successful.to_f / attempts.count * 100).round(2)
  end
  
  def calculate_ip_consistency(attempts)
    return 0 if attempts.empty?
    
    unique_ips = attempts.pluck(:ip_address).uniq.count
    total_attempts = attempts.count
    
    (1.0 - (unique_ips.to_f / total_attempts)).round(2)
  end
  
  def calculate_fingerprint_stability(fingerprints)
    return 0 if fingerprints.empty?
    
    # Simple stability calculation based on user agent consistency
    agents = fingerprints.pluck(:user_agent)
    most_common_agent = agents.max_by { |a| agents.count(a) }
    consistency = agents.count(most_common_agent).to_f / agents.count
    
    consistency.round(2)
  end
  
  def detect_device_changes(fingerprints)
    return [] if fingerprints.count < 2
    
    changes = []
    fingerprints.order(:created_at).each_cons(2) do |prev, curr|
      if prev.user_agent != curr.user_agent
        changes << {
          timestamp: curr.created_at,
          from: prev.user_agent,
          to: curr.user_agent
        }
      end
    end
    
    changes
  end
  
  def calculate_consistency_score(fingerprints)
    return 0 if fingerprints.empty?
    
    # Calculate overall consistency score
    stability = calculate_fingerprint_stability(fingerprints)
    ip_consistency = calculate_ip_consistency(
      @user.login_attempts.recent(7)
    )
    
    (stability + ip_consistency) / 2
  end
end
