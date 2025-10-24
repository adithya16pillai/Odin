class SessionCleanupWorker
  include Sidekiq::Worker
  
  sidekiq_options queue: :maintenance, retry: 3
  
  def perform
    Rails.logger.info "Starting session cleanup..."
    
    expired_count = Session.cleanup_expired!
    Rails.logger.info "Cleaned up #{expired_count} expired sessions"
    
    # Also clean up old login attempts to prevent database bloat
    old_attempts = LoginAttempt.where('created_at < ?', 90.days.ago)
    old_count = old_attempts.count
    old_attempts.delete_all if old_count > 0
    
    Rails.logger.info "Cleaned up #{old_count} old login attempts" if old_count > 0
    
    # Clean up old device fingerprints
    old_fingerprints = DeviceFingerprint.where('created_at < ?', 30.days.ago)
    fingerprint_count = old_fingerprints.count
    old_fingerprints.delete_all if fingerprint_count > 0
    
    Rails.logger.info "Cleaned up #{fingerprint_count} old device fingerprints" if fingerprint_count > 0
  end
end
