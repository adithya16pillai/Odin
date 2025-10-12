class LoginAttempt < ApplicationRecord
  belongs_to :user
  
  validates :ip_address, presence: true
  validates :user_agent, presence: true
  validates :success, inclusion: { in: [true, false] }
  
  scope :successful, -> { where(success: true) }
  scope :failed, -> { where(success: false) }
  scope :recent, ->(hours = 24) { where('created_at > ?', hours.hours.ago) }
  
  def self.record_attempt!(user, success:, ip_address:, user_agent:, metadata: {})
    create!(
      user: user,
      success: success,
      ip_address: ip_address,
      user_agent: user_agent,
      metadata: metadata
    )
  end
end
