class DeviceFingerprint < ApplicationRecord
  belongs_to :user, optional: true
  belongs_to :session, optional: true
  
  validates :fingerprint_hash, presence: true, uniqueness: true
  validates :user_agent, presence: true
  validates :ip_address, presence: true
  
  scope :recent, ->(hours = 24) { where('created_at > ?', hours.hours.ago) }
  scope :by_user, ->(user) { where(user: user) }
  
  def self.record!(fingerprint_data, user: nil, session: nil, ip_address:, user_agent:)
    fingerprint_hash = Digest::SHA256.hexdigest(fingerprint_data.to_json)
    
    create!(
      user: user,
      session: session,
      fingerprint_hash: fingerprint_hash,
      fingerprint_data: fingerprint_data,
      ip_address: ip_address,
      user_agent: user_agent
    )
  end
  
  def matches?(other_fingerprint_data)
    fingerprint_hash == Digest::SHA256.hexdigest(other_fingerprint_data.to_json)
  end
end
