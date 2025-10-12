class Session < ApplicationRecord
  belongs_to :user
  has_many :device_fingerprints, dependent: :destroy
  
  validates :token, presence: true, uniqueness: true
  validates :expires_at, presence: true
  
  scope :active, -> { where('expires_at > ?', Time.current) }
  scope :expired, -> { where('expires_at <= ?', Time.current) }
  
  def expired?
    expires_at <= Time.current
  end
  
  def active?
    !expired?
  end
  
  def self.find_valid(token)
    active.find_by(token: token)
  end
  
  def self.cleanup_expired!
    expired.delete_all
  end
end
