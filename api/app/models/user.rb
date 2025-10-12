class User < ApplicationRecord
  has_secure_password
  
  has_many :sessions, dependent: :destroy
  has_many :login_attempts, dependent: :destroy
  has_many :device_fingerprints, dependent: :destroy
  
  validates :email, presence: true, uniqueness: true, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :password, length: { minimum: 6 }, if: :password_required?
  
  def create_session!
    sessions.create!(
      token: SecureRandom.hex(32),
      expires_at: 30.days.from_now
    )
  end
  
  def active_session?(token)
    sessions.where(token: token, expires_at: Time.current..)
            .exists?
  end
  
  def invalidate_all_sessions!
    sessions.update_all(expires_at: Time.current)
  end
  
  private
  
  def password_required?
    new_record? || password.present?
  end
end
