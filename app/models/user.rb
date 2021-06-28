class User < ApplicationRecord
  attr_reader :password

  before_validation :ensure_session_token
  
  validates :session_token, presence: true
  validates :password_digest, presence: { message: 'Password can\'t be blank' }
  validates :username, presence:true, uniqueness: true
  validates :password, length: { minimum: 6, allow_nil: true }
  
  def self.find_by_credentials(username, password)
    user = User.find_by(username: username)
    return nil if user.nil?
    user.password == password ? user : nil
  end

  def self.generate_session_token
    SecureRandom::urlsafe_base64(16)
  end

  def reset_session_token!
    self.session_token = User.generate_session_token
    self.save!
  end

  def ensure_session_token
    self.reset_session_token! if self.session_token.nil?
  end

  def password=(pass)
    @password = pass
    self.password_digest = BCrypt::Password.create(pass)
  end

end
