module Mutations
  class LoginMutation < BaseMutation
    description "Authenticate a user and create a session"
    
    argument :email, String, required: true, description: "User's email address"
    argument :password, String, required: true, description: "User's password"
    
    field :user, Types::UserType, null: true, description: "The authenticated user"
    field :session, Types::SessionType, null: true, description: "The created session"
    field :success, Boolean, null: false, description: "Whether login was successful"
    field :errors, [String], null: true, description: "List of error messages"
    
    def resolve(email:, password:)
      user = User.find_by(email: email.downcase.strip)
      
      # Record login attempt
      LoginAttempt.record_attempt!(
        user || User.new(email: email), # Create a dummy user for failed attempts
        success: user&.authenticate(password),
        ip_address: context[:ip_address] || "unknown",
        user_agent: context[:user_agent] || "unknown",
        metadata: { email: email }
      )
      
      if user && user.authenticate(password)
        session = user.create_session!
        
        {
          user: user,
          session: session,
          success: true,
          errors: nil
        }
      else
        {
          user: nil,
          session: nil,
          success: false,
          errors: ["Invalid email or password"]
        }
      end
    rescue => e
      Rails.logger.error "Login error: #{e.message}"
      {
        user: nil,
        session: nil,
        success: false,
        errors: ["An error occurred during login"]
      }
    end
  end
end 