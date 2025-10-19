module Mutations
  class RegisterMutation < BaseMutation
    description "Register a new user account"
    
    argument :email, String, required: true, description: "User's email address"
    argument :password, String, required: true, description: "User's password (minimum 6 characters)"
    
    field :user, Types::UserType, null: true, description: "The created user"
    field :session, Types::SessionType, null: true, description: "The created session"
    field :success, Boolean, null: false, description: "Whether registration was successful"
    field :errors, [String], null: true, description: "List of error messages"
    
    def resolve(email:, password:)
      user = User.new(email: email.downcase.strip, password: password)
      
      if user.save
        session = user.create_session!
        
        LoginAttempt.record_attempt!(
          user,
          success: true,
          ip_address: context[:ip_address] || "unknown",
          user_agent: context[:user_agent] || "unknown",
          metadata: { email: email, action: "registration" }
        )
        
        {
          user: user,
          session: session,
          success: true,
          errors: nil
        }
      else
        LoginAttempt.record_attempt!(
          User.new(email: email),
          success: false,
          ip_address: context[:ip_address] || "unknown",
          user_agent: context[:user_agent] || "unknown",
          metadata: { email: email, action: "registration", errors: user.errors.full_messages }
        )
        
        {
          user: nil,
          session: nil,
          success: false,
          errors: user.errors.full_messages
        }
      end
    rescue => e
      Rails.logger.error "Registration error: #{e.message}"
      {
        user: nil,
        session: nil,
        success: false,
        errors: ["An error occurred during registration"]
      }
    end
  end
end 