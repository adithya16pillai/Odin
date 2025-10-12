module Mutations
  class VerifySessionMutation < BaseMutation
    description "Verify if a session token is valid"
    
    argument :session_token, String, required: true, description: "The session token to verify"
    
    field :valid, Boolean, null: false, description: "Whether the session token is valid"
    field :user, Types::UserType, null: true, description: "The user associated with the session (if valid)"
    field :expires_at, GraphQL::Types::ISO8601DateTime, null: true, description: "When the session expires (if valid)"
    
    def resolve(session_token:)
      session = Session.find_valid(session_token)
      
      if session
        {
          valid: true,
          user: session.user,
          expires_at: session.expires_at
        }
      else
        {
          valid: false,
          user: nil,
          expires_at: nil
        }
      end
    rescue => e
      Rails.logger.error "Session verification error: #{e.message}"
      {
        valid: false,
        user: nil,
        expires_at: nil
      }
    end
  end
end 