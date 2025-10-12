module Types
  class UserType < Types::BaseObject
    description "A user account"
    
    field :id, ID, null: false
    field :email, String, null: false
    field :created_at, GraphQL::Types::ISO8601DateTime, null: false
    field :updated_at, GraphQL::Types::ISO8601DateTime, null: false
    
    # Sensitive fields that should only be shown to the user themselves
    field :login_attempts, [Types::LoginAttemptType], null: true, description: "Recent login attempts"
    
    def login_attempts
      object.login_attempts.recent(24).order(created_at: :desc).limit(10)
    end
  end
end
