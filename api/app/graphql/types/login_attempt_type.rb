module Types
  class LoginAttemptType < Types::BaseObject
    description "A login attempt record"
    
    field :id, ID, null: false
    field :success, Boolean, null: false
    field :ip_address, String, null: false
    field :user_agent, String, null: false
    field :metadata, GraphQL::Types::JSON, null: true
    field :created_at, GraphQL::Types::ISO8601DateTime, null: false
  end
end
