module Types
  class SessionType < Types::BaseObject
    description "A user session"
    
    field :id, ID, null: false
    field :token, String, null: false
    field :expires_at, GraphQL::Types::ISO8601DateTime, null: false
    field :created_at, GraphQL::Types::ISO8601DateTime, null: false
    field :user, Types::UserType, null: false
  end
end
