module Mutations
  class BaseMutation < GraphQL::Schema::RelayClassicMutation
    # Common fields that can be included in mutations
    field :success, Boolean, null: false, description: "Whether the operation was successful"
    field :errors, [String], null: true, description: "List of error messages"
    
    protected
    
    def current_user
      context[:current_user]
    end
    
    def ip_address
      context[:ip_address] || "unknown"
    end
    
    def user_agent
      context[:user_agent] || "unknown"
    end
  end
end
