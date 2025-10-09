module Types
  class QueryType < Types::BaseObject
    field :node, Types::NodeType, null: true, description: "Fetches an object given its ID" do
      argument :id, ID, required: true, description: "ID of the object"
    end

    def node(id:)
      context.schema.object_from_id(id, context)
    end

    field :nodes, [Types::NodeType, null: true], null: true, description: "Fetches a list of objects given a list of IDs" do
      argument :ids, [ID], required: true, description: "IDs of the objects"
    end

    def nodes(ids:)
      ids.map { |id| context.schema.object_from_id(id, context) }
    end

    field :me, Types::UserType, null: true, description: "Get the currently authenticated user"
    
    def me
      context[:current_user]
    end
    
    field :login_history, [Types::LoginAttemptType], null: true, description: "Get login history for the current user" do
      argument :limit, Integer, required: false, default_value: 10, description: "Maximum number of records to return"
    end
    
    def login_history(limit:)
      user = context[:current_user]
      return nil unless user
      
      user.login_attempts.order(created_at: :desc).limit(limit)
    end
    
    field :risk_assessment, Types::RiskAssessmentType, null: true, description: "Get risk assessment for a specific login attempt" do
      argument :login_attempt_id, ID, required: true, description: "ID of the login attempt"
    end
    
    def risk_assessment(login_attempt_id:)
      user = context[:current_user]
      return nil unless user
      
      login_attempt = user.login_attempts.find_by(id: login_attempt_id)
      return nil unless login_attempt
      
      login_attempt.risk_assessment
    end
  end
end
