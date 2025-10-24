module Types
  class RiskAssessmentType < Types::BaseObject
    description "Risk assessment for a login attempt"
    
    field :id, ID, null: false
    field :risk_score, Float, null: false, description: "Risk score from 0.0 to 1.0"
    field :risk_level, String, null: false, description: "Risk level: low, medium, high, critical"
    field :factors, [String], null: false, description: "List of risk factors identified"
    field :anomalies, [String], null: true, description: "List of detected anomalies"
    field :recommendations, [String], null: true, description: "Security recommendations"
    field :created_at, GraphQL::Types::ISO8601DateTime, null: false
  end
end
