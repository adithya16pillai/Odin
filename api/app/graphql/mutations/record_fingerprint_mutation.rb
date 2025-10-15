module Mutations
  class RecordFingerprintMutation < BaseMutation
    description "Record a device fingerprint for security tracking"
    
    argument :fingerprint, GraphQL::Types::JSON, required: true, description: "Device fingerprint data"
    argument :session_token, String, required: false, description: "Optional session token to associate with user"
    
    field :success, Boolean, null: false, description: "Whether fingerprint recording was successful"
    field :fingerprint_id, ID, null: true, description: "ID of the recorded fingerprint"
    field :errors, [String], null: true, description: "List of error messages"
    
    def resolve(fingerprint:, session_token: nil)
      ip_address = context[:ip_address] || "unknown"
      user_agent = context[:user_agent] || "unknown"
      
      user = nil
      session = nil
      
      if session_token.present?
        session = Session.find_valid(session_token)
        user = session&.user
      end
      
      device_fingerprint = DeviceFingerprint.record!(
        fingerprint,
        user: user,
        session: session,
        ip_address: ip_address,
        user_agent: user_agent
      )
      
      {
        success: true,
        fingerprint_id: device_fingerprint.id,
        errors: nil
      }
    rescue => e
      Rails.logger.error "Fingerprint recording error: #{e.message}"
      {
        success: false,
        fingerprint_id: nil,
        errors: ["Failed to record fingerprint: #{e.message}"]
      }
    end
  end
end 