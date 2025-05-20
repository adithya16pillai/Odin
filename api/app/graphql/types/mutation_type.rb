module Types
  class MutationType < Types::BaseObject
    field :login, mutation: Mutations::LoginMutation
    field :register, mutation: Mutations::RegisterMutation
    field :record_fingerprint, mutation: Mutations::RecordFingerprintMutation
    field :verify_session, mutation: Mutations::VerifySessionMutation
  end
end