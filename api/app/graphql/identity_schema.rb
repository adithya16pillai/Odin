class IdentitySchema < GraphQL::Schema
  mutation(Types::MutationType)
  query(Types::QueryType)

  use GraphQL::Dataloader

  max_complexity 300
  max_depth 15

  default_max_page_size 100

  class << self
    def id_from_object(object, type_definition, query_ctx)
      object.to_global_id.to_s
    end

    def object_from_id(id, query_ctx)
      GlobalID::Locator.locate(id)
    end
  end

  rescue_from(StandardError) do |err, obj, args, ctx, field|
    Rails.logger.error("GraphQL Error: #{err.message}")
    Rails.logger.error(err.backtrace.join("\n"))

    raise GraphQL::ExecutionError, "Something went wrong: #{err.message}"
  end
end