class IdentitySchema < GraphQL::Schema
  mutation(Types::MutationType)
  query(Types::QueryType)

  # For batch-loading (see https://graphql-ruby.org/dataloader/overview.html)
  use GraphQL::Dataloader

  # GraphQL-Ruby defaults to only processing a query with up to 200 unique selections
  # We configure it to be higher for more complex queries
  max_complexity 300
  max_depth 15

  # Add built-in connections for pagination
  default_max_page_size 100

  # Relay-style Object Identification:
  class << self
    def id_from_object(object, type_definition, query_ctx)
      # Call your application's ID method on the object
      object.to_global_id.to_s
    end

    def object_from_id(id, query_ctx)
      # Find the object using your application's ID lookup
      GlobalID::Locator.locate(id)
    end
  end

  # Return a GraphQL response with detailed error information when something goes wrong
  rescue_from(StandardError) do |err, obj, args, ctx, field|
    # Log the error
    Rails.logger.error("GraphQL Error: #{err.message}")
    Rails.logger.error(err.backtrace.join("\n"))

    # Add a top-level error to the response
    raise GraphQL::ExecutionError, "Something went wrong: #{err.message}"
  end
end