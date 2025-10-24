module Types
  class BaseField < GraphQL::Schema::Field
    def initialize(*args, **kwargs, &block)
      super
    end
  end
end
