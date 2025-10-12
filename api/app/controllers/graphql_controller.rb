class GraphqlController < ApplicationController
  def execute
    variables = prepare_variables(params[:variables])
    query = params[:query]
    operation_name = params[:operationName]
    
    context = {
      current_user: current_user,
      ip_address: request.remote_ip,
      user_agent: request.user_agent
    }
    
    result = IdentitySchema.execute(
      query,
      variables: variables,
      context: context,
      operation_name: operation_name
    )
    
    render json: result
  rescue StandardError => e
    raise e unless Rails.env.development?
    handle_error_in_development(e)
  end

  private

  def current_user
    return @current_user if defined?(@current_user)
    
    token = extract_session_token
    return nil unless token
    
    session = Session.find_valid(token)
    @current_user = session&.user
  end

  def extract_session_token
    # Check Authorization header first
    auth_header = request.headers['Authorization']
    if auth_header&.start_with?('Bearer ')
      return auth_header.split(' ').last
    end
    
    # Check for session_token in query variables
    if params[:variables].present?
      variables = JSON.parse(params[:variables]) rescue {}
      return variables['session_token']
    end
    
    nil
  end

  # Handle variables in form data, JSON body, or a blank value
  def prepare_variables(variables_param)
    case variables_param
    when String
      if variables_param.present?
        JSON.parse(variables_param) || {}
      else
        {}
      end
    when Hash
      variables_param
    when ActionController::Parameters
      variables_param.to_unsafe_h # GraphQL-Ruby will validate name and type
    when nil
      {}
    else
      raise ArgumentError, "Unexpected parameter: #{variables_param}"
    end
  end

  def handle_error_in_development(e)
    logger.error e.message
    logger.error e.backtrace.join("\n")

    render json: {
      errors: [{ message: e.message, backtrace: e.backtrace }],
      data: {}
    }, status: 500
  end
end
